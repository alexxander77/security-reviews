## About the Audit
This security review was conducted as an involvement in a public and open-source competition hosted by Sherlock.xyz & Gitcoin. During the audit 7 Medium severity vulnerabilities were disclosed that were addressed and fixed by the developers.

If you wish to connect with Alex (*alexxander*) reach out at https://twitter.com/__alexxander_

## About Allo-V2
Allo V2 enables users to deploy pools to which Strategies are attached that exercise different governance mechanics over the pool's funding. Pool deployers can opt in to use one of the already developed Strategy contracts by the Allo team or develop custom Strategies.

## Findings List
| #      | Issue Title                                                                               | Severity | Status |
| ------ | ----------------------------------------------------------------- | ----------------------| ------------------|
| [[1]](#my-section1) | QV strategy missing allocators `voiceCredits` update                         | High     | Fixed  |
| [[2]](#my-section2) | QV Strategy has no `receive()` function                                      | Medium   | Fixed  |
| [[3]](#my-section3) | QV strategy wrong `voiceCreditsCastToRecipient` update calculations          | Medium   | Fixed  |
| [[4]](#my-section4) | QV strategy `allocate()` and `distribute()` can be called in the same block  | Medium   | Fixed  |
| [[5]](#my-section5) | RFP strategy reverts when there is more than 1 milestone                     | Medium   | Fixed  |
| [[6]](#my-section6) | RFP strategy register always reverts if using registry Anchor                | Medium   | Fixed  |
| [[7]](#my-section7) | Allo pool funding can avoid paying percent fee                               | Medium   | Fixed  |

[Official report](https://audits.sherlock.xyz/contests/109/report)
## Detailed Explanation
### <a id="my-section1"></a> 1. QV strategy missing allocators voiceCredits update
#### Severity
High
#### Vulnerable Code
[code snippet](https://github.com/sherlock-audit/2023-09-Gitcoin-alexxander77/blob/2c27bba814101c02f9d708ac12d73b1e4ea1f9ce/allo-v2/contracts/strategies/qv-simple/QVSimpleStrategy.sol#L107-L124)
#### Impact
Allocator can cast infinite amount of voice credits.
#### Description
In `QVSimpleStrategy.sol` `allocate()` has a condition that checks if the allocator won't surpass `maxVoiceCreditsPerAllocator`, however, `allocator.voiceCredits` is never updated throughout the `allocate()` function which makes `maxVoiceCreditsPerAllocator` meaningless and allows for infinite allocation of voice credits.
```solidity
if (!_hasVoiceCreditsLeft(voiceCreditsToAllocate, allocator.voiceCredits)) revert INVALID();
```
#### Coded POC
* Add the following getter function to QVBaseStrategy.sol
```solidity
function getAllocatorVoiceCredits(address allocator) external returns(uint256) {
        return allocators[allocator].voiceCredits;
    }
```
* Add the following test function in `QVSimpleStrategy.t.sol`
* Execute with `forge test --match-test testWrongTotalVoiceCredits -vv`

Output - 0 `voiceCredits` in the allocator struct state, although he has allocated
```solidity
function testWrongTotalVoiceCredits() public {

        address recipientId = __register_accept_recipient();

        vm.warp(registrationEndTime + 10);

        address[] memory recipientIds = new address[](1);
        recipientIds[0] = recipientId;

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 9.9e17; // fund amount: 1e18 - fee: 1e17 = 9.9e17

        token.mint(pool_manager1(), 100e18);
        // set the allowance for the transfer
        vm.prank(pool_manager1());
        token.approve(address(allo()), 999999999e18);

        // fund pool
        vm.prank(pool_manager1());
        allo().fundPool(poolId, 1e18);

        vm.warp(allocationStartTime + 10);

        address allocator = randomAddress();
        vm.startPrank(pool_manager1());
        qvSimpleStrategy().addAllocator(allocator);
        bytes memory allocateData = __generateAllocation(recipientId, 10);

        vm.startPrank(address(allo()));
        qvSimpleStrategy().allocate(allocateData, randomAddress());

        console.log("Total vocie credits", qvSimpleStrategy().getAllocatorVoiceCredits(randomAddress()));
        
        

        vm.warp(allocationEndTime + 10);

    }
```
#### Recommendation
Update `voiceCredits` inside the Allocator struct.


### <a id="my-section2"></a> 2. QV Strategy has no receive() function
#### Severity
Medium
#### Vulnerable Code
[code snippet 1](https://github.com/sherlock-audit/2023-09-Gitcoin-alexxander77/blob/2c27bba814101c02f9d708ac12d73b1e4ea1f9ce/allo-v2/contracts/strategies/qv-base/QVBaseStrategy.sol#L30C1-L575C2)

[code snippet 2](https://github.com/sherlock-audit/2023-09-Gitcoin-alexxander77/blob/main/allo-v2/contracts/strategies/qv-simple/QVSimpleStrategy.sol)
#### Impact
The QV strategy Base and Simple contracts don't implement a receive() function, strategy is nonfunctional with Native token.
#### Description
When creating a pool `_fundPool()` is invoked to credit the percent fee to Allo and to credit the remaining funds to the underlying strategy. The issue is that `QVBaseStrategy` & `QVSimpleStrategy` don't implement a `receive()` function and therefore these strategies become unusable with the Native token ( for example `RFPSimpleStrategy` does implement a `receive()` ).
```solidity
function _fundPool(uint256 _amount, uint256 _poolId, IStrategy _strategy) internal {
        // code ... 
        _transferAmountFrom(_token, TransferData({from: msg.sender, to: address(_strategy), amount: amountAfterFee}));
        _strategy.increasePoolAmount(amountAfterFee);

        emit PoolFunded(_poolId, amountAfterFee, feeAmount);
    }
```
#### Recommendation
Implement a `receive()` function.

### <a id="my-section3"></a> 3. QV strategy wrong `voiceCreditsCastToRecipient` update calculations
#### Severity
Medium
#### Vulnerable Code
[code snippet](https://github.com/sherlock-audit/2023-09-Gitcoin-alexxander77/blob/2c27bba814101c02f9d708ac12d73b1e4ea1f9ce/allo-v2/contracts/strategies/qv-base/QVBaseStrategy.sol#L506-L534)
#### Impact
This will lead to an inflated `_recipient.totalVotesReceived` and will cause wrong vote accounting for any subsequent `allocate()` executions.
#### Description
In `_qv_allocate(..., uint256 voiceCreditsToAllocate, ...)` the variable `totalCredits = voiceCreditsToAllocate + creditsCastToRecipient` is the sum of the already delegated voice credits to the recipient and the new voice credits to be further allocated. The issue is that later in the function we have `_allocator.voiceCreditsCastToRecipient[_recipientId] += totalCredits;` which increments the allocators casted credits with his new and old casted voice credits (rather only with the new).
```solidity
function _qv_allocate(
        Allocator storage _allocator,
        Recipient storage _recipient,
        address _recipientId,
        uint256 _voiceCreditsToAllocate,
        address _sender
    ) internal onlyActiveAllocation {
        // check the `_voiceCreditsToAllocate` is > 0
        if (_voiceCreditsToAllocate == 0) revert INVALID();

        // get the previous values
        uint256 creditsCastToRecipient = _allocator.voiceCreditsCastToRecipient[_recipientId];
        uint256 votesCastToRecipient = _allocator.votesCastToRecipient[_recipientId];

        // get the total credits and calculate the vote result
        uint256 totalCredits = _voiceCreditsToAllocate + creditsCastToRecipient;
        // code ...

        // @audit wrong, should be += voiceCreditsToAllocate
        _allocator.voiceCreditsCastToRecipient[_recipientId] += totalCredits;

        // more code ...
    }
```
#### Coded POC
* Add the following getter function to `QVBaseStrategy.sol`
```solidity
function getAllocatorVoiceCreditsCastToRecipient(address allocator, address recipient) external returns(uint256) {
        return allocators[allocator].voiceCreditsCastToRecipient[recipient];
    }
```
* Add the following test function in `QVSimpleStrategy.t.sol`
* Execute with `forge test --match-test testWrongVoiceCreditsToRecipient -vv`

Output - the voice credits that are cast are 30 instead of 20
```solidity
function testWrongVoiceCreditsToRecipient() public {
        
        // register recipient
        address recipientId = __register_accept_recipient();

        vm.warp(registrationEndTime + 10);

        address[] memory recipientIds = new address[](1);
        recipientIds[0] = recipientId;

        // fund pool
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 9.9e17; // fund amount: 1e18 - fee: 1e17 = 9.9e17

        token.mint(pool_manager1(), 100e18);
        // set the allowance for the transfer
        vm.prank(pool_manager1());
        token.approve(address(allo()), 999999999e18);

        vm.prank(pool_manager1());
        allo().fundPool(poolId, 1e18);

        vm.warp(allocationStartTime + 10);

        address allocator = randomAddress();
        vm.startPrank(pool_manager1());
        qvSimpleStrategy().addAllocator(allocator);
        bytes memory allocateData = __generateAllocation(recipientId, 10);

        // allocate 10 credits
        vm.startPrank(address(allo()));
        qvSimpleStrategy().allocate(allocateData, randomAddress());

        console.log("Voice Credits Cast To After 1st allocate()", qvSimpleStrategy().getAllocatorVoiceCreditsCastToRecipient(randomAddress(), recipientId));
        
        // allocate 10 more credits, however allocator now has credited a wrong 30 credits to the recipient
        vm.startPrank(address(allo()));
        qvSimpleStrategy().allocate(allocateData, randomAddress());

        console.log("Voice Credits Cast To After 2st allocate()", qvSimpleStrategy().getAllocatorVoiceCreditsCastToRecipient(randomAddress(), recipientId));

    }
```
#### Recommendation
Rework the accounting to such `_allocator.voiceCreditsCastToRecipient[_recipientId] = totalCredits;`
### <a id="my-section4"></a> 4. QV strategy allocate() and distribute() can be called in the same block
#### Severity
Medium
#### Vulnerable Code
[code snippet 1](https://github.com/sherlock-audit/2023-09-Gitcoin-alexxander77/blob/2c27bba814101c02f9d708ac12d73b1e4ea1f9ce/allo-v2/contracts/strategies/qv-base/QVBaseStrategy.sol#L310-L328)

[code snippet 2](https://github.com/sherlock-audit/2023-09-Gitcoin-alexxander77/blob/2c27bba814101c02f9d708ac12d73b1e4ea1f9ce/allo-v2/contracts/strategies/qv-base/QVBaseStrategy.sol#L506-L534)
#### Impact
In the QV strategy contracts the functions `allocate()` and `distribute()` can be called in the same block contrary to the developers intentions. In the current implementation this leads to a potential DoS scenario but more importantly this could break future integrations of the strategy by other contracts or off-chain components that rely on the correctness of the `onlyActiveAllocation` & `onlyAfterAllocation` modifiers.
#### Description
Below are the underlying implementations of the mentioned modifiers - the first one is used with the `allocate()` function and the second one is used with `distribute()` i.e we want to distribute funds only after allocations have ended. The issue is that if `block.timestamp = allocationEndTime` the `_checkOnlyAfterAllocation()` won't revert since `block.timestamp isn't < allocationEndTime` (they are equal), therefore at the `allocationEndTime` block both `allocate()` and `distribute()` can be executed which already breaks the developers intentions.

```solidity
function _checkOnlyActiveAllocation() internal view virtual {
        if (allocationStartTime > block.timestamp || block.timestamp > allocationEndTime) {
            revert ALLOCATION_NOT_ACTIVE();
        }
    }
function _checkOnlyAfterAllocation() internal view virtual {
        if (block.timestamp < allocationEndTime) revert ALLOCATION_NOT_ENDED();
    }
```

A specific scenario where this could have serious impact is if we have multiple `distribute()` invocations - this is possible since `distribute()` accepts an array of recipients and could be called many times as long as the passed array contains recipients that haven't been paid out ( this could also be done by some off-chain or contract implementation that communicates with the strategy ). The severe impact is achieved when an allocator executes `allocate()` in between the `distribute()` invocations ( again we could have allocator logic (in good faith) that relies on the modifiers to revert on a allocate() invocation and doesn't know about the ongoing distribute() calls ). In such a scenario where we have distribute - allocate - distribute the increase in `totalRecipientVotes` will make the subsequent `distribute()` calls disproportionate since distribute has already paid some recipients at a lower `totalRecipientVotes` (also note that `distribute()` doesn't decrement from `poolAmount` ), therefore some subsequent calls to `distribute()` after the wrongful `allocate()` will inevitably revert and the recipients won't be able to receive their funds, moreover, the QV strategy doesn't implement a withdraw mechanism and the funds will remain forever bricked in the contract.
#### Coded POC
In the test contract `QVSimpleStrategy.t.sol` place these import statements:
* `import {Metadata} from "../../../contracts/core/libraries/Metadata.sol";`
* `import {IStrategy} from "../../../contracts/core/interfaces/IStrategy.sol";`
* Place in the contract the below shown `testAllocateDistributeSameBlock()` and `_helperRegister2Recipients()` functions
* Execute with `forge test --match-test testAllocateDistributeSameBlock -vv`
The expected result is a revert due to `distribute()` failing to distribute to an eligible recipient
```solidity
function testAllocateDistributeSameBlock() public {
        
        // two recipients
        address recipientAId;
        address recipientBId;

        // register the two recipients
        (recipientAId, recipientBId) = _helperRegister2Recipients();

        // Fund the Pool
        vm.warp(registrationEndTime + 10);

        token.mint(pool_manager1(), 100e18);

        vm.prank(pool_manager1());
        token.approve(address(allo()), 999999999e18);

        vm.prank(pool_manager1());
        allo().fundPool(poolId, 100e18);

        // Allocation Period Starts
        vm.warp(allocationStartTime + 10);

        address allocator = randomAddress();
        vm.startPrank(pool_manager1());
        qvSimpleStrategy().addAllocator(allocator);

        // each recipient will receive 10 credits
        bytes memory allocateData1 = __generateAllocation(recipientAId, 10);
        bytes memory allocateData2 = __generateAllocation(recipientBId, 10);

        vm.startPrank(address(allo()));

        // allocate to recipients
        qvSimpleStrategy().allocate(allocateData1, randomAddress());
        qvSimpleStrategy().allocate(allocateData2, randomAddress());

        vm.stopPrank();

        // Last block of allocation period but distribute() can already be called
        vm.warp(allocationEndTime);

        vm.startPrank(address(allo()));
        address[] memory recipients1 = new address[](1);
        address[] memory recipients2 = new address[](1);

        recipients1[0] = recipientAId;
        recipients2[0] = recipientBId;

        // distribute to recipient 1
        qvStrategy().distribute(recipients1, "", pool_admin());

        // allocate 10 more votes to recipient2 
        qvSimpleStrategy().allocate(allocateData2, randomAddress());
        
        // accounting is now wrong and distribute reverts - bricking the funds
        qvStrategy().distribute(recipients2, "", pool_admin());

        console.log("Token balance rec1", token.balanceOf(recipientAId));
        console.log("Token balance rec2", token.balanceOf(recipientBId));

    }

    function _helperRegister2Recipients() internal returns(address, address) {
         
        address recipientA = address(77);
        address recipientB = address(88);

        Metadata memory metadata = Metadata({protocol: 1, pointer: "metadata"});
        
        bool _isUsingRegistryAnchor = false;

        bytes memory data1 = abi.encode(recipientA, _isUsingRegistryAnchor, metadata);
        bytes memory data2 = abi.encode(recipientB, _isUsingRegistryAnchor, metadata);

        
        // Register recipients
        vm.warp(registrationStartTime + 10);

        vm.startPrank(address(allo()));

        address recipientAId = qvStrategy().registerRecipient(data1, recipientA);
        address recipientBId = qvStrategy().registerRecipient(data2, recipientB);

        // Accept recipients
        address[] memory recipientIds = new address[](2);
        recipientIds[0] = recipientAId;
        recipientIds[1] = recipientBId;

        IStrategy.Status[] memory Statuses = new IStrategy.Status[](2);
        Statuses[0] = IStrategy.Status.Accepted;
        Statuses[1] = IStrategy.Status.Accepted;

        vm.startPrank(pool_admin());
        qvStrategy().reviewRecipients(recipientIds, Statuses);
        vm.stopPrank();

        vm.startPrank(pool_manager1());
        qvStrategy().reviewRecipients(recipientIds, Statuses);
        vm.stopPrank();

        return (recipientAId, recipientBId);
    }
```
#### Recommendation
Rework the after allocation modifier to such
```solidity
function _checkOnlyAfterAllocation() internal view virtual {
        if (block.timestamp <= allocationEndTime) revert ALLOCATION_NOT_ENDED();
    }
```
### <a id="my-section5"></a> 5. RFP strategy reverts when there is more than 1 milestone 
#### Severity
Medium
#### Vulnerable Code
[code snippet](https://github.com/sherlock-audit/2023-09-Gitcoin-alexxander77/blob/2c27bba814101c02f9d708ac12d73b1e4ea1f9ce/allo-v2/contracts/strategies/rfp-simple/RFPSimpleStrategy.sol#L382-L412)
#### Impact
The current logic in `_distribute()` inside `RFPSimpleStrategy.sol` will render the strategy useless when there are more than 1 milestones.
#### Description
The `_distribute()` function checks that the `proposalBid` doesn't exceed `poolAmount` and then subtracts the current milestone amount from `poolAmount`, however `proposalBid` is always constant and at some point `poolAmount` will be less than `proposalBid` and the function will revert and unable future milestones to be executed.
```solidity
// make sure has enough funds to distribute based on the proposal bid
if (recipient.proposalBid > poolAmount) revert NOT_ENOUGH_FUNDS();
```
#### Coded POC
* Add `testTwoMilestones` and the modified `__register_recipient()` to RFPSimpleStrategy.t.sol
* In this scenario we have `maxBid = 4.95e18`, pool with 5e18 funds, milestones worth 7e17 & 3e17 and an accepted proposal bid of 3e18
* Execute the test with `forge test --match-test testTwoMilestones -vv`

Output - the function reverts on trying to distribute the second milestone with `NOT_ENOUGH_FUNDS()` revert message.
```solidity
function testTwoMilestones() public {
       uint newMaxBid = 4950000000000000000;

       vm.prank(pool_admin());
       strategy.increaseMaxBid(newMaxBid);

       address funder = address(77);
       vm.deal(funder, 5e18);
       vm.prank(funder);
       allo().fundPool{value: 5e18}(poolId, 5e18);
       console.log("Strategy Balance", address(strategy).balance);

       address recId = __register_recipient();
       console.log("Id", recId);

       __setMilestones();

       // _helperPrintMilestone(strategy.getMilestone(0));

       vm.prank(address(allo()));
       strategy.allocate(abi.encode(recId), address(pool_admin()));

       console.log("Accepted Recipient Id: ", strategy.acceptedRecipientId());

       vm.prank(recipient());
       strategy.submitUpcomingMilestone(Metadata({protocol: 1, pointer: "metadata"}));

       vm.prank(address(allo()));
       strategy.distribute(new address[](0), "", pool_admin());   
       
       console.log("Strategy Balance", address(strategy).balance);

       vm.prank(recipient());
       strategy.submitUpcomingMilestone(Metadata({protocol: 1, pointer: "metadata"}));

       vm.prank(address(allo()));
       strategy.distribute(new address[](0), "", pool_admin());   
       
       console.log("Strategy Balance", address(strategy).balance);

   }

   function __register_recipient() internal returns (address recipientId) {
       address sender = recipient();
       Metadata memory metadata = Metadata({protocol: 1, pointer: "metadata"});

       bytes memory data = abi.encode(recipientAddress(), false, 3e18, metadata);
       vm.prank(address(allo()));
       recipientId = strategy.registerRecipient(data, sender);
   }
```
#### Recommendation
Rework `_distribute`.

### <a id="my-section6"></a> 6. RFP strategy register always reverts if using registry Anchor 
#### Severity
Medium
#### Vulnerable Code
[code snippet](https://github.com/sherlock-audit/2023-09-Gitcoin-alexxander77/blob/2c27bba814101c02f9d708ac12d73b1e4ea1f9ce/allo-v2/contracts/strategies/rfp-simple/RFPSimpleStrategy.sol#L314-L379)
#### Impact
If `RFPSimpleStrategy.sol` has `useRegistryAnchor=true` `_registerRecipient()` will always revert.
#### Description
In `_registerRecipient()` the address `recipientAddress`; variable is declared, however, if `useRegistryAnchor=true` the corresponding block of code doesn't assign any value to `recipientAddress` and later in the function the if-statement that checks if `recipientAddress==0` will revert the whole register thus disabling recipients from ever registering.
```solidity
function _registerRecipient(bytes memory _data, address _sender)
        internal
        override
        onlyActivePool
        returns (address recipientId)
    {
        bool isUsingRegistryAnchor;
        address recipientAddress;
        address registryAnchor;
        uint256 proposalBid;
        Metadata memory metadata;

        // Decode '_data' depending on the 'useRegistryAnchor' flag
        if (useRegistryAnchor) {
            /// @custom:data when 'true' -> (address recipientId, uint256 proposalBid, Metadata metadata)
            (recipientId, proposalBid, metadata) = abi.decode(_data, (address, uint256, Metadata));

            // If the sender is not a profile member this will revert
            if (!_isProfileMember(recipientId, _sender)) revert UNAUTHORIZED();
        } else {
            // some code ...
        }

        // Check if the metadata is required and if it is, check if it is valid, otherwise revert
        if (metadataRequired && (bytes(metadata.pointer).length == 0 || metadata.protocol == 0)) {
            revert INVALID_METADATA();
        }

        if (proposalBid > maxBid) {
            // If the proposal bid is greater than the max bid this will revert
            revert EXCEEDING_MAX_BID();
        } else if (proposalBid == 0) {
            // If the proposal bid is 0, set it to the max bid
            proposalBid = maxBid;
        }

        // If the recipient address is the zero address this will revert
        if (recipientAddress == address(0)) revert RECIPIENT_ERROR(recipientId);

        // more code
    }
```
#### Recommendation
Rework registering to be similar to the QV strategy implementation register.

### <a id="my-section7"></a> 7. Allo pool funding can avoid paying percent fee 
#### Severity
Medium
#### Vulnerable Code
[code snippet](https://github.com/sherlock-audit/2023-09-Gitcoin-alexxander77/blob/2c27bba814101c02f9d708ac12d73b1e4ea1f9ce/allo-v2/contracts/core/Allo.sol#L502-L519)
#### Impact
User can avoid the percent fee with certain fund amounts.
#### Description
The following block of code is from the `_fundPool()` function and `feeAmount` can round down to 0 on certain amounts. An example would be if `percentFee=1e16` then for an amount up to 1000 the `feeAmount` will round down to 0.
```solidity
if (percentFee > 0) {
            feeAmount = (_amount * percentFee) / getFeeDenominator();
            amountAfterFee -= feeAmount;

            _transferAmountFrom(_token, TransferData({from: msg.sender, to: treasury, amount: feeAmount}));
        }
```
#### Coded POC
* Paste the code below in `Allo.t.sol`
* Execute the test with `forge test --match-test test_avoidPercentFee -vvvv`
  
Output - Upon Inspection of the logs we can see there was no percent fee deducted
```solidity
function test_avoidPercentFee() public {

        uint256 baseFee = 1e17;
        allo().updateBaseFee(baseFee);

        // vm.expectEmit(true, false, false, true);
        // emit BaseFeePaid(1, baseFee);

        vm.deal(address(pool_admin()), 1e18);

        vm.startPrank(pool_admin());

        uint256 poolId = allo().createPoolWithCustomStrategy{value: 3e17}(
            poolProfile_id(), strategy, "0x", NATIVE, 1e17, metadata, pool_managers()
        );

        console.log("Strategy balance AFTER", strategy.balance);
        
        allo().fundPool{value: 99}(poolId, 99);

    }
```
#### Recommendation
Check if a minimum amount of deposit is met.
