## About the Audit
This security review was conducted as an involvement in a public and open-source competition hosted by code4rena & WenWin lottery. During the audit 2 Medium severity vulnerabilities were disclosed that were addressed and fixed by the developers.

If you wish to connect with Alex (*alexxander*) reach out at https://twitter.com/__alexxander_

## About WenWin lottery
WenWin is a lottery system based on raffle tickets where once a week winning tickets are selected and rewards are distributed to the winners. Moreover, front-end developers are incentivized to develop UIs for the lottery and receive a pay cut from the platform's fees. The system integrates with Chainlink VRF. 

## Findings List
| #      | Issue Title                                                                                       | Severity | Status |
| ------ | ----------------------------------------------------------------- | ------------------------------| ------------------|
| [[1]](#my-section1) | An attacker can leave the protocol in a "drawing" state for extended period of time  | Medium   | Fixed  |
| [[2]](#my-section2) | Undermining the fairness of the protocol in `swapSource()`                           | Medium   | Fixed  |

[Official report](https://code4rena.com/reports/2023-03-wenwin)
## Detailed Explanation

### <a id="my-section1"></a> 1. An attacker can leave the protocol in a "drawing" state for extended period of time
#### Severity
Medium
#### Vulnerable Code
[code snippet](https://github.com/code-423n4/2023-03-wenwin/blob/91b89482aaedf8b8feb73c771d11c257eed997e8/src/RNSourceController.sol#L106-L120)
#### Impact
System is left for extended period of time in “Drawing” state without the possibility to execute further draws, user experience is damaged significantly.
#### Description
The culprit for this issue is the implementation of `requestRandomNumberFromSource()` in `RNSourceController.sol`. After `lastRequestFulfilled = false` the invocation to `VRFv2RNSource.sol` is done in a `try{} catch{}` block -
```solidity
        lastRequestTimestamp = block.timestamp;
        lastRequestFulfilled = false;

        try source.requestRandomNumber() {
            emit SuccessfulRNRequest(source);
        } catch Error(string memory reason) {
            emit FailedRNRequest(source, bytes(reason));
        } catch (bytes memory reason) {
            emit FailedRNRequest(source, reason);
        }
    }
```
This is very problematic due to how `try{} catch{}` works & the 63/64 gas rule. If the request to Chainlink VRF fails at any point then execution of the above block will not revert but will continue in the `catch{}` statements only emitting an event and leaving `RNSourceController` in the state `lastRequestFulfilled = false` and triggering the `maxRequestDelay (currently 5 hours)` until `retry()` becomes available to call to retry sending a RN request. This turns out to be dangerous since there is a trivial way of making Chainlink VRF revert - simply not supplying enough gas for the transaction either initially in calling `executeDraw()` or subsequently in `retry()` invocations with the attacker front-running the malicious transaction thus entering the catch block with the left 1/64 gas.


#### Recommendation
Refactor the `try{} catch{}` in `requestRandomNumberFromSource()` in `RNSourceController.sol`

### <a id="my-section2"></a> 2. Undermining the fairness of the protocol in `swapSource()`
#### Severity
Medium
#### Vulnerable Code
[code snippet 1](https://github.com/code-423n4/2023-03-wenwin/blob/91b89482aaedf8b8feb73c771d11c257eed997e8/src/RNSourceController.sol#L60-L75)
[code snippet 2](https://github.com/code-423n4/2023-03-wenwin/blob/91b89482aaedf8b8feb73c771d11c257eed997e8/src/RNSourceController.sol#L89-L104)
#### Impact
Re-requesting randomness is achieved when swapping sources of randomness. Fairness of protocol is undermined.
#### Description
The `swapSource()` method can be successfully called if 2 important boolean checks are true. `notEnoughRetryInvocations` - makes sure that there were `maxFailedAttempts` failed requests for a RN.
`notEnoughTimeReachingMaxFailedAttempts` - makes sure that `maxRequestDelay` amount of time has passed since the timestamp for reaching `maxFailedAttempts` was recorded in `maxFailedAttemptsReachedAt` i.e sufficient time has passed since the last `retry()` invocation. The most important detail to note here is that the `swapSource()` function does not rely on `lastRequestTimestamp` to check whether `maxRequestDelay` has passed since the last RN request.
```solidity
    function swapSource(IRNSource newSource) external override onlyOwner {
        if (address(newSource) == address(0)) {
            revert RNSourceZeroAddress();
        }
        bool notEnoughRetryInvocations = failedSequentialAttempts < maxFailedAttempts;
        bool notEnoughTimeReachingMaxFailedAttempts = block.timestamp < maxFailedAttemptsReachedAt + maxRequestDelay;
        if (notEnoughRetryInvocations || notEnoughTimeReachingMaxFailedAttempts) {
            revert NotEnoughFailedAttempts();
        }
        source = newSource;
        failedSequentialAttempts = 0;
        maxFailedAttemptsReachedAt = 0;


        emit SourceSet(newSource);
        requestRandomNumberFromSource();
    }
```
The bug resides in the `retry()` method. `maxFailedAttemptsReachedAt` is ONLY updated when `failedAttempts == maxFailedAttempts` - notice again the strict equality - meaning that `maxFailedAttemptsReachedAt` won't be updated if there are more `retry()` invocations after `failedAttempts == maxFailedAttempts`. This means that after the point of time when the last failed `retry()` sets `maxFailedAttemptsReachedAt` and the `maxRequestDelay` time passes - `retry()` and `swapSource()` (in that exact order) can be called simultaneously. This breaks the core assumption that randomness can be requested only once per draw. 
```solidity
        uint256 failedAttempts = ++failedSequentialAttempts;
        if (failedAttempts == maxFailedAttempts) {
            maxFailedAttemptsReachedAt = block.timestamp;
        }
```
#### Recommendation
Replace `failedAttempts == maxFailedAttempts` with `failedAttempts >= maxFailedAttempts` in `retry()` in `RNSourceController.sol`.
