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
| 1 | Attacker can mint arbitrary amount of `hToken` on RootChain                                                                                     | Critical | Fixed |
| 2 | Re-adding a deprecated gauge in a new epoch before calling `updatePeriod()` / `queueRewardsForCycle()` will leave some gauges without rewards.  | Critical | Fixed |
| 3 | Attacker can steal Accumulated Awards from RootBridgeAgent by abusing `retrySettlement()`                                                       | High     | Fixed |
| 4 | `sweep()` doesn’t convert WETH to ETH                                                                                                           | High     | Fixed |
| 5 | `retrySettlement()` should revert on a Settlement that has been redeemed or is non existing, crediting back ETH to user                         | Medium   | Fixed |
| 6 | UniV3 Staker `restakeToken(...)` calls unstakeToken(...)` with wrong argument                                                                   | Medium   | Fixed |
| 7 | BoostAggregator loss of funds for low-value rewards                                                                                             | Medium   | Fixed |
| 8 | BoostAggregator owner can set fees to 100% and steal all of the users' rewards                                                                  | Medium   | Fixed |
| 9 | Deprecating a gauge before `queueRewardsForCycle()` in a new cycle leads to loss of rewards                                                     | Medium   | Acknowledged |
| 10| Adversary can grief wrongfully sent NFTs to BoostAggregator.sol                                                                                 | Low      | Fixed |
| 11| Adversary can restrain users from withdrawing their NFTs from UniswapV3Staker                                                                   | Low      | Acknowledged |

# Detailed Explanation

## 1. Attacker can mint arbitrary amount of `hToken` on RootChain

### Severity
Critical

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
**Impact**

**Recommendation** 

## 2. Re-adding a deprecated gauge in a new epoch before calling `updatePeriod()` / `queueRewardsForCycle()` will leave some gauges without rewards.
