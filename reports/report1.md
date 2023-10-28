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
| 9 | Deprecating a gauge before queueRewardsForCycle() in a new cycle leads to loss of rewards                                                       | Medium   | Acknowledged |
| 10| Adversary can grief wrongfully sent NFTs to BoostAggregator.sol                                                                                 | Low      | Fixed |
| 11| Adversary can restrain users from withdrawing their NFTs from UniswapV3Staker                                                                   | Low      | Acknowledged |


