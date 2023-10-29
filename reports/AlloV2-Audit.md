# About the Audit
This security review was conducted as an involvement in a public and open-source competition hosted by Sherlock.xyz & Gitcoin. During the audit 7 Medium severity vulnerabilities were disclosed that were addressed and fixed by the developers.

If you wish to connect with Alex (*alexxander*) reach out at https://twitter.com/__alexxander_

# About Allo-V2
Allo V2 enables users to deploy pools to which Strategies are attached that exercise different governance mechanics over the pool's funding. Pool deployers can opt in to use one of the already developed Strategy contracts by the Allo team or develop custom Strategies.

# Findings List
| # | Issue Title                                                                                | Severity | Status |
| ------ | ----------------------------------------------------------------- | --------------    | ------------------|
| [[1]](#my-section1) | QV strategy allocate() and distribute() can be called in the same block  | Medium   | Fixed  |
| [[2]](#my-section2) | QV Strategy has no receive() function                                    | Medium   | Fixed  |
| [[3]](#my-section3) | QV strategy wrong voiceCreditsCastToRecipient update calculations        | Medium   | Fixed  |
| [[4]](#my-section4) | QV strategy missing allocators voiceCredits update                       | Medium   | Fixed  |
| [[5]](#my-section5) | RFP strategy reverts when there is more than 1 milestone                 | Medium   | Fixed  |
| [[6]](#my-section6) | RFP strategy register always reverts if using registry Anchor            | Medium   | Fixed  |
| [[7]](#my-section7) | Allo pool funding can avoid paying percent fee                           | Medium   | Fixed  |

# Detailed Explanation


