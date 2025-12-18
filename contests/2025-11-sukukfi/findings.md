# [M-01] Missing zero address validation allows owner/spender to set zero address as controller in requestDeposit(), leading to permanent loss of funds

## Finding description
requestDeposit() allows users or operators to provide controller = address(0).
The controller is the address that receives the final shares (for deposit) after the asynchronous lifecycle is completed, and this violates the intended invariant that the zero address should never be considered as controller in all operations.

## Impact
If a user or automation bot accidentally or maliciously sets controller = 0x000...0000, all shares associated with that request become permanently unclaimable.

## Recommended mitigation steps
Add a validation check:
```solidity
require(controller != address(0), "InvalidController");
```

## Proof of Concept
Simply change the controller in ERC7575Upgradeable.t.sol::test_BasicDepositFlow() function to address zero and run the test.
```solidity
function test_BasicDepositFlow() public {
        uint256 depositAmount = 1000e18;

        // Alice requests deposit
        vm.startPrank(alice);
        asset.approve(address(vault), depositAmount);
        vault.requestDeposit(depositAmount, address(0), alice); // Change controller to address zero.
        vm.stopPrank();

        // Check pending deposit
        assertEq(vault.pendingDepositRequest(0, alice), depositAmount);

        // Admin fulfills deposit
        vault.fulfillDeposit(address(0), depositAmount); // And this.

        // Check claimable
        assertEq(vault.claimableDepositRequest(0, address(0)), depositAmount); // And this also.

        // Alice claims shares
        vm.prank(address(0)); // And this (if you want address zero to receive the shares).
        uint256 shares = vault.deposit(depositAmount, address(0)); // And this.

        // Verify shares received
        assertEq(shareToken.balanceOf(address(0)), shares); // And this last one.
        assertEq(shares, depositAmount); // 1:1 initially
    }
```
## Links to affected code
src%2FERC7575VaultUpgradeable.sol#L341-L356