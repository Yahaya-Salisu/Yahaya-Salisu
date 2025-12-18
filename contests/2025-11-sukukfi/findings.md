| ID                                                                                                               | Title                                                                                                        |
| ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| [L-01](#l-01-Missing-zero-address-validation-allows-owner/spender-to-set-zero-address-as-controller-in-requestDeposit(),-leading-to-permanent-loss-of-funds)
| Missing zero address validation allows owner/spender to set zero address as controller in requestDeposit(), leading to permanent loss of funds
|
| [L-02](#l-02-Missing-validation-in-requestRedeem()-function-allows-owner/operator-or-bot-to-set-zero-address-as-controller,-Leading-to-permanent-loss-of-funds)
| Missing validation in requestRedeem() function allows owner/operator or bot to set zero address as controller, Leading to permanent loss of funds
|


## [L-01] Missing zero address validation allows owner/spender to set zero address as controller in requestDeposit(), leading to permanent loss of funds

### Finding description
`requestDeposit()` allows users or operators to provide `controller = address(0)`.
The controller is the address that receives the final shares (for deposit) after the asynchronous lifecycle is completed, and this violates the intended invariant that the zero address should never be considered as controller in all operations.

### Impact
If a user or automation bot accidentally or maliciously sets controller = `0x000...0000`, all shares associated with that request become permanently unclaimable.

### Recommended mitigation steps
Add a validation check:
```solidity
require(controller != address(0), "InvalidController");
```

### Proof of Concept
Simply change the controller in `ERC7575Upgradeable.t.sol::test_BasicDepositFlow()` function to address zero and run the test.
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

### Links to affected code
src%2FERC7575VaultUpgradeable.sol#L341-L356

---

## [L-02] Missing validation in requestRedeem() function allows owner/operator or bot to set zero address as controller, Leading to permanent loss of funds

### Finding description and impact
`requestRedeem()` allows users to provide `controller = address(0)`.
The controller is the address that receives the final assets (for redeem) after the asynchronous lifecycle is completed, and this violates the intended invariant that the zero address should never be considered as controller in all operations.

### Impact
If a user or automation bot accidentally or maliciously sets `controller = 0x000...0000`, all assets associated with that request become permanently unclaimable.

### Recommended mitigation steps
Add a validation check:
```solidity
require(controller != address(0), "InvalidController");
```

### Proof of Concept
Simply change all the controller's parameters in `ERC7575Upgradeable.t.sol::test_RedeemFlow()` function to address zero and run the test.

```solidity
    function test_RedeemFlow() public {
        uint256 depositAmount = 1000e18;

        // First deposit to get shares
        vm.startPrank(alice);
        asset.approve(address(vault), depositAmount);
        vault.requestDeposit(depositAmount, address (0), alice);
        vm.stopPrank();

        vault.fulfillDeposit(address(0), depositAmount);

        vm.prank(alice);
        uint256 shares = vault.deposit(depositAmount, address(0));

        // Now test redeem
        vm.startPrank(alice);
        shareToken.approve(address(vault), shares);
        vault.requestRedeem(shares, address(0), alice);
        vm.stopPrank();

        // Check pending redeem
        assertEq(vault.pendingRedeemRequest(0, alice), shares);

        // Fulfill redeem
        vault.fulfillRedeem(address(0), shares);

        // Claim assets
        vm.prank(address(0));
        uint256 assets = vault.redeem(shares, address(0), alice);

        // Verify
        assertEq(assets, depositAmount);
        assertEq(asset.balanceOf(alice), INITIAL_BALANCE);
        assertEq(shareToken.balanceOf(alice), 0);
    }
```

### Links to affected code
src%2FERC7575VaultUpgradeable.sol#L715-L751
