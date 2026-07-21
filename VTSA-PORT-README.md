# V-TSA on Virtuoso (the `vtsa-port` branch)

This branch hosts **V-TSA — verified certified-region TLB coalescing** —
on the Virtuoso simulator (Sniper + MimicOS). The design, formal contract,
and evidence discipline come from the v-tsa repository
(github.com/snarang181/v-tsa); `docs/virtuoso-port-plan.md` there is the
port's ledger, with an execution record per phase.

## Layout

| Piece | Where |
|---|---|
| Certificate manager (TLA-contract port) | `simulator/sniper/common/system/memory_management/certificates/cert_manager.{h,cc}` |
| AddressSpaceView + radix adapter (perms overlay) | `certificates/address_space_view.h`, `radix_address_space_view.{h,cc}` |
| Certificate RLB (stale-version rejection) | `certificates/cert_rlb.h` |
| Compiler-hint flags + metadata gate | `certificates/hint_flags.h` |
| Adaptive COW estimator (derived 202/178 threshold) | `certificates/adaptive_cow_estimator.h` |
| Revocation sweep interface | `certificates/mutation_listener.h` |
| MMU design (RLB consult, coalesced fills, k-budget baseline, COW hook) | `.../mmu_designs/mmu_vtsa.{h,cc}` (factory type `"vtsa"`) |
| OS side (cert table, hint registry, fork/CoW emulation, mutation entry points) | `common/system/memory_management/mimicos.h` |
| Magic-op decode (region register/unregister, mprotect, fork mark) | `common/system/magic_server.cc` (`SIM_CMD_USER`, cmds `0x75A0-0x75A3`) |
| scan_lag promotion timing | `include/.../reserve_thp.h` (`scan_lag_faults`) |
| Conformance + RLB + estimator test suites | `simulator/sniper/test/vtsa_cert/` (`make run`) |

## Schemes (config/address_translation_schemes/)

- `vtsa_hwk.cfg` — bounded largest-feasible hardware coalescing, k=4
  extra PTE probes (the validation-ceiling baseline; nothing above 16KB).
- `vtsa_auto.cfg` — blind certification: 64-miss/2MB-window trigger,
  granularity fallback 2MB→256KB→64KB→16KB.
- `vtsa_certified.cfg` — hint-gated (REGION_REGISTER magic ops from the
  v-tsa hint runtime; DENSE required, SPARSE/NO_COALESCE/
  SHARED_SENSITIVE/COW_SENSITIVE refuse; refusals fall back to bounded).
- `vtsa_adaptive.cfg` — certified with the COW clause replaced by the
  causal estimator.
- `vtsa_thp.cfg` — instant-promote THP reference, V-TSA off, identical
  TLB hierarchy.

Key knobs under `[perf_model/mmu/vtsa]` (charged-constants defaults from
v-tsa's `tlb_sim.py`): `mode`, `k_budget=4`, `miss_threshold=64`,
`rlb_entries=16`, `cert_check_cycles=2`, `rlb_miss_cycles=20`,
`pte_probe_cycles=4`, `metadata_lookup_cycles=4`, `cow_fault_cycles=180`,
`cow_copy_cycles=2000`, `estimator_walk_cycles=180`. Allocator regime:
`[perf_model/reserve_thp]` `target_fragmentation` (1.0 = contiguity
available), `threshold_for_promotion` (0.0 instant / >1 never),
`scan_lag_faults` (promotion lag in allocation events).

## Invariants the port preserves (tested)

Page tables stay the authority (the consult runs strictly after the walk
and can only widen the installed entry); publish validates every covered
page once and refusal leaves no state; every mutation (unmap, protect,
promote, demote, COW write, fork) revokes overlapping certificates BEFORE
completing and sweeps dependent TLB/RLB entries; versions are monotone so
a stale hint can never alias a reissued certificate. `test/vtsa_cert/`
replays the formal counterexamples and a 2,000-step seeded fuzz
(ASan/UBSan clean); the base MMU's VA↔PA sanity checks run as the
ground-truth guard in every simulation.

## Upstream findings recorded along the way

- `sim_api.h` SimMagic macros clobber operand registers at -O2 (fixed
  register constraints in v-tsa's hint runtime; upstream unpatched).
- The live pin-frontend's magic instrumentation is a TODO; magics flow
  via the SIFT recorder path.
- The userspace-MimicOS process mode is non-functional at `8188baf`
  (stale wrapper; zero translations) — everything here targets
  sniper-space + the in-simulator MimicOS.
- The published trace tarball ships `dlrm.sift` byte-identical to
  `bfs.sift` (and `gc` == `gen`).
- The radix page table cannot rewrite a 2MB leaf into 4KB PTEs (union
  aliasing) — fork/CoW schemes run with promotion disabled.

## Results

Evidence packets live in the v-tsa repo: `results/virtuoso/phase6/`
(30-row grid, heuristic + hint tiers) and `results/virtuoso/gups_sweep/`
(HPCC RandomAccess × fragmentation: −99.3% page walks, −3.6% e2e vs
bounded k=4, 0.27% from THP parity at steady state).
