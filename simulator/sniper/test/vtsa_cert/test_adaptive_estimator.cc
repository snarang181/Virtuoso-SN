/* test_adaptive_estimator.cc - V-TSA: directed tests for the adaptive
 * certification gate (port of tlb_sim.py::AdaptiveCowEstimator).
 *
 * Pins: the derived threshold (202/178 with charged constants - derived,
 * never fitted), optimistic epoch-0 certify, refusal under revocation-
 * dominated cadence, certify under access-dominated cadence, same-clock
 * revocation coalescing, and causality (a past decision cannot change
 * until the next revocation epoch).
 */
#include "../../common/system/memory_management/certificates/adaptive_cow_estimator.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>

using vtsa::AdaptiveCowEstimator;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, \
                         __LINE__, #cond);                                \
            std::exit(1);                                                 \
        }                                                                 \
    } while (0)

int main()
{
    /* Charged-constants mode: walk 180, cert check 2, RLB miss 20. */
    AdaptiveCowEstimator est(180, 2, 20);

    /* Threshold derivation cross-check: 202/178 = 1.1348... */
    double thr = est.certify_threshold_accesses();
    CHECK(std::fabs(thr - 202.0 / 178.0) < 1e-12);

    /* Epoch 0: optimistic certify. */
    CHECK(est.decide(1));

    /* Region 2: revocation-dominated (interval ~1 access < threshold)
     * => refuse. */
    for (int i = 0; i < 6; i++) {
        est.note_access(2);
        est.observe_revocation(2);
    }
    CHECK(!est.decide(2));

    /* Region 3: access-dominated (interval 100 >> threshold) => certify. */
    for (int i = 0; i < 5; i++) {
        for (int a = 0; a < 100; a++)
            est.note_access(3);
        est.observe_revocation(3);
    }
    CHECK(est.decide(3));

    /* Same-clock coalescing: many certs swept by ONE mutation = one
     * revocation event, not many. */
    for (int a = 0; a < 100; a++)
        est.note_access(4);
    est.observe_revocation(4);
    est.observe_revocation(4); /* same clock: coalesced */
    est.observe_revocation(4); /* same clock: coalesced */
    CHECK(est.slot(4)->revocations == 1);
    CHECK(est.slot(4)->coalesced_same_clock == 2);
    CHECK(est.decide(4)); /* interval 100 -> certify */

    /* Causality: the answer is epoch-cached; accesses after a decision do
     * not flip it until the next revocation. */
    bool before = est.decide(2);
    for (int a = 0; a < 1000; a++)
        est.note_access(2);
    CHECK(est.decide(2) == before);
    est.observe_revocation(2); /* interval 1001 now enters the window */
    /* mean(1,1,1,1001)... window K=4 keeps last 4: (1,1,1,1001)/4 = 251
     * > 1.135 -> certify */
    CHECK(est.decide(2));

    std::printf("vtsa_p5_adaptive_estimator=pass threshold=%.4f\n", thr);
    return 0;
}
