/* test_cert_rlb.cc - V-TSA: directed tests for the certificate RLB.
 *
 * The property under test is the Phase 2 gate: a STALE RLB entry (its
 * certificate revoked or reissued since caching) must never authorize a
 * fill - lookup re-verifies liveness+version against the certificate
 * table and drops mismatches (the monotone-version discipline made
 * MMU-visible).  Also covers LRU capacity behavior and overlap sweep.
 */
#include "../../common/system/memory_management/certificates/cert_rlb.h"
#include "fake_vspace.h"

#include <cstdio>
#include <cstdlib>

using namespace vtsa;
using namespace vtsa_test;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, \
                         __LINE__, #cond);                                \
            std::exit(1);                                                 \
        }                                                                 \
    } while (0)

static const uint64_t kBase = 0x10000000ull;
static const uint32_t kRW = kPermW | kPermU;

int main()
{
    FakePmm pmm;
    CertificateManager cm;
    CHECK(cm.init(nullptr) == 0);
    FakeVspace vs(&pmm, &cm, kBase, 4096, kRW);

    for (uint64_t p = 0; p < 64; p++)
        CHECK(vs.touch(p, true));

    /* Publish and cache in the RLB. */
    int64_t id = cm.publish(&vs, vs.pva(0), 16 * kPageSize, kPageSize);
    CHECK(id >= 0);
    CertStatus st;
    CHECK(cm.get(id, &st) == 0);

    CertRLB rlb(4);
    rlb.insert(&vs, st);
    CertRLB::Entry ent;
    CHECK(rlb.lookup(&vs, vs.pva(3), cm, &ent) && ent.id == id);
    CHECK(rlb.stats().hits == 1);

    /* Mutation revokes the cert; the cached RLB entry MUST go stale and
     * the next lookup MUST miss (never authorize a fill). */
    CHECK(vs.unmap(2, 1) == 0);
    CHECK(!rlb.lookup(&vs, vs.pva(3), cm, &ent));
    CHECK(rlb.stats().stale_rejects == 1);

    /* Reissue on the same slot: version moved on, RLB re-populates with
     * the NEW version and hits again. */
    for (uint64_t p = 16; p < 32; p++)
        CHECK(vs.touch(p, true));
    int64_t id2 = cm.publish(&vs, vs.pva(16), 16 * kPageSize, kPageSize);
    CHECK(id2 >= 0);
    CertStatus st2;
    CHECK(cm.get(id2, &st2) == 0);
    rlb.insert(&vs, st2);
    CHECK(rlb.lookup(&vs, vs.pva(20), cm, &ent) && ent.version == st2.version);

    /* A stale-version clone of the entry (old version forced) must be
     * rejected even though the slot id is live: version mismatch. */
    CertStatus forged = st2;
    forged.version = st2.version - 1; /* stale/forged version */
    CertRLB rlb2(4);
    rlb2.insert(&vs, forged);
    CHECK(!rlb2.lookup(&vs, vs.pva(20), cm, &ent));
    CHECK(rlb2.stats().stale_rejects == 1);

    /* Capacity + LRU: 4-entry RLB, insert 5, oldest evicted. */
    CertRLB rlb3(4);
    int64_t ids[5];
    for (int i = 0; i < 5; i++) {
        for (uint64_t p = 512ull + 16 * i; p < 512ull + 16 * i + 16; p++)
            CHECK(vs.touch(p, true));
        ids[i] = cm.publish(&vs, vs.pva(512 + 16 * i), 16 * kPageSize,
                            kPageSize);
        CHECK(ids[i] >= 0);
        CertStatus s;
        CHECK(cm.get(ids[i], &s) == 0);
        rlb3.insert(&vs, s);
    }
    CHECK(!rlb3.lookup(&vs, vs.pva(512), cm, &ent));      /* evicted   */
    CHECK(rlb3.lookup(&vs, vs.pva(512 + 16), cm, &ent));  /* retained  */

    /* Overlap sweep drops dependent entries. */
    rlb3.invalidate_overlap(&vs, vs.pva(512 + 32), 16 * kPageSize);
    CHECK(!rlb3.lookup(&vs, vs.pva(512 + 32), cm, &ent));

    CHECK(cm.shutdown() == 0);
    std::printf("vtsa_p2_cert_rlb=pass stale_rejects_verified=2\n");
    return 0;
}
