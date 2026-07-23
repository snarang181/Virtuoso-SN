/* test_cert_upgrade.cc - V-TSA: directed tests for the granularity
 * upgrade path (the mosaic fix).
 *
 * Properties pinned:
 *   1. publish-first ordering: an enclosing 2MB certificate may be
 *      published while smaller certs still cover parts of the range
 *      (overlap is legal; check() semantics unaffected for covered VAs).
 *   2. revoke_overlapping_except retires every overlapping cert EXCEPT
 *      the new one, each with an ordinary version bump.
 *   3. after the upgrade the large cert validates and serves checks;
 *      stale RLB entries for the subsumed certs are version-rejected.
 *   4. the upgrade is NOT a page-table mutation: every page translates
 *      to the same frame before and after.
 */
#include "../../common/system/memory_management/certificates/cert_rlb.h"
#include "fake_vspace.h"

#include <cerrno>
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

    /* Burn frames 1..511 on window 0 so window 1's pages land on an
     * aligned, contiguous frame run (frames 512..1023). */
    for (uint64_t p = 0; p < 511; p++)
        CHECK(vs.touch(p, true));
    for (uint64_t p = 512; p < 1024; p++)
        CHECK(vs.touch(p, true));

    /* The mosaic: four 64KB certs over the first 64 pages of window 1. */
    int64_t small_ids[4];
    for (int i = 0; i < 4; i++) {
        small_ids[i] = cm.publish(&vs, vs.pva(512 + 16 * i), 64ull << 10,
                                  64ull << 10);
        CHECK(small_ids[i] >= 0);
    }
    CHECK(cm.live_count() == 4);

    /* Record pre-upgrade translations for property 4. */
    uint64_t frames_before[8];
    for (int i = 0; i < 8; i++) {
        PageInfo pi;
        CHECK(vs.translate(vs.pva(512 + 64 * i), pi) && pi.present);
        frames_before[i] = pi.frame;
    }

    /* Cache one small cert in an RLB (property 3 setup). */
    CertRLB rlb(8);
    CertStatus st_small;
    CHECK(cm.get(small_ids[0], &st_small) == 0);
    rlb.insert(&vs, st_small);
    CertRLB::Entry ent;
    CHECK(rlb.lookup(&vs, vs.pva(513), cm, &ent) && ent.id == small_ids[0]);

    /* --- the upgrade sequence, publish-first --- */
    const char *why;
    CHECK(CertificateManager::validate_range(&vs, vs.pva(512), kHugeSize,
                                             kHugeSize, &why) == 0);
    int64_t big = cm.publish(&vs, vs.pva(512), kHugeSize, kHugeSize);
    CHECK(big >= 0);
    /* Overlap is legal pre-subsumption: 5 live certs. */
    CHECK(cm.live_count() == 5);

    uint64_t small_versions[4];
    for (int i = 0; i < 4; i++) {
        CertStatus s;
        CHECK(cm.get(small_ids[i], &s) == 0 && s.live);
        small_versions[i] = s.version;
    }

    cm.revoke_overlapping_except(&vs, vs.pva(512), kHugeSize, big);

    /* Property 2: every small cert dead with version+1; big cert kept. */
    for (int i = 0; i < 4; i++) {
        CertStatus s;
        CHECK(cm.get(small_ids[i], &s) == 0);
        CHECK(!s.live && s.version == small_versions[i] + 1);
    }
    CertStatus st_big;
    CHECK(cm.get(big, &st_big) == 0 && st_big.live);
    CHECK(cm.live_count() == 1);
    CHECK(cm.validate(big) == 0);

    /* Property 3: the check path serves the big cert everywhere in the
     * window; the stale RLB entry is version-rejected, never served. */
    CertStatus st;
    CHECK(cm.check(&vs, vs.pva(513), &st) == 0 && st.id == big &&
          st.gran == kHugeSize);
    CHECK(!rlb.lookup(&vs, vs.pva(513), cm, &ent));
    CHECK(rlb.stats().stale_rejects == 1);
    rlb.insert(&vs, st_big);
    CHECK(rlb.lookup(&vs, vs.pva(1000), cm, &ent) && ent.id == big);

    /* Property 4: no translation changed - upgrade is not a mutation. */
    for (int i = 0; i < 8; i++) {
        PageInfo pi;
        CHECK(vs.translate(vs.pva(512 + 64 * i), pi) && pi.present);
        CHECK(pi.frame == frames_before[i]);
    }

    /* keep_id discipline: revoking with a keep range NOT covering the
     * keeper must still keep it (id filter, not geometry). */
    int64_t other = cm.publish(&vs, vs.pva(0), 16 * kPageSize, kPageSize);
    CHECK(other >= 0);
    cm.revoke_overlapping_except(&vs, vs.pva(0), 32 * kPageSize, other);
    CertStatus s2;
    CHECK(cm.get(other, &s2) == 0 && s2.live);

    CHECK(cm.shutdown() == 0);
    std::printf("vtsa_upgrade=pass subsumed=4 kept=big stale_rejects=1\n");
    return 0;
}
