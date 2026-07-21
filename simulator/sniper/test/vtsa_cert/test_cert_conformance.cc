/* test_cert_conformance.cc - V-TSA port: the formal contract, replayed
 * against the Virtuoso-hosted certificate manager.
 *
 * Port of ukern/tests/test_cert_conformance.c (v-tsa repository).  The
 * suite replays formal/certified/vtsa_certified.tla scenarios against the
 * live implementation:
 *
 * (a) SAFE-MODEL INVARIANT: after ANY sequence of {publish, touch, unmap,
 *     protect, promote, demote}, every LIVE certificate's covered pages
 *     still validate (PagesValidateDescriptor re-evaluated by validate()).
 *     Seeded splitmix64 fuzz, N = 2000 steps, invariant asserted after
 *     EVERY step.
 *
 * (b) The three broken-variant counterexamples as concrete tests:
 *     1. broken/certify_without_page_validation.tla: publishing over a
 *        hole / non-uniform perms / non-contiguous 2MB window MUST be
 *        refused by the API (no cert created).
 *     2. broken/missing_revoke_on_remap_overlap.tla: unmap/protect/
 *        promote/demote over a covered page MUST kill the certificate
 *        (live=0, version bumped) BEFORE the next check.
 *     3. broken/certificate_scope_overrun.tla: check() beyond
 *        [va_base, va_base+bytes) MUST miss even when the probed page is
 *        itself mapped; a hit reports exactly the descriptor's own
 *        base/size.
 *
 * Phase 1 port scope (docs/virtuoso-port-plan.md in the v-tsa repo):
 * fork/COW ops are STUBBED (Virtuoso has no fork/CoW until Phase 5); the
 * fuzz keeps the op slot but substitutes a guarded touch, and the final
 * assertions check forks == 0 instead of forks > 0.  Everything else is
 * a faithful translation.
 */
#include "fake_vspace.h"

#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>

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

static char g_dir[512];

static void path_of(char *out, size_t len, const char *name)
{
    std::snprintf(out, len, "%s/%s", g_dir, name);
}

static uint64_t sm64(uint64_t *s)
{
    uint64_t z = (*s += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

/* ---- shared environment ------------------------------------------------ */

#define REGION_PAGES 4096ull /* 16MB region, 8 windows */
static const uint64_t kGuestBase = 0x10000000ull; /* 2MB-aligned */
static const uint32_t kRW = kPermW | kPermU;

static FakePmm *g_pmm;
static CertificateManager *g_cm;
static FakeVspace *g_vs;

static void env_up(const char *tag)
{
    char p[640], name[128];
    std::snprintf(name, sizeof(name), "conf_%s_certs.jsonl", tag);
    path_of(p, sizeof(p), name);
    g_pmm = new FakePmm();
    g_cm = new CertificateManager();
    CHECK(g_cm->init(p) == 0);
    g_vs = new FakeVspace(g_pmm, g_cm, kGuestBase, REGION_PAGES, kRW);
}

static void env_down()
{
    CHECK(g_cm->shutdown() == 0);
    delete g_vs;
    delete g_cm;
    delete g_pmm;
    g_vs = nullptr;
    g_cm = nullptr;
    g_pmm = nullptr;
}

static uint64_t pva(uint64_t page) { return g_vs->pva(page); }

static void touch_write(FakeVspace *vs, uint64_t page)
{
    CHECK(vs->touch(page, true));
}

static void touch_read(FakeVspace *vs, uint64_t page)
{
    CHECK(vs->touch(page, false));
}

/* ---- (b1) publish-without-validation must be impossible ---------------- */
static void test_counterexample_publish()
{
    env_up("cx_publish");

    /* Hole: pages 0..3 and 5..7 present, 4 absent. */
    for (uint64_t p = 0; p < 8; p++)
        if (p != 4)
            touch_write(g_vs, p);
    CHECK(g_cm->publish(g_vs, pva(0), 8 * kPageSize, kPageSize) == -EINVAL);
    CHECK(g_cm->live_count() == 0);
    CertStatus st;
    CHECK(g_cm->check(g_vs, pva(0), &st) == -ENOENT);

    /* Non-uniform perms: page 10 read-only inside a writable range. */
    for (uint64_t p = 8; p < 16; p++)
        touch_write(g_vs, p);
    CHECK(g_vs->protect(10, 1, kPermU) == 0);
    CHECK(g_cm->publish(g_vs, pva(8), 8 * kPageSize, kPageSize) == -EINVAL);
    CHECK(g_cm->live_count() == 0);
    /* Restore and show the positive control: uniform range publishes. */
    CHECK(g_vs->protect(10, 1, kRW) == 0);
    int64_t ok = g_cm->publish(g_vs, pva(8), 8 * kPageSize, kPageSize);
    CHECK(ok >= 0);
    CHECK(g_cm->validate(ok) == 0);
    CHECK(g_cm->revoke(ok) == 0);

    /* gran=2MB over a NON-CONTIGUOUS window: interleave windows 1 and 2
     * so window 1's frames alternate - PagesValidateDescriptor's
     * ppn = base.ppn + off fails. */
    for (uint64_t i = 0; i < kHugeFrames; i++) {
        touch_write(g_vs, 512 + i);  /* window 1 */
        touch_write(g_vs, 1024 + i); /* window 2 */
    }
    CHECK(g_cm->publish(g_vs, pva(512), kHugeSize, kHugeSize) == -EINVAL);
    CHECK(g_cm->live_count() == 0);
    /* Misaligned 2MB-gran geometry also refused. */
    CHECK(g_cm->publish(g_vs, pva(513), kHugeSize, kHugeSize) == -EINVAL);
    /* Positive control: after the daemon compacts window 1 into a real
     * aligned run, the same publish succeeds. */
    DaemonPolicy pol;
    pol.max_promotions_per_tick = 1;
    CHECK(g_vs->daemon_tick(pol) == 1);
    PageInfo pi;
    CHECK(g_vs->translate(pva(512), pi) && pi.present && pi.level == 2);
    ok = g_cm->publish(g_vs, pva(512), kHugeSize, kHugeSize);
    CHECK(ok >= 0);
    CHECK(g_cm->validate(ok) == 0);

    env_down();
    std::printf("vtsa_p1_cert_counterexample_publish=pass\n");
}

/* ---- (b2) mutation-without-revoke must be impossible -------------------- */
static void test_counterexample_revoke()
{
    env_up("cx_revoke");
    CertStatus st;

    /* unmap a covered page -> cert dead BEFORE the next check. */
    for (uint64_t p = 100; p < 108; p++)
        touch_write(g_vs, p);
    int64_t id = g_cm->publish(g_vs, pva(100), 8 * kPageSize, kPageSize);
    CHECK(id >= 0);
    CHECK(g_cm->check(g_vs, pva(103), &st) == 0 && st.id == id);
    uint64_t v0 = st.version;
    CHECK(g_vs->unmap(102, 1) == 0);
    CHECK(g_cm->get(id, &st) == 0);
    CHECK(!st.live && st.version == v0 + 1); /* version flip */
    CHECK(g_cm->check(g_vs, pva(103), &st) == -ENOENT);

    /* protect (perm change) is a mutation too. */
    for (uint64_t p = 108; p < 116; p++)
        touch_write(g_vs, p);
    id = g_cm->publish(g_vs, pva(108), 8 * kPageSize, kPageSize);
    CHECK(id >= 0);
    CHECK(g_vs->protect(110, 1, kPermU) == 0);
    CHECK(g_cm->get(id, &st) == 0 && !st.live);
    CHECK(g_cm->check(g_vs, pva(108), &st) == -ENOENT);

    /* daemon promotion is a mutation (frames move / PTEs rewritten). */
    for (uint64_t i = 0; i < kHugeFrames; i++)
        touch_write(g_vs, 1536 + i); /* window 3 full */
    id = g_cm->publish(g_vs, pva(1600), 16 * kPageSize, kPageSize);
    CHECK(id >= 0);
    DaemonPolicy pol;
    CHECK(g_vs->daemon_tick(pol) == 1);
    CHECK(g_cm->get(id, &st) == 0 && !st.live);

    /* demotion is a mutation as well. */
    id = g_cm->publish(g_vs, pva(1536), kHugeSize, kHugeSize);
    CHECK(id >= 0);
    CHECK(g_vs->demote(pva(1536)) == 0);
    CHECK(g_cm->get(id, &st) == 0 && !st.live);
    /* After demotion the window is still contiguous+aligned: it can be
     * re-certified - versions keep moving forward on the reused slot. */
    int64_t id2 = g_cm->publish(g_vs, pva(1536), kHugeSize, kHugeSize);
    CHECK(id2 >= 0);
    CHECK(g_cm->get(id2, &st) == 0 && st.live);
    CHECK(g_cm->validate(id2) == 0);

    env_down();
    std::printf("vtsa_p1_cert_counterexample_revoke=pass\n");
}

/* ---- (b3) scope overrun must be impossible ------------------------------ */
static void test_counterexample_scope()
{
    env_up("cx_scope");
    CertStatus st;

    for (uint64_t p = 199; p < 210; p++) /* neighbors mapped */
        touch_write(g_vs, p);
    int64_t id = g_cm->publish(g_vs, pva(200), 8 * kPageSize, kPageSize);
    CHECK(id >= 0);

    /* Inside: hit, and the returned authority is EXACTLY the cert's. */
    CHECK(g_cm->check(g_vs, pva(207) + 4095, &st) == 0);
    CHECK(st.id == id && st.va_base == pva(200) &&
          st.bytes == 8 * kPageSize);
    /* One page beyond either end: MISS - even though those pages are
     * present and translatable (the certificate conveys no authority
     * over them). */
    PageInfo pi;
    CHECK(g_vs->translate(pva(208), pi) && pi.present);
    CHECK(g_cm->check(g_vs, pva(208), &st) == -ENOENT);
    CHECK(g_vs->translate(pva(199), pi) && pi.present);
    CHECK(g_cm->check(g_vs, pva(199), &st) == -ENOENT);
    /* A different address space never hits this one's certs. */
    FakeVspace other(g_pmm, g_cm, kGuestBase, REGION_PAGES, kRW);
    CHECK(g_cm->check(&other, pva(204), &st) == -ENOENT);

    env_down();
    std::printf("vtsa_p1_cert_counterexample_scope=pass\n");
}

/* ---- (a) the safe-model invariant under a seeded op fuzz ---------------- */

#define FUZZ_STEPS 2000
#define FUZZ_SEED 0x156C0FFEEull

struct FuzzCounters
{
    uint64_t publishes_ok = 0, publishes_refused = 0, revokes_ok = 0;
    uint64_t touches = 0, unmaps = 0, protects = 0, ticks = 0, demotes = 0,
             forks = 0;
    uint64_t checks_hit = 0, checks_miss = 0, invariant_checks = 0;
};

/* Guarded touch: never write a read-only page (protection violation -
 * no COW to rescue it until Phase 5). */
static void fuzz_touch(FakeVspace *vs, uint64_t page, uint64_t rnd,
                       FuzzCounters *c)
{
    bool want_write = (rnd & 1);
    PageInfo pi;
    vs->translate(vs->pva(page), pi);
    if (want_write && pi.present && !(pi.perms & kPermW))
        want_write = false; /* genuinely RO */
    CHECK(vs->touch(page, want_write));
    c->touches++;
}

static bool range_has_hole(FakeVspace *vs, uint64_t page, uint64_t npages)
{
    for (uint64_t p = page; p < page + npages; p++) {
        PageInfo pi;
        if (!vs->translate(vs->pva(p), pi) || !pi.present)
            return true;
    }
    return false;
}

/* THE INVARIANT: every live certificate still validates. */
static void assert_all_live_certs_validate(FuzzCounters *c)
{
    for (int64_t id = 0; id < kCertMax; id++) {
        CertStatus st;
        if (g_cm->get(id, &st) != 0 || !st.live)
            continue;
        CHECK(g_cm->validate(id) == 0);
        c->invariant_checks++;
    }
}

static void test_fuzz()
{
    env_up("fuzz");
    uint64_t rng = FUZZ_SEED;
    FuzzCounters c;
    DaemonPolicy pol;
    pol.max_promotions_per_tick = 2;

    for (int step = 0; step < FUZZ_STEPS; step++) {
        uint64_t op = sm64(&rng) % 100;
        if (op < 30) { /* touch */
            (void)sm64(&rng); /* vs pick (single space until Phase 5) */
            fuzz_touch(g_vs, sm64(&rng) % REGION_PAGES, sm64(&rng), &c);
        } else if (op < 45) { /* publish 4KB gran */
            (void)sm64(&rng);
            uint64_t len = 1 + sm64(&rng) % 32;
            uint64_t start = sm64(&rng) % (REGION_PAGES - len);
            int64_t id =
                g_cm->publish(g_vs, pva(start), len * kPageSize, kPageSize);
            if (id >= 0) {
                c.publishes_ok++;
                CHECK(g_cm->validate(id) == 0);
            } else {
                CHECK(id == -EINVAL || id == -ENOSPC);
                c.publishes_refused++;
            }
        } else if (op < 50) { /* publish 2MB gran */
            (void)sm64(&rng);
            uint64_t win = sm64(&rng) % (REGION_PAGES / 512);
            int64_t id =
                g_cm->publish(g_vs, pva(win * 512), kHugeSize, kHugeSize);
            if (id >= 0) {
                c.publishes_ok++;
                CHECK(g_cm->validate(id) == 0);
            } else {
                CHECK(id == -EINVAL || id == -ENOSPC);
                c.publishes_refused++;
            }
        } else if (op < 58) { /* revoke */
            if (g_cm->revoke((int64_t)(sm64(&rng) % kCertMax)) == 0)
                c.revokes_ok++;
        } else if (op < 70) { /* unmap subrange */
            (void)sm64(&rng);
            uint64_t len = 1 + sm64(&rng) % 8;
            uint64_t start = sm64(&rng) % (REGION_PAGES - len);
            CHECK(g_vs->unmap(start, len) == 0);
            c.unmaps++;
        } else if (op < 75) { /* protect subrange */
            (void)sm64(&rng);
            uint64_t len = 1 + sm64(&rng) % 4;
            uint64_t start = sm64(&rng) % (REGION_PAGES - len);
            if (!range_has_hole(g_vs, start, len)) {
                uint32_t prot = (sm64(&rng) & 1) ? kPermU : kRW;
                if (g_vs->protect(start, len, prot) == 0)
                    c.protects++;
            }
        } else if (op < 80) { /* fill win + tick */
            (void)sm64(&rng);
            uint64_t win = sm64(&rng) % (REGION_PAGES / 512);
            for (uint64_t i = 0; i < kHugeFrames; i++)
                fuzz_touch(g_vs, win * 512 + i, sm64(&rng) | 1, &c);
            g_vs->daemon_tick(pol);
            c.ticks++;
        } else if (op < 85) { /* demote */
            (void)sm64(&rng);
            if (g_vs->has_huge_window()) {
                CHECK(g_vs->demote(g_vs->first_huge_va()) == 0);
                c.demotes++;
            }
        } else if (op < 92) { /* fork / COW write - STUBBED until Phase 5 */
            fuzz_touch(g_vs, sm64(&rng) % REGION_PAGES, 1, &c);
        } else { /* check consistency */
            (void)sm64(&rng);
            uint64_t page = sm64(&rng) % REGION_PAGES;
            CertStatus st;
            int rc = g_cm->check(g_vs, pva(page), &st);
            if (rc == 0) {
                c.checks_hit++;
                CHECK(pva(page) >= st.va_base &&
                      pva(page) < st.va_base + st.bytes);
                CertStatus s3;
                CHECK(g_cm->get(st.id, &s3) == 0 && s3.live &&
                      s3.version == st.version);
            } else {
                CHECK(rc == -ENOENT);
                c.checks_miss++;
                /* miss must mean NO live cert covers (vs, va) - single
                 * address space, so this is fully checkable here */
                for (int64_t id = 0; id < kCertMax; id++) {
                    CertStatus s2;
                    if (g_cm->get(id, &s2) == 0 && s2.live)
                        CHECK(!(pva(page) >= s2.va_base &&
                                pva(page) < s2.va_base + s2.bytes));
                }
            }
        }
        /* THE SAFE-MODEL INVARIANT, asserted after EVERY step. */
        assert_all_live_certs_validate(&c);
    }

    std::printf(
        "vtsa_p1_cert_fuzz=pass steps=%d seed=0x%llx invariant_checks=%" PRIu64
        " publishes_ok=%" PRIu64 " publishes_refused=%" PRIu64
        " revokes=%" PRIu64 " touches=%" PRIu64 " unmaps=%" PRIu64
        " protects=%" PRIu64 " ticks=%" PRIu64 " demotes=%" PRIu64
        " forks=%" PRIu64 " checks_hit=%" PRIu64 " checks_miss=%" PRIu64 "\n",
        FUZZ_STEPS, (unsigned long long)FUZZ_SEED, c.invariant_checks,
        c.publishes_ok, c.publishes_refused, c.revokes_ok, c.touches,
        c.unmaps, c.protects, c.ticks, c.demotes, c.forks, c.checks_hit,
        c.checks_miss);
    CHECK(c.publishes_ok > 50); /* the fuzz exercised the model */
    CHECK(c.publishes_refused > 0);
    CHECK(c.invariant_checks > 1000);
    CHECK(c.forks == 0); /* Phase 1 scope: fork/COW arrive in Phase 5 */

    std::printf("vtsa_p1_cert_fuzz_daemon: promotions=%" PRIu64
                " demotions=%" PRIu64 "\n",
                g_vs->daemon_stats().promotions,
                g_vs->daemon_stats().demotions);

    env_down();
}

int main(int argc, char **argv)
{
    if (argc > 1) {
        std::snprintf(g_dir, sizeof(g_dir), "%s", argv[1]);
    } else {
        std::snprintf(g_dir, sizeof(g_dir), "/tmp/vtsa_cert_XXXXXX");
        CHECK(mkdtemp(g_dir) != nullptr);
    }
    test_counterexample_publish();
    test_counterexample_revoke();
    test_counterexample_scope();
    test_fuzz();
    std::printf("vtsa_p1_cert_conformance=pass\n");
    return 0;
}
