/* cert_manager.h - V-TSA port: certificate manager - the formal contract,
 * executable, re-hosted on Virtuoso.
 *
 * Faithful port of ukern/cert.c (v-tsa repository), which is the executable
 * counterpart of formal/certified/vtsa_certified.tla.  The TLA-action
 * mapping is preserved verbatim:
 *
 *   TLA+ action / definition           ->  this class
 *   ------------------------------------------------------------------
 *   PublishDescriptor                  ->  publish()
 *   PagesValidateDescriptor            ->  validate_range() (also exposed
 *                                          as validate())
 *   RevokeDescriptor                   ->  revoke()
 *   RemapPage/UnmapPage =>
 *     RevokeOverlappingDescriptors     ->  on_mutation() - the address-
 *                                          space mutation hook; must be
 *                                          invoked by unmap, protect,
 *                                          promotion, demotion, COW write
 *                                          and fork BEFORE the operation
 *                                          completes
 *   HintMatchesOSDescriptor (OS side)  ->  check(): descriptor fields
 *                                          only, NO page walk - the O(1)
 *                                          miss-path check the MMU model
 *                                          calls
 *   version flip (NextRegionVersion)   ->  monotone uint64 version bump
 *                                          (strictly stronger: a stale
 *                                          hint can never alias a
 *                                          reissued version)
 *   descriptor-id reuse                ->  slot reuse with version
 *                                          continuity per slot
 *
 * Port deltas vs ukern/cert.c (deliberate, recorded in
 * docs/virtuoso-port-plan.md of the v-tsa repo):
 *   - ukern_vspace*        -> const AddressSpaceView* (same pointer-
 *                             identity scoping; TLA ASID role)
 *   - signal-safe write(2) logging -> std::FILE JSONL (no SIGSEGV pager
 *                             here; MimicOS faults are simulated events)
 *   - schema string is "vtsa_cert_events_v1"; event names and fields are
 *                             unchanged from ukern so packet tooling
 *                             parses both
 *
 * Unlike the ukern host, Virtuoso has a real simulated TLB: check-time
 * liveness+version guarding is NOT sufficient there.  The Phase 3 MMU work
 * must sweep dependent TLB/RLB entries on revocation (SweepMutatedPage).
 * This class only guarantees the descriptor-side contract.
 */
#pragma once
#include "address_space_view.h"

#include <cstdint>
#include <cstdio>

namespace vtsa
{

/* Port delta (recorded): ukern used 256 slots for few, large,
 * region-granularity certificates; the Virtuoso port certifies per
 * gran-window, so large working sets need a bigger table. Slot reuse
 * and version continuity are unchanged. */
constexpr int64_t kCertMax = 4096;

struct CertStatus
{
    int64_t  id      = -1;
    int      live    = 0;
    uint64_t version = 0;
    uint64_t va_base = 0;
    uint64_t bytes   = 0;
    uint64_t gran    = 0;
};

class CertificateManager
{
public:
    CertificateManager() = default;
    ~CertificateManager();

    /* Lifecycle.  event_log_path may be null (no log).  Returns 0, or
     * -EBUSY if already active / a negative errno on open failure. */
    int init(const char *event_log_path);
    int shutdown();

    /* PublishDescriptor: validate the whole range ONCE, then publish.
     * Returns slot id >= 0, -EINVAL (refused, no state created) or
     * -ENOSPC (table full). */
    int64_t publish(const AddressSpaceView *as, uint64_t va, uint64_t bytes,
                    uint64_t gran);

    /* RevokeDescriptor: -EINVAL bad id, -ENOENT not live, else 0. */
    int revoke(int64_t id);

    /* HintMatchesOSDescriptor, OS half: find a LIVE descriptor covering
     * (as, va).  Deliberately NO walk over covered pages - certification
     * validated them and every mutation revokes.  0 on hit (fills out),
     * -ENOENT on miss. */
    int check(const AddressSpaceView *as, uint64_t va, CertStatus *out);

    /* Slot inspection (live OR revoked) - test/consistency aid. */
    int get(int64_t id, CertStatus *out) const;

    /* Re-run PagesValidateDescriptor for a live cert against the current
     * tables: 0 = still valid.  The conformance invariant probe. */
    int validate(int64_t id) const;

    /* RemapPage/UnmapPage => RevokeOverlappingDescriptors.  Call sites:
     * unmap, protect, promote, demote, COW write, fork - before the
     * operation completes. */
    void on_mutation(const AddressSpaceView *as, uint64_t va,
                     uint64_t bytes);

    /* Granularity upgrade support: revoke every live cert of `as`
     * overlapping [va, va+bytes) EXCEPT keep_id.  Used after publishing
     * an enclosing larger-granularity certificate (safe order: publish
     * first - ENOSPC aborts with the small certs intact - then subsume).
     * Same RevokeDescriptor semantics per revoked slot (version bump);
     * upgrades are not page-table mutations, so no TLB sweep is required
     * (frames are unchanged; stale RLB entries die on version check). */
    void revoke_overlapping_except(const AddressSpaceView *as, uint64_t va,
                                   uint64_t bytes, int64_t keep_id);

    uint64_t live_count() const;
    uint64_t event_seq() const { return m_active ? m_seq : 0; }

    /* PagesValidateDescriptor, executable (see cert.c:validate_range).
     * Exposed for the MMU-side granularity-fallback probe.
     *
     * Port delta vs ukern (recorded): gran accepts the full coalescing
     * set {4KB, 16KB, 64KB, 256KB, 2MB} - the window contiguity/alignment
     * checks generalize verbatim (gran_frames = gran/4KB); ukern's
     * {4KB, 2MB} behavior is the unchanged subset, which the conformance
     * suite pins.  pages_checked (optional) reports pages walked before
     * success/refusal so callers can charge validation cost exactly. */
    static int validate_range(const AddressSpaceView *as, uint64_t va,
                              uint64_t bytes, uint64_t gran,
                              const char **why,
                              uint64_t *pages_checked = nullptr);

    static bool gran_allowed(uint64_t gran)
    {
        return gran == kPageSize || gran == (16ull << 10) ||
               gran == (64ull << 10) || gran == (256ull << 10) ||
               gran == kHugeSize;
    }

private:
    struct Cert
    {
        int                     live    = 0;
        uint64_t                version = 0; /* bumps on publish AND revoke */
        const AddressSpaceView *as      = nullptr;
        uint64_t                va_base = 0;
        uint64_t                bytes   = 0;
        uint64_t                gran    = 0;
    };

    void revoke_slot(int64_t id, const char *cause);

    void log_publish(int64_t id, const Cert &c);
    void log_refuse(uint64_t va, uint64_t bytes, uint64_t gran,
                    const char *reason);
    void log_revoke(int64_t id, const Cert &c, const char *cause);
    void log_check_miss(uint64_t va);

    bool       m_active = false;
    std::FILE *m_log    = nullptr;
    uint64_t   m_seq    = 0;
    Cert       m_certs[kCertMax];
};

} // namespace vtsa
