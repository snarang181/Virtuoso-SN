/* cert_manager.cc - V-TSA port of ukern/cert.c.  See cert_manager.h for the
 * TLA-action mapping and the recorded port deltas. */
#include "cert_manager.h"

#include <cerrno>
#include <cinttypes>

namespace vtsa
{

/* ---- event log (JSONL; ukern event names, vtsa schema string) -------- */

void CertificateManager::log_publish(int64_t id, const Cert &c)
{
    if (!m_log)
        { m_seq++; return; }
    std::fprintf(m_log,
                 "{\"seq\":%" PRIu64 ",\"event\":\"cert_publish\","
                 "\"id\":%" PRId64 ",\"va\":\"0x%" PRIx64
                 "\",\"bytes\":%" PRIu64 ",\"gran\":%" PRIu64
                 ",\"version\":%" PRIu64 "}\n",
                 ++m_seq, id, c.va_base, c.bytes, c.gran, c.version);
    std::fflush(m_log);
}

void CertificateManager::log_refuse(uint64_t va, uint64_t bytes,
                                    uint64_t gran, const char *reason)
{
    if (!m_log)
        { m_seq++; return; }
    std::fprintf(m_log,
                 "{\"seq\":%" PRIu64
                 ",\"event\":\"cert_publish_refused\",\"va\":\"0x%" PRIx64
                 "\",\"bytes\":%" PRIu64 ",\"gran\":%" PRIu64
                 ",\"reason\":\"%s\"}\n",
                 ++m_seq, va, bytes, gran, reason);
    std::fflush(m_log);
}

void CertificateManager::log_revoke(int64_t id, const Cert &c,
                                    const char *cause)
{
    if (!m_log)
        { m_seq++; return; }
    std::fprintf(m_log,
                 "{\"seq\":%" PRIu64 ",\"event\":\"cert_revoke\","
                 "\"id\":%" PRId64 ",\"va\":\"0x%" PRIx64
                 "\",\"version\":%" PRIu64 ",\"cause\":\"%s\"}\n",
                 ++m_seq, id, c.va_base, c.version, cause);
    std::fflush(m_log);
}

void CertificateManager::log_check_miss(uint64_t va)
{
    if (!m_log)
        { m_seq++; return; }
    std::fprintf(m_log,
                 "{\"seq\":%" PRIu64
                 ",\"event\":\"cert_check_miss\",\"va\":\"0x%" PRIx64
                 "\"}\n",
                 ++m_seq, va);
    std::fflush(m_log);
}

/* ---- PagesValidateDescriptor, executable ------------------------------ *
 * formal/certified/vtsa_certified.tla:
 *   PagesValidateDescriptor(desc) ==
 *     /\ DescriptorRangeInBounds(desc)
 *     /\ pageTable[asid][base].perms # {}
 *     /\ \A off: present /\ ppn = base.ppn + off /\ perms = base.perms
 * Mapped as in ukern: range in canonical bounds and gran-aligned; every
 * covered 4KB page present; W/U perms equal to the first page's; for
 * gran=2MB each window is a contiguous, 2MB-aligned frame run (either a
 * real 2MB leaf - contiguity guaranteed by construction - or 512 4KB PTEs
 * whose frames form such a run).                                          */
int CertificateManager::validate_range(const AddressSpaceView *as,
                                       uint64_t va, uint64_t bytes,
                                       uint64_t gran, const char **why,
                                       uint64_t *pages_checked)
{
    *why = "ok";
    if (pages_checked)
        *pages_checked = 0;
    if (!as || bytes == 0 || !gran_allowed(gran) || (va % gran) != 0 ||
        (bytes % gran) != 0) {
        *why = "bad_geometry";
        return -EINVAL;
    }
    if (va + bytes < va || va + bytes - 1 >= (1ull << (kVaBits - 1))) {
        *why = "out_of_bounds";              /* DescriptorRangeInBounds */
        return -EINVAL;
    }
    const uint64_t gran_frames = gran >> kPageShift;
    uint32_t perms0 = 0;
    bool have_perms0 = false;
    uint64_t win_base_frame = 0;
    PageInfo pi;
    for (uint64_t off = 0; off < bytes; off += kPageSize) {
        if (pages_checked)
            (*pages_checked)++;
        if (!as->translate(va + off, pi) || !pi.present) {
            *why = "page_absent";            /* hole => refuse           */
            return -EINVAL;
        }
        uint32_t perms = pi.perms & (kPermW | kPermU);
        if (!have_perms0) {
            perms0 = perms;
            have_perms0 = true;
        } else if (perms != perms0) {
            *why = "perms_not_uniform";      /* perms = base.perms       */
            return -EINVAL;
        }
        if (gran > kPageSize) {
            uint64_t widx = (off >> kPageShift) & (gran_frames - 1);
            if (widx == 0) {
                win_base_frame = pi.frame;
                /* Window base must be gran-aligned physically.  A level-2
                 * (2MB) leaf guarantees 2MB alignment by construction.   */
                if (!(gran == kHugeSize && pi.level == 2) &&
                    (pi.frame % gran_frames) != 0) {
                    *why = "window_not_aligned";
                    return -EINVAL;
                }
            } else if (pi.frame != win_base_frame + widx) {
                *why = "window_not_contiguous"; /* ppn = base.ppn + off  */
                return -EINVAL;
            }
        }
    }
    return 0;
}

/* ---- RevokeOverlappingDescriptors ------------------------------------- */

void CertificateManager::revoke_slot(int64_t id, const char *cause)
{
    Cert &c = m_certs[id];
    c.live = 0;                  /* valid   = FALSE                       */
    c.version++;                 /* version flip (monotone counter)       */
    log_revoke(id, c, cause);    /* (noCoalesce=TRUE lives in the MMU
                                    sweep, Phase 3 - a dead cert can never
                                    be checked here)                      */
}

/* The address-space mutation hook: RemapPage/UnmapPage =>
 * RevokeOverlappingDescriptors.  Must also be invoked by promotion,
 * demotion, COW writes and fork.                                          */
void CertificateManager::on_mutation(const AddressSpaceView *as, uint64_t va,
                                     uint64_t bytes)
{
    if (!m_active || bytes == 0)
        return;
    for (int64_t i = 0; i < kCertMax; i++) {
        Cert &c = m_certs[i];
        if (c.live && c.as == as && va < c.va_base + c.bytes &&
            c.va_base < va + bytes)
            revoke_slot(i, "mutation");
    }
}

/* Granularity upgrade: subsume smaller certificates under a freshly
 * published larger one.  Caller publishes the large cert FIRST (so a full
 * table aborts the upgrade without losing coverage), then calls this to
 * retire the now-redundant smaller certs.  Each retirement is an ordinary
 * revocation (version bump, logged with cause "upgrade"). */
void CertificateManager::revoke_overlapping_except(const AddressSpaceView *as,
                                                   uint64_t va,
                                                   uint64_t bytes,
                                                   int64_t keep_id)
{
    if (!m_active || bytes == 0)
        return;
    for (int64_t i = 0; i < kCertMax; i++) {
        if (i == keep_id)
            continue;
        Cert &c = m_certs[i];
        if (c.live && c.as == as && va < c.va_base + c.bytes &&
            c.va_base < va + bytes)
            revoke_slot(i, "upgrade");
    }
}

/* ---- lifecycle --------------------------------------------------------- */

int CertificateManager::init(const char *event_log_path)
{
    if (m_active)
        return -EBUSY;
    for (Cert &c : m_certs)
        c = Cert{};
    m_seq = 0;
    m_log = nullptr;
    if (event_log_path) {
        m_log = std::fopen(event_log_path, "w");
        if (!m_log)
            return -errno;
        std::fputs("{\"schema\":\"vtsa_cert_events_v1\"}\n", m_log);
        std::fflush(m_log);
    }
    m_active = true;
    return 0;
}

int CertificateManager::shutdown()
{
    if (!m_active)
        return -EINVAL;
    if (m_log)
        std::fclose(m_log);
    m_log = nullptr;
    for (Cert &c : m_certs)
        c = Cert{};
    m_seq = 0;
    m_active = false;
    return 0;
}

CertificateManager::~CertificateManager()
{
    if (m_active)
        shutdown();
}

/* ---- PublishDescriptor -------------------------------------------------- */

void CertificateManager::set_capacity(int64_t n)
{
    if (n < 1) n = 1;
    if (n > kCertMax) n = kCertMax;
    m_capacity = n;
}

int64_t CertificateManager::publish(const AddressSpaceView *as, uint64_t va,
                                    uint64_t bytes, uint64_t gran)
{
    if (!m_active || !as)
        return -EINVAL;
    const char *why;
    /* PublishDescriptor's enabling condition: certification validates
     * every covered page ONCE, here.  Refusal leaves no state - this is
     * exactly what broken variant certify_without_page_validation.tla
     * removes, turning bogus certificates into coalesced entries that
     * disagree with the page table.                                       */
    if (validate_range(as, va, bytes, gran, &why) != 0) {
        log_refuse(va, bytes, gran, why);
        return -EINVAL;
    }
    int64_t id = -1;
    for (int64_t i = 0; i < m_capacity; i++)
        if (!m_certs[i].live) {
            id = i;
            break;
        }
    if (id < 0) {
        log_refuse(va, bytes, gran, "table_full");
        return -ENOSPC;
    }
    Cert &c = m_certs[id];
    c.live = 1;                  /* valid = TRUE                          */
    c.version++;                 /* NextRegionVersion on the reused slot  */
    c.as = as;
    c.va_base = va;
    c.bytes = bytes;
    c.gran = gran;
    log_publish(id, c);
    return id;
}

/* ---- RevokeDescriptor ---------------------------------------------------- */

int CertificateManager::revoke(int64_t id)
{
    if (!m_active || id < 0 || id >= kCertMax)
        return -EINVAL;
    if (!m_certs[id].live)
        return -ENOENT;          /* RevokeDescriptor requires old.valid   */
    revoke_slot(id, "api");
    return 0;
}

/* ---- the O(1) miss-path check -------------------------------------------- *
 * HintMatchesOSDescriptor's OS half: find a LIVE descriptor covering
 * (as, va) and report its fields+version.  Deliberately NO walk over
 * covered pages.  O(kCertMax) table scan, O(1) in covered pages.
 * Scope is exact: va outside [va_base, va_base+bytes) can never hit -
 * broken variant certificate_scope_overrun.tla is what you get when a
 * fill trusts a hint's base/size instead of the descriptor's.             */
int CertificateManager::check(const AddressSpaceView *as, uint64_t va,
                              CertStatus *out)
{
    if (!m_active || !as)
        return -EINVAL;
    for (int64_t i = 0; i < kCertMax; i++) {
        const Cert &c = m_certs[i];
        if (c.live && c.as == as && va >= c.va_base &&
            va < c.va_base + c.bytes) {
            if (out) {
                out->id = i;
                out->live = 1;
                out->version = c.version;
                out->va_base = c.va_base;
                out->bytes = c.bytes;
                out->gran = c.gran;
            }
            return 0;
        }
    }
    log_check_miss(va);
    return -ENOENT;
}

int CertificateManager::get(int64_t id, CertStatus *out) const
{
    if (!m_active || id < 0 || id >= kCertMax || !out)
        return -EINVAL;
    const Cert &c = m_certs[id];
    out->id = id;
    out->live = c.live;
    out->version = c.version;
    out->va_base = c.va_base;
    out->bytes = c.bytes;
    out->gran = c.gran;
    return 0;
}

int CertificateManager::validate(int64_t id) const
{
    if (!m_active || id < 0 || id >= kCertMax)
        return -EINVAL;
    const Cert &c = m_certs[id];
    if (!c.live)
        return -ENOENT;
    const char *why;
    return validate_range(c.as, c.va_base, c.bytes, c.gran, &why);
}

uint64_t CertificateManager::live_count() const
{
    uint64_t n = 0;
    for (int64_t i = 0; i < kCertMax; i++)
        if (m_certs[i].live)
            n++;
    return n;
}

} // namespace vtsa
