/* address_space_view.h - V-TSA port: the page-table view the certificate
 * manager validates against.
 *
 * The CertificateManager (cert_manager.h) is a faithful port of ukern/cert.c
 * from the v-tsa repository and must stay free of Sniper globals so the
 * conformance suite (test/vtsa_cert/) can drive it standalone.  Everything it
 * needs from an address space is behind this interface:
 *
 *   - identity: the AddressSpaceView pointer itself scopes certificates
 *     (the ukern code used the ukern_vspace pointer; the TLA model uses an
 *     ASID - same role).
 *   - translate(): a FUNCTIONAL page-table lookup (no timing, no stats,
 *     no fault side effects) reporting presence, frame, W/U permissions
 *     and leaf level for one 4KB-aligned virtual address.
 *
 * Adapters:
 *   - test/vtsa_cert/fake_vspace.h - conformance-suite vspace with
 *     map/unmap/protect/promote/demote ops mirroring ukern semantics.
 *   - (Phase 2/3) an adapter over ParametricDramDirectoryMSI::PageTableRadix
 *     plus the permissions overlay.  NOTE: the upstream radix PTE carries
 *     only {valid, ppn} - permissions do not exist upstream and are a V-TSA
 *     addition maintained beside the page table.
 */
#pragma once
#include <cstdint>

namespace vtsa
{

constexpr uint64_t kPageSize   = 4096;             /* UKERN_PAGE_SIZE   */
constexpr uint64_t kPageShift  = 12;
constexpr uint64_t kHugeSize   = 2ull << 20;       /* UKERN_HUGE_SIZE   */
constexpr uint64_t kHugeFrames = 512;              /* UKERN_HUGE_FRAMES */
constexpr uint64_t kVaBits     = 48;               /* UKERN_VA_BITS     */

/* W/U permission mask, ukern PTE-flag semantics. */
enum Perm : uint32_t
{
    kPermW = 1u << 0,
    kPermU = 1u << 1,
};

struct PageInfo
{
    bool     present = false;
    uint64_t frame   = 0;   /* physical frame number (4KB units)          */
    uint32_t perms   = 0;   /* Perm mask (W/U)                            */
    int      level   = 1;   /* 1 = 4KB leaf, 2 = 2MB leaf (ukern levels)  */
};

class AddressSpaceView
{
public:
    virtual ~AddressSpaceView() = default;

    /* Functional lookup of the 4KB page containing va.  Returns true and
     * fills out when the walk itself succeeds (out.present may still be
     * false for a hole); returns false only for an invalid query.  For a
     * 2MB leaf, frame reports base_frame + page_index_in_window, exactly
     * like ukern_translate. */
    virtual bool translate(uint64_t va, PageInfo &out) const = 0;
};

} // namespace vtsa
