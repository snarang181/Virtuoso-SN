/* radix_address_space_view.h - V-TSA: AddressSpaceView adapter over a real
 * Virtuoso page table (one per application).
 *
 * Translation comes from PageTable::functionalLookup (side-effect-free).
 * Permissions are a V-TSA overlay: the upstream radix PTE has no permission
 * bits, so pages default to writable+user and Phase 3's mprotect delivery
 * updates the overlay (set_perms) and fires the mutation hook.  Frame
 * normalization follows the upstream convention that PPN is always
 * 4KB-granularity: a 2MB leaf's frame for page i is ppn + i.
 */
#pragma once
#include "address_space_view.h"

#include <unordered_map>

namespace ParametricDramDirectoryMSI
{
class PageTable;
}

namespace vtsa
{

class RadixAddressSpaceView : public AddressSpaceView
{
public:
    RadixAddressSpaceView(ParametricDramDirectoryMSI::PageTable *pt,
                          int app_id)
        : m_pt(pt), m_app_id(app_id)
    {
    }

    int app_id() const { return m_app_id; }

    bool translate(uint64_t va, PageInfo &out) const override;

    /* Phase 3: mprotect delivery updates the overlay (per 4KB vpn). */
    void set_perms(uint64_t vpn, uint32_t perms) { m_perms[vpn] = perms; }
    void clear_perms(uint64_t vpn) { m_perms.erase(vpn); }

private:
    ParametricDramDirectoryMSI::PageTable *m_pt;
    int m_app_id;
    std::unordered_map<uint64_t, uint32_t> m_perms; /* vpn -> Perm mask */
};

} // namespace vtsa
