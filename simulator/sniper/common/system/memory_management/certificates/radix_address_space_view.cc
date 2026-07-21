#include "radix_address_space_view.h"
#include "../page_tables/pagetable.h"

namespace vtsa
{

bool RadixAddressSpaceView::translate(uint64_t va, PageInfo &out) const
{
    out = PageInfo{};
    IntPtr ppn = 0;
    int page_size = 0;
    if (!m_pt->functionalLookup((IntPtr)va, &ppn, &page_size))
        return true; /* valid query, hole */
    out.present = true;
    if (page_size == 21) {
        out.level = 2;
        out.frame = (uint64_t)ppn + ((va >> kPageShift) & (kHugeFrames - 1));
    } else {
        out.level = 1;
        out.frame = (uint64_t)ppn;
    }
    auto it = m_perms.find(va >> kPageShift);
    out.perms = (it != m_perms.end()) ? it->second : (kPermW | kPermU);
    return true;
}

} // namespace vtsa
