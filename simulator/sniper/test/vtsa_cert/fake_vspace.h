/* fake_vspace.h - conformance-suite address space for the V-TSA
 * CertificateManager port.
 *
 * A deliberately small but semantically faithful stand-in for the ukern
 * vspace/pager/daemon stack the original suite ran on:
 *   - first-touch demand paging (touch maps an absent page with the
 *     region's default perms; frames come from a shared bump allocator,
 *     so sequential touches get contiguous frames and interleaved touches
 *     get interleaved frames - exactly the property the 2MB-window
 *     counterexamples rely on)
 *   - protect() changes W/U perms of PRESENT pages (ukern semantics:
 *     future demand maps use the region default)
 *   - unmap() drops present pages (later touches re-map fresh frames)
 *   - daemon_tick() is the khugepaged-style promoter: a window with all
 *     512 pages present at 4KB level and uniform perms is migrated to a
 *     freshly allocated 2MB-aligned frame run and rewritten as a level-2
 *     leaf
 *   - demote() expands a level-2 leaf back to 512 sequential 4KB PTEs
 *   - EVERY mutating op (unmap, protect, promote, demote) invokes the
 *     certificate manager's on_mutation() before returning - the six-site
 *     mutation-hook discipline (COW write and fork arrive in Phase 5)
 *
 * No timing, no host memory: reads/writes are events, not loads/stores.
 */
#pragma once
#include "../../common/system/memory_management/certificates/cert_manager.h"

#include <cassert>
#include <cstdint>
#include <map>

namespace vtsa_test
{

using vtsa::AddressSpaceView;
using vtsa::CertificateManager;
using vtsa::PageInfo;
using vtsa::kHugeFrames;
using vtsa::kHugeSize;
using vtsa::kPageShift;
using vtsa::kPageSize;
using vtsa::kPermU;
using vtsa::kPermW;

/* Shared frame allocator ("pmm"): bump allocation + aligned runs. */
class FakePmm
{
public:
    uint64_t alloc_frame() { return m_next++; }

    uint64_t alloc_aligned_run(uint64_t frames)
    {
        uint64_t base = (m_next + frames - 1) / frames * frames;
        m_next = base + frames;
        return base;
    }

private:
    uint64_t m_next = 1; /* frame 0 reserved so frame!=0 when present */
};

struct DaemonPolicy
{
    int max_promotions_per_tick = 1;
};

struct DaemonStats
{
    uint64_t promotions = 0;
    uint64_t demotions = 0;
};

class FakeVspace : public AddressSpaceView
{
public:
    FakeVspace(FakePmm *pmm, CertificateManager *cm, uint64_t guest_base,
               uint64_t region_pages, uint32_t default_perms)
        : m_pmm(pmm), m_cm(cm), m_base(guest_base),
          m_region_pages(region_pages), m_default_perms(default_perms)
    {
        assert(guest_base % kHugeSize == 0);
    }

    uint64_t guest_base() const { return m_base; }
    uint64_t pva(uint64_t page) const { return m_base + page * kPageSize; }
    const DaemonStats &daemon_stats() const { return m_dstats; }

    /* ---- AddressSpaceView ------------------------------------------ */
    bool translate(uint64_t va, PageInfo &out) const override
    {
        out = PageInfo{};
        if (va < m_base || va >= m_base + m_region_pages * kPageSize)
            return true; /* valid query, hole */
        uint64_t page = (va - m_base) >> kPageShift;
        uint64_t win = page / kHugeFrames;
        auto hit = m_huge.find(win);
        if (hit != m_huge.end()) {
            out.present = true;
            out.frame = hit->second.base_frame + (page % kHugeFrames);
            out.perms = hit->second.perms;
            out.level = 2;
            return true;
        }
        auto it = m_pages.find(page);
        if (it == m_pages.end())
            return true; /* hole */
        out.present = true;
        out.frame = it->second.frame;
        out.perms = it->second.perms;
        out.level = 1;
        return true;
    }

    /* ---- demand-paged touches --------------------------------------- */
    /* Returns false for a genuine protection violation (write to RO). */
    bool touch(uint64_t page, bool is_write)
    {
        assert(page < m_region_pages);
        PageInfo pi;
        translate(pva(page), pi);
        if (!pi.present) {
            m_pages[page] = Pte{m_pmm->alloc_frame(), m_default_perms};
            pi.present = true;
            pi.perms = m_default_perms;
        }
        if (is_write && !(pi.perms & kPermW))
            return false; /* protection violation (no COW until Phase 5) */
        return true;
    }

    /* ---- mutating ops: each one notifies the cert manager ----------- */

    int unmap(uint64_t start_page, uint64_t npages)
    {
        demote_intersecting(start_page, npages);
        for (uint64_t p = start_page; p < start_page + npages; p++)
            m_pages.erase(p);
        notify(start_page, npages);
        return 0;
    }

    int protect(uint64_t start_page, uint64_t npages, uint32_t perms)
    {
        demote_intersecting(start_page, npages);
        for (uint64_t p = start_page; p < start_page + npages; p++) {
            auto it = m_pages.find(p);
            if (it != m_pages.end())
                it->second.perms = perms;
        }
        notify(start_page, npages);
        return 0;
    }

    /* khugepaged-style promotion pass. Returns number of promotions. */
    int daemon_tick(const DaemonPolicy &pol)
    {
        int done = 0;
        for (uint64_t win = 0; win < m_region_pages / kHugeFrames &&
                               done < pol.max_promotions_per_tick;
             win++) {
            if (m_huge.count(win))
                continue;
            uint32_t perms = 0;
            if (!window_fully_populated_uniform(win, &perms))
                continue;
            /* Migrate to a fresh 2MB-aligned run (compaction with real
             * frame movement, like daemon.c's order-9 runs). */
            uint64_t run = m_pmm->alloc_aligned_run(kHugeFrames);
            for (uint64_t i = 0; i < kHugeFrames; i++)
                m_pages.erase(win * kHugeFrames + i);
            m_huge[win] = Huge{run, perms};
            m_dstats.promotions++;
            done++;
            /* PTEs rewritten + frames moved => mutation. */
            notify(win * kHugeFrames, kHugeFrames);
        }
        return done;
    }

    int demote(uint64_t va)
    {
        if (va < m_base || (va - m_base) % kHugeSize != 0)
            return -1;
        uint64_t win = (va - m_base) / kHugeSize;
        auto it = m_huge.find(win);
        if (it == m_huge.end())
            return -1;
        for (uint64_t i = 0; i < kHugeFrames; i++)
            m_pages[win * kHugeFrames + i] =
                Pte{it->second.base_frame + i, it->second.perms};
        m_huge.erase(it);
        m_dstats.demotions++;
        notify(win * kHugeFrames, kHugeFrames);
        return 0;
    }

    bool has_huge_window() const { return !m_huge.empty(); }

    /* First promoted window's guest VA, or UINT64_MAX. */
    uint64_t first_huge_va() const
    {
        if (m_huge.empty())
            return UINT64_MAX;
        return m_base + m_huge.begin()->first * kHugeSize;
    }

private:
    struct Pte
    {
        uint64_t frame;
        uint32_t perms;
    };
    struct Huge
    {
        uint64_t base_frame; /* 2MB-aligned */
        uint32_t perms;
    };

    void notify(uint64_t start_page, uint64_t npages)
    {
        if (m_cm)
            m_cm->on_mutation(this, pva(start_page), npages * kPageSize);
    }

    void demote_intersecting(uint64_t start_page, uint64_t npages)
    {
        uint64_t w0 = start_page / kHugeFrames;
        uint64_t w1 = (start_page + npages - 1) / kHugeFrames;
        for (uint64_t w = w0; w <= w1; w++)
            if (m_huge.count(w))
                demote(m_base + w * kHugeSize);
    }

    bool window_fully_populated_uniform(uint64_t win, uint32_t *perms) const
    {
        uint32_t p0 = 0;
        bool have = false;
        for (uint64_t i = 0; i < kHugeFrames; i++) {
            auto it = m_pages.find(win * kHugeFrames + i);
            if (it == m_pages.end())
                return false;
            if (!have) {
                p0 = it->second.perms;
                have = true;
            } else if (it->second.perms != p0) {
                return false;
            }
        }
        *perms = p0;
        return true;
    }

    FakePmm *m_pmm;
    CertificateManager *m_cm;
    uint64_t m_base;
    uint64_t m_region_pages;
    uint32_t m_default_perms;
    std::map<uint64_t, Pte> m_pages;  /* page index -> 4KB PTE  */
    std::map<uint64_t, Huge> m_huge;  /* window index -> 2MB leaf */
    DaemonStats m_dstats;
};

} // namespace vtsa_test
