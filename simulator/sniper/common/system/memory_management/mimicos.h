#ifndef MIMICOS_H
#define MIMICOS_H

#include "../../../include/memory_management/physical_memory_allocators/physical_memory_allocator.h"
#include "application_context.h"
#include "page_fault_state.h"
#include "mimicos_message.h"
#include "memory_management/hugetlbfs.h"
#include "memory_management/policies/hugetlbfs_policy.h"
#include "memory_management/swap_cache.h"
#include "memory_management/policies/swap_cache_policy.h"
#include "subsecond_time.h"
#include "fixed_types.h"
#include "certificates/cert_manager.h"
#include "certificates/radix_address_space_view.h"
#include "certificates/mutation_listener.h"
#include "certificates/hint_flags.h"
#include "certificates/adaptive_cow_estimator.h"
#include "memory_management/page_tables/pagetable_radix.h"
#include <unordered_set>

#include <unordered_map>
#include <memory>
#include <vector>
#include <fstream>

// Backward compatibility: old code used MimicOS_NS::Message
namespace MimicOS_NS {
    using Message = MimicOSMessage;
}

// Type aliases for Sniper-space policy-based templates
using SniperHugeTLBfs  = ::HugeTLBfs<Sniper::HugeTLBfs::MetricsPolicy>;
using SniperSwapCache  = ::SwapCache<Sniper::SwapCache::MetricsPolicy>;

/**
 * @brief Per-core performance statistics for adaptive policies
 * 
 * This structure holds per-core statistics that can be used by various
 * adaptive components (e.g., MPLRU controller, prefetchers, etc.)
 * 
 * Updated by MMU on each translation, accessible globally via MimicOS.
 */
struct PerCoreStats {
    // ============ Translation Statistics ============
    SubsecondTime translation_latency;      // Cumulative translation latency
    SubsecondTime page_walk_latency;        // Cumulative page table walk latency
    UInt64 num_translations;                // Total translations performed
    UInt64 l2_tlb_misses;                   // L2 TLB misses (triggers page walks)
    UInt64 l2_tlb_hits;                     // L2 TLB hits
    
    // ============ Data Access Statistics ============
    SubsecondTime data_access_latency;      // Cumulative data access latency
    UInt64 num_data_accesses;               // Total data accesses
    UInt64 cache_hits;                      // Cache hits (L1/L2/L3)
    UInt64 cache_misses;                    // Cache misses (DRAM accesses)
    
    // ============ NUCA Cache Statistics ============
    UInt64 nuca_accesses;                   // Total NUCA accesses (reads + writes)
    UInt64 nuca_misses;                     // Total NUCA misses (read + write misses)
    UInt64 nuca_metadata_misses;            // NUCA misses for metadata (page table) blocks
    UInt64 nuca_data_misses;                // NUCA misses for data blocks
    
    // ============ Instruction Statistics ============
    UInt64 instructions_executed;           // Total instructions executed
    UInt64 cycles;                          // Total cycles
    
    // ============ Timing ============
    SubsecondTime last_update_time;         // When stats were last updated
    
    PerCoreStats() 
        : translation_latency(SubsecondTime::Zero())
        , page_walk_latency(SubsecondTime::Zero())
        , num_translations(0)
        , l2_tlb_misses(0)
        , l2_tlb_hits(0)
        , data_access_latency(SubsecondTime::Zero())
        , num_data_accesses(0)
        , cache_hits(0)
        , cache_misses(0)
        , nuca_accesses(0)
        , nuca_misses(0)
        , nuca_metadata_misses(0)
        , nuca_data_misses(0)
        , instructions_executed(0)
        , cycles(0)
        , last_update_time(SubsecondTime::Zero())
    {}
    
    // Derived metrics
    float getL2TlbMissRate() const {
        UInt64 total = l2_tlb_hits + l2_tlb_misses;
        return total > 0 ? (float)l2_tlb_misses / total : 0.0f;
    }
    
    float getL2TlbMPKI() const {
        return instructions_executed > 0 ? 
            (float)l2_tlb_misses * 1000.0f / instructions_executed : 0.0f;
    }
    
    float getTranslationShare() const {
        // Translation latency as fraction of total cycles
        if (cycles == 0) return 0.0f;
        return (float)translation_latency.getNS() / (float)cycles;
    }
    
    float getRho() const {
        // Ratio of translation stalls to data stalls
        if (data_access_latency.getNS() == 0) return 0.0f;
        return (float)translation_latency.getNS() / (float)data_access_latency.getNS();
    }
    
    float getNucaMPKI() const {
        // NUCA misses per 1000 instructions
        return instructions_executed > 0 ? 
            (float)nuca_misses * 1000.0f / instructions_executed : 0.0f;
    }
    
    float getNucaMetadataMPKI() const {
        // NUCA metadata misses per 1000 instructions
        return instructions_executed > 0 ? 
            (float)nuca_metadata_misses * 1000.0f / instructions_executed : 0.0f;
    }
    
    float getNucaDataMPKI() const {
        // NUCA data misses per 1000 instructions
        return instructions_executed > 0 ? 
            (float)nuca_data_misses * 1000.0f / instructions_executed : 0.0f;
    }
};

/**
 * @brief MimicOS - Simulated Operating System for memory management
 * 
 * MimicOS coordinates memory management simulation:
 * - Application lifecycle (page tables, VMAs)
 * - Physical memory allocation
 * - Swap space (optional)
 * - Communication with userspace MimicOS (VirtuOS)
 * 
 * Two modes of operation:
 * 1. Sniper-space: MimicOS handles page faults directly
 * 2. Userspace: MimicOS communicates with VirtuOS for page fault handling
 * 
 * This class uses modular components:
 * - ApplicationContext: per-application state (page tables, VMAs)
 * - PageFaultState: page fault tracking
 * - MimicOSMessage/Protocol: userspace communication
 */

class MimicOS
{
public:
    // ============ Construction/Destruction ============
    
    /**
     * @brief Construct MimicOS
     * 
     * @param is_guest True if this is a guest OS (for virtualization)
     */
    explicit MimicOS(bool is_guest);
    ~MimicOS();
    
    // Disable copy
    MimicOS(const MimicOS&) = delete;
    MimicOS& operator=(const MimicOS&) = delete;

    // ============ Application Management ============
    
    /**
     * @brief Create a new application context
     * 
     * @param app_id Application ID
     */
    void createApplication(int app_id);
    
    /**
     * @brief Get the application context for an app
     * 
     * @param app_id Application ID
     * @return ApplicationContext* or nullptr if not found
     */
    ApplicationContext* getApplication(int app_id);
    const ApplicationContext* getApplication(int app_id) const;

    // ============ Page Table Access (convenience methods) ============
    
    ParametricDramDirectoryMSI::PageTable* getPageTable(int app_id);
    ParametricDramDirectoryMSI::RangeTable* getRangeTable(int app_id);
    
    // ============ VMA Access (convenience methods) ============
    
    std::vector<VMA>& getVMA(int app_id);
    
    void setAllocatedVMA(int app_id, int vma_index);
    void setPhysicalOffset(int app_id, int vma_index, IntPtr offset);
    IntPtr getPhysicalOffsetSpot(int app_id, IntPtr va);
    bool incrementSuccessfulOffsetBasedAllocations(int app_id, IntPtr va);
    int getSuccessfulOffsetBasedAllocations(int app_id, IntPtr va);
    int getVMAThresholdSpot(int app_id, IntPtr va);
    
    // ============ V-TSA Certificate Manager ============
    // OS-owned certificate table (the TLA-contract implementation) plus a
    // per-application AddressSpaceView adapter over the app's page table.
    // Lazily constructed on first use so non-VTSA configs pay nothing.

    vtsa::CertificateManager* getVtsaCertManager()
    {
        if (!m_vtsa_cert_manager) {
            m_vtsa_cert_manager.reset(new vtsa::CertificateManager());
            m_vtsa_cert_manager->init(nullptr);
        }
        return m_vtsa_cert_manager.get();
    }

    vtsa::RadixAddressSpaceView* getVtsaView(int app_id)
    {
        auto it = m_vtsa_views.find(app_id);
        if (it != m_vtsa_views.end())
            return it->second.get();
        ParametricDramDirectoryMSI::PageTable *pt = getPageTable(app_id);
        if (!pt)
            return nullptr;
        auto view = std::unique_ptr<vtsa::RadixAddressSpaceView>(
            new vtsa::RadixAddressSpaceView(pt, app_id));
        auto *raw = view.get();
        m_vtsa_views[app_id] = std::move(view);
        vtsaPreloadRegions(app_id);
        return raw;
    }

    /* Region-preload sidecar (trace replays): windowed traces recorded
     * with record-trace -f fast-forward past allocation time, so the
     * REGION_REGISTER magic ops are not in the trace. If
     * $TSA_PRELOAD_REGIONS names the region file the hint runtime dumped
     * at record time ("base_hex len flags_hex site_id" per line), those
     * regions are registered here when the app's view is first created.
     * Live (non-trace) runs deliver regions via magic ops and do not set
     * the variable. */
    void vtsaPreloadRegions(int app_id)
    {
        if (m_vtsa_preloaded.count(app_id))
            return;
        m_vtsa_preloaded.insert(app_id);
        const char *path = getenv("TSA_PRELOAD_REGIONS");
        if (!path || !*path)
            return;
        FILE *f = fopen(path, "r");
        if (!f)
            return;
        unsigned long long base, len, site;
        unsigned int flags;
        int n = 0;
        while (fscanf(f, "%llx %llu %x %llu", &base, &len, &flags, &site) == 4) {
            vtsa::HintRegion r;
            r.base = base;
            r.len = len;
            r.flags = flags;
            r.site_id = site;
            vtsaRegionRegister(app_id, r);
            n++;
        }
        fclose(f);
        std::cout << "[MimicOS] V-TSA preloaded " << n
                  << " hint regions for app " << app_id << " from "
                  << path << std::endl;
    }

    // V-TSA mutation entry points.  Contract: revoke overlapping certs
    // BEFORE the operation is visible, then sweep dependent TLB/RLB state
    // on every registered MMU.  No-ops until the VTSA layer is in use.

    void vtsaRegisterSweepListener(vtsa::MutationSweepListener *l)
    {
        m_vtsa_sweep_listeners.push_back(l);
    }

    bool vtsaActive() const { return m_vtsa_cert_manager != nullptr; }

    void vtsaMutation(int app_id, IntPtr va, UInt64 bytes, bool unmap_op)
    {
        if (!vtsaActive())
            return;
        vtsa::RadixAddressSpaceView *view = getVtsaView(app_id);
        if (!view)
            return;
        vtsaNotifyEstimator(app_id, (uint64_t)va, bytes);
        m_vtsa_cert_manager->on_mutation(view, (uint64_t)va, bytes);
        for (auto *l : m_vtsa_sweep_listeners)
            l->vtsaSweep(view, (uint64_t)va, bytes, unmap_op);
    }

    // Promotion of the 2MB window containing va (PTE rewrite): a mutation.
    void vtsaPromotionEvent(int app_id, IntPtr va)
    {
        vtsaMutation(app_id, va & ~((IntPtr)vtsa::kHugeSize - 1),
                     vtsa::kHugeSize, false);
    }

    // munmap delivery (Phase 4 magic ops): drop PTEs, then revoke + sweep
    // with 4KB shootdown.
    void vtsaMunmap(int app_id, IntPtr va, UInt64 bytes)
    {
        ParametricDramDirectoryMSI::PageTable *pt = getPageTable(app_id);
        vtsa::RadixAddressSpaceView *view = getVtsaView(app_id);
        if (pt)
            for (UInt64 off = 0; off < bytes; off += vtsa::kPageSize)
                pt->deletePage(va + off);
        if (view)
            for (UInt64 off = 0; off < bytes; off += vtsa::kPageSize)
                view->clear_perms(((uint64_t)va + off) >> vtsa::kPageShift);
        vtsaMutation(app_id, va, bytes, true);
    }

    // mprotect delivery (Phase 4 magic ops): update the perms overlay,
    // then revoke + sweep (perm change is a mutation - the contract).
    void vtsaMprotect(int app_id, IntPtr va, UInt64 bytes, uint32_t perms)
    {
        vtsa::RadixAddressSpaceView *view = getVtsaView(app_id);
        if (view)
            for (UInt64 off = 0; off < bytes; off += vtsa::kPageSize)
                view->set_perms(((uint64_t)va + off) >> vtsa::kPageShift,
                                perms);
        vtsaMutation(app_id, va, bytes, false);
    }

    // V-TSA compiler-hint region registry (delivered by magic ops from
    // the traced binary's hint runtime; consumed by the hint-gated MMU
    // policy).  Registration is bookkeeping, not a mutation; UNregister
    // is munmap semantics and routes through vtsaMunmap.

    void vtsaRegionRegister(int app_id, const vtsa::HintRegion &r)
    {
        m_vtsa_hint_regions[app_id].push_back(r);
        m_vtsa_hint_registered++;
    }

    void vtsaRegionUnregister(int app_id, IntPtr base, UInt64 len)
    {
        auto it = m_vtsa_hint_regions.find(app_id);
        if (it != m_vtsa_hint_regions.end())
            for (size_t i = 0; i < it->second.size();)
                if (it->second[i].base == (uint64_t)base &&
                    it->second[i].len == len)
                    it->second.erase(it->second.begin() + i);
                else
                    i++;
        vtsaMunmap(app_id, base, len);
    }

    /* Hint lookup for va: true iff a registered region covers it. */
    bool vtsaHintFor(int app_id, uint64_t va, vtsa::HintRegion *out) const
    {
        auto it = m_vtsa_hint_regions.find(app_id);
        if (it == m_vtsa_hint_regions.end())
            return false;
        for (const auto &r : it->second)
            if (va >= r.base && va < r.base + r.len) {
                if (out)
                    *out = r;
                return true;
            }
        return false;
    }

    UInt64 vtsaHintRegisteredCount() const { return m_vtsa_hint_registered; }

    /* Revocations observed by the adaptive gate: one event per affected
     * hint region (same-clock coalescing happens inside the estimator). */
    void vtsaNotifyEstimator(int app_id, uint64_t va, uint64_t bytes)
    {
        if (!m_vtsa_estimator)
            return;
        auto it = m_vtsa_hint_regions.find(app_id);
        if (it == m_vtsa_hint_regions.end())
            return;
        for (const auto &r : it->second)
            if (va < r.base + r.len && r.base < va + bytes)
                m_vtsa_estimator->observe_revocation(r.site_id);
    }


    // ============ V-TSA emulated fork/CoW (option 5b of the port plan) ==
    // No simulated child: fork_mark snapshots the parent's registered
    // regions (RO+COW overlay + per-frame refcounts), revokes ALL
    // certificates, and sweeps with 4KB shootdown so every subsequent
    // access misses the TLB and COW writes are detectable at the miss
    // path. Child-side execution carries no V-TSA claim; parent-side
    // revocation, reach loss, and copy amplification are what get priced.

    void vtsaForkMark(int app_id)
    {
        vtsa::RadixAddressSpaceView *view = getVtsaView(app_id);
        ParametricDramDirectoryMSI::PageTable *pt = getPageTable(app_id);
        auto it = m_vtsa_hint_regions.find(app_id);
        if (!view || !pt || it == m_vtsa_hint_regions.end())
            return;
        auto &cow = m_vtsa_cow_pages[app_id];
        for (const auto &r : it->second) {
            for (uint64_t va = r.base & ~(vtsa::kPageSize - 1);
                 va < r.base + r.len; va += vtsa::kPageSize) {
                IntPtr ppn = 0;
                int psize = 0;
                if (!pt->functionalLookup((IntPtr)va, &ppn, &psize))
                    continue;
                uint64_t vpn = va >> vtsa::kPageShift;
                uint64_t frame =
                    psize == 21
                        ? (uint64_t)ppn + (vpn & (vtsa::kHugeFrames - 1))
                        : (uint64_t)ppn;
                if (cow.count(vpn)) {
                    m_vtsa_frame_refs[frame]++;
                } else {
                    cow.insert(vpn);
                    view->set_perms(vpn, vtsa::kPermU); /* drop W */
                    uint64_t &refs = m_vtsa_frame_refs[frame];
                    refs = refs ? refs + 1 : 2;
                }
                m_vtsa_cow_stats_pages_marked++;
            }
            /* revoke + sweep (with 4KB shootdown) region by region */
            vtsaMutationSweepUnmapStyle(app_id, (IntPtr)r.base, r.len);
        }
        m_vtsa_cow_stats_fork_marks++;
    }

    bool vtsaIsCow(int app_id, uint64_t va) const
    {
        auto it = m_vtsa_cow_pages.find(app_id);
        return it != m_vtsa_cow_pages.end() &&
               it->second.count(va >> vtsa::kPageShift) != 0;
    }

    /* Resolve a COW write fault: copy when shared, reuse when last owner;
     * either way the write is a mutation (revoke + sweep). Returns true
     * if a copy (frame migration) happened. */
    bool vtsaCowResolve(int app_id, IntPtr va, UInt64 core_id)
    {
        vtsa::RadixAddressSpaceView *view = getVtsaView(app_id);
        ParametricDramDirectoryMSI::PageTable *pt = getPageTable(app_id);
        auto &cow = m_vtsa_cow_pages[app_id];
        uint64_t vpn = (uint64_t)va >> vtsa::kPageShift;
        cow.erase(vpn);
        if (view)
            view->set_perms(vpn, vtsa::kPermW | vtsa::kPermU);
        bool copied = false;
        IntPtr ppn = 0;
        int psize = 0;
        if (pt && pt->functionalLookup(va & ~(IntPtr)(vtsa::kPageSize - 1),
                                       &ppn, &psize) && psize == 12) {
            uint64_t &refs = m_vtsa_frame_refs[(uint64_t)ppn];
            if (refs > 1) {
                auto alloc = m_memory_allocator->allocate(
                    4096, (UInt64)va, core_id, false, false);
                if (alloc.first != (UInt64)-1 && alloc.second == 12) {
                    pt->updatePageTableFrames(
                        va & ~(IntPtr)(vtsa::kPageSize - 1), core_id,
                        (IntPtr)alloc.first, 12, {});
                    copied = true;
                    m_vtsa_cow_stats_copies++;
                }
                refs--;
            } else {
                m_vtsa_frame_refs.erase((uint64_t)ppn);
                m_vtsa_cow_stats_reuses++;
            }
        }
        m_vtsa_cow_stats_faults++;
        vtsaMutation(app_id, va & ~(IntPtr)(vtsa::kPageSize - 1),
                     vtsa::kPageSize, false);
        return copied;
    }

    UInt64 vtsaCowStat(int which) const
    {
        switch (which) {
        case 0: return m_vtsa_cow_stats_fork_marks;
        case 1: return m_vtsa_cow_stats_pages_marked;
        case 2: return m_vtsa_cow_stats_faults;
        case 3: return m_vtsa_cow_stats_copies;
        default: return m_vtsa_cow_stats_reuses;
        }
    }

    // The adaptive gate lives OS-side (one causal view across cores).
    vtsa::AdaptiveCowEstimator* getVtsaEstimator(uint64_t walk_cycles,
                                                 uint64_t cert_cycles,
                                                 uint64_t rlb_cycles)
    {
        if (!m_vtsa_estimator)
            m_vtsa_estimator.reset(new vtsa::AdaptiveCowEstimator(
                walk_cycles, cert_cycles, rlb_cycles));
        return m_vtsa_estimator.get();
    }
    vtsa::AdaptiveCowEstimator* getVtsaEstimatorRaw()
    {
        return m_vtsa_estimator.get();
    }

    // ============ P1 real fork: address-space clone (option 5c) =========
    /* Clone the parent's populated leaf mappings + VMAs into a child
     * ApplicationContext. The child does not execute until P2 (no trace
     * stream bound), but the clone is real: leaf PTEs installed in a
     * child page table (huge mappings shattered to 4KB - the classic COW
     * clone; promotion can rebuild), both sides write-protected via the
     * per-app permission overlays, per-frame refcounts shared across
     * apps so a COW resolve on EITHER side copies-or-reuses correctly.
     * Contract obligations: parent certificates overlapping cloned
     * ranges are revoked+swept before fork returns
     * (revoke-before-complete); the child starts with an empty
     * certificate table (its view has no published certs). Returns the
     * child app id, or -1 on failure. */
    int vtsaForkApplication(int parent_app, UInt64 core_id)
    {
        ParametricDramDirectoryMSI::PageTable *ppt = getPageTable(parent_app);
        vtsa::RadixAddressSpaceView *pview = getVtsaView(parent_app);
        if (!ppt || !pview)
            return -1;
        int child_app = m_vtsa_next_fork_app++;
        createApplication(child_app);
        ParametricDramDirectoryMSI::PageTable *cpt = getPageTable(child_app);
        if (!cpt)
            return -1;
        vtsa::RadixAddressSpaceView *cview = getVtsaView(child_app);
        auto &pcow = m_vtsa_cow_pages[parent_app];
        auto &ccow = m_vtsa_cow_pages[child_app];
        /* Enumerate the parent's REAL populated mappings by walking its
         * radix page table (VMA sidecars are absent for live runs and
         * most traces - the page table is the ground truth). */
        auto *pradix =
            dynamic_cast<ParametricDramDirectoryMSI::PageTableRadix *>(ppt);
        if (!pradix)
            return -1;
        std::vector<std::pair<IntPtr, IntPtr>> leaves; /* {va, frame} 4KB */
        pradix->enumerateMappings([&](IntPtr va, IntPtr ppn, int bits) {
            if (bits == 12) {
                leaves.emplace_back(va, ppn);
            } else { /* 2MB leaf: shatter to 4KB frames (classic COW clone) */
                for (uint64_t j = 0; j < vtsa::kHugeFrames; j++)
                    leaves.emplace_back(va + (IntPtr)(j * vtsa::kPageSize),
                                        ppn + (IntPtr)j);
            }
        });
        uint64_t cloned = 0;
        IntPtr lo = 0, hi = 0;
        /* The radix insert consumes pre-allocated page-table frames for
         * new intermediate levels (up to levels-1 per insert); keep a
         * small pool topped up and drop only what each insert consumed. */
        std::vector<UInt64> ptframes;
        for (const auto &m : leaves) {
            IntPtr va = m.first;
            uint64_t frame = (uint64_t)m.second;
            uint64_t vpn = (uint64_t)va >> vtsa::kPageShift;
            while (ptframes.size() < 3)
                ptframes.push_back(
                    m_memory_allocator->handle_page_table_allocations(4096));
            int used = cpt->updatePageTableFrames(va, core_id, (IntPtr)frame,
                                                  12, ptframes);
            if (used > 0)
                ptframes.erase(ptframes.begin(), ptframes.begin() + used);
            if (!pcow.count(vpn)) {
                pcow.insert(vpn);
                pview->set_perms(vpn, vtsa::kPermU); /* drop W */
            }
            ccow.insert(vpn);
            if (cview)
                cview->set_perms(vpn, vtsa::kPermU);
            uint64_t &refs = m_vtsa_frame_refs[frame];
            refs = refs ? refs + 1 : 2;
            cloned++;
        }
        /* revoke-before-complete on the parent, 4KB shootdown style. Sweep
         * per CONTIGUOUS cloned run (the enumeration is VA-ordered), never
         * the whole span - a live address space stretches from the binary
         * to the stack and the shootdown loops are per-page. */
        (void)lo; (void)hi;
        size_t ri = 0;
        while (ri < leaves.size()) {
            IntPtr run_base = leaves[ri].first;
            IntPtr run_end = run_base + (IntPtr)vtsa::kPageSize;
            ri++;
            while (ri < leaves.size() && leaves[ri].first == run_end) {
                run_end += (IntPtr)vtsa::kPageSize;
                ri++;
            }
            vtsaMutationSweepUnmapStyle(parent_app, run_base,
                                        (UInt64)(run_end - run_base));
        }
        /* Child inherits the parent's hint regions (same VAs, same flags);
         * certificates are NOT inherited - the child re-certifies. */
        auto hit = m_vtsa_hint_regions.find(parent_app);
        if (hit != m_vtsa_hint_regions.end())
            m_vtsa_hint_regions[child_app] = hit->second;
        m_vtsa_fork_real_forks++;
        m_vtsa_fork_real_pages += cloned;
        return child_app;
    }

    /* Warm-start replay: install PTEs for every VPN listed in
     * $VTSA_PREWARM_PAGES (one decimal VPN per line) through the normal
     * allocator, at application creation. Models a long-running process
     * whose footprint faulted in before the measurement window - the
     * discriminating experiment for population-churn vs genuine-limit
     * on server workloads. Scheme-neutral: allocation follows the
     * scheme's own policy (instant-promote THP gets 2MB frames here,
     * exactly as its first-touch reservation would). */
    void vtsaPrewarmPages(int app_id)
    {
        const char *path = getenv("VTSA_PREWARM_PAGES");
        if (!path)
            return;
        ParametricDramDirectoryMSI::PageTable *pt = getPageTable(app_id);
        if (!pt)
            return;
        FILE *f = fopen(path, "r");
        if (!f)
            return;
        std::vector<UInt64> ptframes;
        unsigned long long vpn;
        uint64_t warmed = 0, skipped = 0;
        while (fscanf(f, "%llu", &vpn) == 1) {
            IntPtr va = (IntPtr)vpn << 12;
            IntPtr have_ppn = 0;
            int have_ps = 0;
            if (pt->functionalLookup(va, &have_ppn, &have_ps)) {
                skipped++; /* covered by an earlier 2MB install */
                continue;
            }
            auto alloc = m_memory_allocator->allocate(4096, (UInt64)va, 0,
                                                      false, false);
            if (alloc.first == (UInt64)-1)
                continue;
            while (ptframes.size() < 3)
                ptframes.push_back(
                    m_memory_allocator->handle_page_table_allocations(4096));
            int used = pt->updatePageTableFrames(
                alloc.second == 21 ? (va & ~((IntPtr)(1 << 21) - 1)) : va, 0,
                (IntPtr)alloc.first, alloc.second, ptframes);
            if (used > 0)
                ptframes.erase(ptframes.begin(), ptframes.begin() + used);
            warmed++;
        }
        fclose(f);
        m_log << "[MimicOS] V-TSA prewarmed " << warmed
              << " pages (skipped " << skipped << ") for app " << app_id
              << " from " << path << std::endl;
    }

    UInt64 vtsaForkRealStat(int which) const
    {
        switch (which) {
        case 0: return m_vtsa_fork_real_forks;
        case 1: return m_vtsa_fork_real_pages;
        default: return m_vtsa_fork_real_skipped_vmas;
        }
    }
    /* Stable pointers for registerStatsMetric (registered by core 0's
     * vtsa MMU so the counters land in sim.stats exactly once). */
    UInt64* vtsaForkRealForksPtr() { return &m_vtsa_fork_real_forks; }
    UInt64* vtsaForkRealPagesPtr() { return &m_vtsa_fork_real_pages; }
    UInt64* vtsaForkRealSkippedPtr() { return &m_vtsa_fork_real_skipped_vmas; }

    /* Like vtsaMutation but sweeps 4KB entries too (fork/unmap style). */
    void vtsaMutationSweepUnmapStyle(int app_id, IntPtr va, UInt64 bytes)
    {
        if (!vtsaActive())
            return;
        vtsa::RadixAddressSpaceView *view = getVtsaView(app_id);
        if (!view)
            return;
        vtsaNotifyEstimator(app_id, (uint64_t)va, bytes);
        m_vtsa_cert_manager->on_mutation(view, (uint64_t)va, bytes);
        for (auto *l : m_vtsa_sweep_listeners)
            l->vtsaSweep(view, (uint64_t)va, bytes, true);
    }

    // ============ Memory Allocator ============

    PhysicalMemoryAllocator* getMemoryAllocator() { return m_memory_allocator.get(); }

    /**
     * @brief Get the NUMA node ID for a given physical page number.
     *
     * Delegates to the underlying physical memory allocator. NUMA-aware
     * allocators (e.g., NumaReservationTHPAllocator) return the actual node;
     * non-NUMA allocators return 0 (single implicit node).
     *
     * @param ppn Physical page number (4KB granularity)
     * @return NUMA node ID (0-based)
     */
    UInt32 getNumaNodeForPPN(UInt64 ppn) const
    {
        if (m_memory_allocator)
            return m_memory_allocator->getNumaNodeForPPN(ppn);
        return 0;
    }
    
    // ============ Swap Management ============
    
    bool isSwapEnabled() const { return m_swap_cache != nullptr; }
    SniperSwapCache* getSwapCache() { return m_swap_cache.get(); }
    bool swapOutPage(IntPtr vpn, int app_id);
    void deletePageTableEntry(IntPtr vpn, int app_id);
    
    void setLastPageFaultCausedSwapping(bool caused_swapping) {
        m_last_pf_caused_swapping = caused_swapping;
    }
    
    // ============ HugeTLBfs Management ============
    
    /**
     * @brief Check if HugeTLBfs service is enabled
     * @return true if hugetlbfs is enabled and initialized
     */
    bool isHugeTLBfsEnabled() const { return m_hugetlbfs != nullptr && m_hugetlbfs->isEnabled(); }
    
    /**
     * @brief Get the HugeTLBfs service
     * @return Pointer to HugeTLBfs service, or nullptr if disabled
     */
    SniperHugeTLBfs* getHugeTLBfs() { return m_hugetlbfs.get(); }
    const SniperHugeTLBfs* getHugeTLBfs() const { return m_hugetlbfs.get(); }
    
    /**
     * @brief Allocate a huge page for an application
     * 
     * Convenience method that delegates to HugeTLBfs service.
     * 
     * @param app_id    Application requesting the page
     * @param vaddr     Virtual address to be mapped
     * @param size_2mb  True for 2MB page, false for 1GB page
     * @return Base physical page number, or -1 if allocation fails
     */
    IntPtr allocateHugePage(int app_id, IntPtr vaddr, bool size_2mb = true);
    
    /**
     * @brief Deallocate a huge page
     * 
     * @param base_ppn  Base physical page number
     * @param size_2mb  True for 2MB page, false for 1GB page
     * @return true if deallocation succeeded
     */
    bool deallocateHugePage(IntPtr base_ppn, bool size_2mb = true);
    
    // ============ Page Fault State (per-core) ============
    
    /**
     * @brief Initialize per-core page fault state vectors
     * @param num_cores Number of cores in the system
     */
    void initPerCorePageFaultState(UInt32 num_cores);
    
    PageFaultState& getPageFaultState(core_id_t core_id) {
        assert(core_id >= 0 && (size_t)core_id < m_pf_states.size());
        return m_pf_states[core_id];
    }
    const PageFaultState& getPageFaultState(core_id_t core_id) const {
        assert(core_id >= 0 && (size_t)core_id < m_pf_states.size());
        return m_pf_states[core_id];
    }
    void resetPageFaultState(core_id_t core_id) {
        assert(core_id >= 0 && (size_t)core_id < m_pf_states.size());
        m_pf_states[core_id].reset();
    }
    
    // Per-core page fault API
    bool getIsPageFault(core_id_t core_id) const {
        assert(core_id >= 0 && (size_t)core_id < m_pf_states.size());
        return m_pf_states[core_id].isActive();
    }
    void setIsPageFault(core_id_t core_id, bool is_pf) {
        assert(core_id >= 0 && (size_t)core_id < m_pf_states.size());
        if (!is_pf) m_pf_states[core_id].reset();
        else m_pf_states[core_id].is_active = true;
    }
    IntPtr getVaTriggeredPageFault(core_id_t core_id) const {
        assert(core_id >= 0 && (size_t)core_id < m_pf_states.size());
        return m_pf_states[core_id].getFaultingVA();
    }
    void setVaTriggeredPageFault(core_id_t core_id, IntPtr va) {
        assert(core_id >= 0 && (size_t)core_id < m_pf_states.size());
        m_pf_states[core_id].faulting_va = va;
    }
    void setNumRequestedFrames(core_id_t core_id, int num_frames) {
        assert(core_id >= 0 && (size_t)core_id < m_pf_states.size());
        m_pf_states[core_id].num_requested_frames = num_frames;
    }
    int getNumRequestedFrames(core_id_t core_id) const {
        assert(core_id >= 0 && (size_t)core_id < m_pf_states.size());
        return m_pf_states[core_id].getNumRequestedFrames();
    }
    
    // ============ Userspace Communication ============
    
    bool isUserspaceMimicosEnabled() const { return m_userspace_enabled; }
    
    MimicOSMessage* getMessage() { return &m_message; }
    
    template <typename... Args>
    void buildMessageWithArgs(const std::string& message_type, Args&&... args) {
        MimicOSProtocol::buildMessage(m_message, message_type, std::forward<Args>(args)...);
    }
    
    // ============ Configuration ============
    
    String getName() const { return m_name; }
    SubsecondTime getPageFaultLatency() const { return m_page_fault_latency.getLatency(); }
    
    int getNumberOfPageSizes() const { return static_cast<int>(m_page_sizes.size()); }
    int* getPageSizeList() { return m_page_sizes.data(); }
    const std::vector<int>& getPageSizes() const { return m_page_sizes; }
    
    String getPageTableType() const { return m_page_table_type; }
    String getPageTableName() const { return m_page_table_name; }
    void setPageTableType(const String& type) { m_page_table_type = type; }
    void setPageTableName(const String& name) { m_page_table_name = name; }
    
    String getRangeTableType() const { return m_range_table_type; }
    String getRangeTableName() const { return m_range_table_name; }
    void setRangeTableType(const String& type) { m_range_table_type = type; }
    void setRangeTableName(const String& name) { m_range_table_name = name; }
    
    UInt64 getAccessesPerVPN(IntPtr vpn, int app_id);
    
    // ============ Protocol Codes (static, for external access) ============
    
    static std::unordered_map<std::string, uint64_t> protocol_codes_encode;
    static std::unordered_map<uint64_t, std::string> protocol_codes_decode;
    
    // ============ Per-Core Statistics ============
    
    /**
     * @brief Initialize per-core stats for a given number of cores
     * @param num_cores Number of cores in the system
     */
    void initPerCoreStats(UInt32 num_cores);
    
    /**
     * @brief Get per-core statistics (read-only)
     * @param core_id Core ID
     * @return Reference to per-core stats, or empty stats if invalid
     */
    const PerCoreStats& getPerCoreStats(core_id_t core_id) const;
    
    /**
     * @brief Get per-core statistics (mutable, for updates)
     * @param core_id Core ID
     * @return Pointer to per-core stats, or nullptr if invalid
     */
    PerCoreStats* getPerCoreStatsMutable(core_id_t core_id);
    
    /**
     * @brief Update translation statistics for a core
     * 
     * Called by MMU after each translation to update stats.
     * 
     * @param core_id       Core ID
     * @param tr_latency    Translation latency for this access
     * @param is_l2_miss    True if L2 TLB missed (triggered page walk)
     * @param walk_latency  Page walk latency (if applicable)
     */
    void updateTranslationStats(core_id_t core_id, 
                                SubsecondTime tr_latency,
                                bool is_l2_miss,
                                SubsecondTime walk_latency = SubsecondTime::Zero());
    
    /**
     * @brief Update instruction count for a core
     * @param core_id       Core ID
     * @param instructions  Number of instructions executed
     * @param cycles        Number of cycles elapsed
     */
    void updateInstructionStats(core_id_t core_id, UInt64 instructions, UInt64 cycles);
    
    /**
     * @brief Update data access statistics for a core
     * @param core_id       Core ID
     * @param latency       Data access latency
     * @param is_cache_hit  True if hit in cache (L1/L2/L3)
     */
    void updateDataAccessStats(core_id_t core_id, SubsecondTime latency, bool is_cache_hit);
    
    /**
     * @brief Check if per-core stats are initialized
     */
    bool isPerCoreStatsInitialized() const { return !m_per_core_stats.empty(); }
    
    // ============ Deprecated ============
    
    /**
     * @deprecated Use exception handlers instead
     */
    void handle_page_fault(IntPtr address, IntPtr core_id, int frames);

private:
    // ============ Identity ============
    String m_name;
    bool m_is_guest;
    bool m_userspace_enabled;
    
    // ============ Subsystems ============
    std::unique_ptr<PhysicalMemoryAllocator> m_memory_allocator;
    std::unique_ptr<SniperSwapCache> m_swap_cache;
    std::unique_ptr<SniperHugeTLBfs> m_hugetlbfs;
    
    // ============ Per-Application State ============
    std::unordered_map<int, std::unique_ptr<ApplicationContext>> m_applications;

    // ============ V-TSA State ============
    std::unique_ptr<vtsa::CertificateManager> m_vtsa_cert_manager;
    std::unordered_map<int, std::unique_ptr<vtsa::RadixAddressSpaceView>> m_vtsa_views;
    std::vector<vtsa::MutationSweepListener*> m_vtsa_sweep_listeners;
    std::unordered_map<int, std::vector<vtsa::HintRegion>> m_vtsa_hint_regions;
    UInt64 m_vtsa_hint_registered = 0;
    std::unordered_set<int> m_vtsa_preloaded;
    std::unordered_map<int, std::unordered_set<uint64_t>> m_vtsa_cow_pages;
    std::unordered_map<uint64_t, uint64_t> m_vtsa_frame_refs;
    std::unique_ptr<vtsa::AdaptiveCowEstimator> m_vtsa_estimator;
    UInt64 m_vtsa_cow_stats_fork_marks = 0;
    UInt64 m_vtsa_cow_stats_pages_marked = 0;
    UInt64 m_vtsa_cow_stats_faults = 0;
    UInt64 m_vtsa_cow_stats_copies = 0;
    UInt64 m_vtsa_cow_stats_reuses = 0;
    // P1 real fork (option 5c): child app ids allocated from 1000 so they
    // never collide with trace-stream app ids.
    int m_vtsa_next_fork_app = 1000;
    UInt64 m_vtsa_fork_real_forks = 0;
    UInt64 m_vtsa_fork_real_pages = 0;
    UInt64 m_vtsa_fork_real_skipped_vmas = 0;
    
    // ============ Page Fault State (per-core) ============
    std::vector<PageFaultState> m_pf_states;
    MimicOSMessage m_message;
    bool m_last_pf_caused_swapping;
    
    // ============ Configuration ============
    String m_page_table_type;
    String m_page_table_name;
    String m_range_table_type;
    String m_range_table_name;
    std::vector<int> m_page_sizes;
    ComponentLatency m_page_fault_latency;
    double m_target_fragmentation;
    
    // ============ Per-Core Statistics ============
    std::vector<PerCoreStats> m_per_core_stats;
    static PerCoreStats s_empty_stats;  // Returned for invalid core_id
    
    // ============ Logging ============
    std::string m_log_file_name;
    std::ofstream m_log;
};

#endif // MIMICOS_H
