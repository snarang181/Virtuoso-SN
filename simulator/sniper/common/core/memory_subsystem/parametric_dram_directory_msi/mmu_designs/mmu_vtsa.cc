// ============================================================================
// @kanellok: MMU Implementation - Memory Management Unit for Sniper Simulator
// ============================================================================
//
// This file implements the Memory Management Unit (MMU) for the Sniper
// multi-core simulator. The MMU is responsible for:
//
//   1. Virtual-to-Physical Address Translation
//      - TLB hierarchy lookup (L1 iTLB, L1 dTLB, L2 TLB, etc.)
//      - Page table walks on TLB miss
//      - Page fault handling (sniper-space or userspace mode)
//
//   2. Translation Timing Modelm
//      - TLB hit/miss latency calculation
//      - Page table walk latency (including cache effects)
//      - Page fault latency modeling
//
//   3. Statistics Collection
//      - Translation counts, TLB hit rates
//      - Per-page and per-region metrics
//      - Reuse distance analysis
//
// Architecture Overview:
// ~~~~~~~~~~~~~~~~~~~~~~
//   +--------+     +-------------+     +------------+
//   |  Core  | --> |     MMU     | --> |   Memory   |
//   +--------+     +-------------+     +------------+
//                        |
//          +-------------+-------------+
//          |             |             |
//     +----v----+   +----v----+   +----v----+
//     |  TLB    |   |   PTW   |   | MimicOS |
//     | Subsys  |   |  Walker |   |  (OS)   |
//     +---------+   +---------+   +---------+
//
// Key Design Decisions:
// ~~~~~~~~~~~~~~~~~~~~~
// - Uses const references for TLBSubsystem to avoid vector copying
// - Bit shifts instead of pow() for power-of-2 calculations
// - Bitwise AND instead of modulo for offset extraction
// - Supports both sniper-space (fast) and userspace (accurate) page fault handling
//
// ============================================================================

// === Core MMU Headers ===
#include "mmu_vtsa.h"
#include <cerrno>
#include "mmu_base.h"
#include "memory_manager.h"
#include "cache_cntlr.h"

// === Page Table & TLB ===
#include "pagetable_factory.h"
#include "pagetable_radix.h"
#include "metadata_factory.h"
#include "filter_factory.h"

// === OS & Exception Handling ===
#include "mimicos.h"
#include "misc/exception_handler_base.h"
#include "sniper_space_exception_handler.h"

// === MPLRU Controller (for adaptive NUCA cache replacement) ===
#include "mplru_controller_impl.h"

// === Sniper Core ===
#include "subsecond_time.h"
#include "fixed_types.h"
#include "instruction.h"
#include "core.h"
#include "thread.h"

// === Standard Library ===
#include <iostream>
#include <fstream>
#include <algorithm>
#include <vector>

// === Debug Configuration ===
#include "debug_config.h"

// ============================================================================
// Compile-Time Configuration
// ============================================================================

// Enable detailed per-translation event logging (WARNING: very large output files!)
// Only enable for debugging specific translation behavior
// #define ENABLE_TRANSLATION_EVENTS_LOG

using namespace std;

namespace ParametricDramDirectoryMSI
{

// ============================================================================
// Construction / Destruction
// ============================================================================

    /**
     * @brief Construct a new Memory Management Unit
     * 
     * Initializes the MMU for a specific core, setting up:
     * - Debug log files (if enabled)
     * - Page table walker with MSHRs for parallel walks
     * - TLB hierarchy (L1i, L1d, L2, etc.)
     * - Statistics counters
     * 
     * @param _core           Pointer to the core this MMU belongs to
     * @param _memory_manager Pointer to the memory manager for cache access
     * @param _shmem_perf_model Performance model for timing simulation
     * @param _name           Configuration name prefix (e.g., "mmu")
     * @param _nested_mmu     Optional nested MMU for virtualization (can be NULL)
     */
    MemoryManagementUnitVTSA::MemoryManagementUnitVTSA(Core *_core, MemoryManagerBase *_memory_manager, ShmemPerfModel *_shmem_perf_model, String _name, MemoryManagementUnitBase *_nested_mmu)
    : MemoryManagementUnitBase(_core, _memory_manager, _shmem_perf_model, _name, _nested_mmu), memory_manager(_memory_manager)
    {
        std::cout << std::endl;
        std::cout << "[MMU] Initializing MMU for core " << core->getId() << std::endl;
        
        // Initialize centralized logging
        mmu_log = new SimLog("MMU", core->getId(), DEBUG_MMU);
        mmu_log->log("Initializing MMU for core " + std::to_string(core->getId()));

        // Initialize CSV logs for detailed per-page analysis
#if ENABLE_MMU_CSV_LOGS
        initializePerPageLogs();
#endif

        // Initialize MMU components in order
        instantiatePageTableWalker();  // Creates PTW filter and MSHR entries
        instantiateTLBSubsystem();     // Creates TLB hierarchy from config
        registerMMUStats();            // Registers statistics with Sniper

		// ---- V-TSA layer init ----
		{
			String vtsa_mode = Sim()->getCfg()->getString("perf_model/" + name + "/vtsa/mode");
			if (vtsa_mode == "hardware_k") m_vtsa_mode = VTSA_MODE_HARDWARE_K;
			else if (vtsa_mode == "off") m_vtsa_mode = VTSA_MODE_OFF;
			else if (vtsa_mode == "certified") m_vtsa_mode = VTSA_MODE_CERTIFIED;
			else if (vtsa_mode == "adaptive") m_vtsa_mode = VTSA_MODE_ADAPTIVE;
			else m_vtsa_mode = VTSA_MODE_AUTO_CERTIFY;
			m_vtsa_k_budget = Sim()->getCfg()->getInt("perf_model/" + name + "/vtsa/k_budget");
			m_vtsa_miss_threshold = Sim()->getCfg()->getInt("perf_model/" + name + "/vtsa/miss_threshold");
			m_vtsa_upgrade_interval = Sim()->getCfg()->getInt("perf_model/" + name + "/vtsa/upgrade_probe_interval");
			m_vtsa_max_gran_bits = Sim()->getCfg()->getInt("perf_model/" + name + "/vtsa/max_gran_bits");
			UInt64 rlb_entries = Sim()->getCfg()->getInt("perf_model/" + name + "/vtsa/rlb_entries");
			m_vtsa_rlb = new vtsa::CertRLB(rlb_entries);
			m_vtsa_cert_check_latency = new ComponentLatency(core->getDvfsDomain(), Sim()->getCfg()->getInt("perf_model/" + name + "/vtsa/cert_check_cycles"));
			m_vtsa_rlb_miss_latency = new ComponentLatency(core->getDvfsDomain(), Sim()->getCfg()->getInt("perf_model/" + name + "/vtsa/rlb_miss_cycles"));
			m_vtsa_pte_probe_latency = new ComponentLatency(core->getDvfsDomain(), Sim()->getCfg()->getInt("perf_model/" + name + "/vtsa/pte_probe_cycles"));
			m_vtsa_metadata_latency = new ComponentLatency(core->getDvfsDomain(), Sim()->getCfg()->getInt("perf_model/" + name + "/vtsa/metadata_lookup_cycles"));
			m_vtsa_cow_fault_latency = new ComponentLatency(core->getDvfsDomain(), Sim()->getCfg()->getInt("perf_model/" + name + "/vtsa/cow_fault_cycles"));
			m_vtsa_cow_copy_latency = new ComponentLatency(core->getDvfsDomain(), Sim()->getCfg()->getInt("perf_model/" + name + "/vtsa/cow_copy_cycles"));
			memset(&vtsa_stats, 0, sizeof(vtsa_stats));
			registerVTSAStats();
			if (m_vtsa_mode != VTSA_MODE_OFF)
				Sim()->getMimicOS()->vtsaRegisterSweepListener(this);
			if (m_vtsa_mode == VTSA_MODE_ADAPTIVE)
				Sim()->getMimicOS()->getVtsaEstimator(
					Sim()->getCfg()->getInt("perf_model/" + name + "/vtsa/estimator_walk_cycles"),
					Sim()->getCfg()->getInt("perf_model/" + name + "/vtsa/cert_check_cycles"),
					Sim()->getCfg()->getInt("perf_model/" + name + "/vtsa/rlb_miss_cycles"));
		}
        std::cout << std::endl;
    }

    /**
     * @brief Destroy the Memory Management Unit
     * 
     * Cleans up all allocated resources:
     * - Dumps any pending CSV logs
     * - Closes log files
     * - Frees TLB hierarchy and page table walkers
     */
    MemoryManagementUnitVTSA::~MemoryManagementUnitVTSA()
    {
        std::cout << "[MMU] Destroying MMU for core " << core->getId() << std::endl;

        // Print sanity check summary
        if (sanity_checks_enabled)
        {
            std::cout << "[MMU Sanity] Core " << core->getId() 
                      << " checked " << va_to_pa_map.size() << " unique VA->PA mappings, "
                      << pa_to_va_map.size() << " unique PA->VA mappings, "
                      << sanity_check_violations << " violations detected" << std::endl;
        }

#if ENABLE_MMU_CSV_LOGS
        dumpPerPageLogs();
        translation_latency_log.close();
#ifdef ENABLE_TRANSLATION_EVENTS_LOG
        translation_events_log.close();
#endif
        reuse_distance_log.close();
        ptw_per_page_log.close();
        use_after_eviction_log.close();
#endif
        delete mmu_log;
        delete tlb_subsystem;
        delete pt_walkers;
        delete[] translation_stats.tlb_latency_per_level;
        delete[] translation_stats.tlb_hit_page_sizes;
    }

// ============================================================================
// Initialization Methods
// ============================================================================
    
    /**
     * @brief Instantiate metadata table for ARM-style tagged memory support.
     * 
     * This creates a metadata table that can be used for memory tagging
     * extensions (MTE) or similar features. The metadata table stores
     * per-cache-line tags for memory safety features.
     * 
     * @note Currently unused but available for future ARM MTE extensions.
     */
    void MemoryManagementUnitVTSA::instantiateMetadataTable()
    {
        String metadata_table_name = Sim()->getCfg()->getString("perf_model/"+name+"/metadata_table_name");
        metadata_table = MetadataFactory::createMetadataTable(metadata_table_name, core, shmem_perf_model, this, memory_manager);
    }

    /**
     * @brief Initialize the Page Table Walker (PTW) subsystem.
     * 
     * Creates two key components:
     * 
     * 1. PTW Filter: Page Walk Caches or hardware units that can filter memory accesses  for intermediate page-table entries.
     * 
     * 2. PTW MSHRs: Miss Status Holding Registers for parallel walks.
     *    - Number configured via "page_table_walkers" setting
     *    - Allows multiple concurrent page table walks (typical: 2-4)
     *    - Queues walks when all walkers are busy
     */
    void MemoryManagementUnitVTSA::instantiatePageTableWalker()
    {
        // Create PTW filter (for speculative engines, etc.)
        String filter_type = Sim()->getCfg()->getString("perf_model/" + name + "/ptw_filter_type");
        ptw_filter = FilterPTWFactory::createFilterPTWBase(filter_type, name, core);

        // Create MSHRs for parallel page table walks
        // Modern CPUs support 2-4 concurrent page table walks
        int num_walkers = Sim()->getCfg()->getInt("perf_model/" + name + "/page_table_walkers");
        pt_walkers = new MSHR(num_walkers);
    }

    /**
     * @brief Initialize the TLB hierarchy and page size prediction.
     * 
     * TLB Hierarchy Structure (typical configuration):
     * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     *   Level 0: L1 iTLB (Only 4KB) + L1 dTLB (64 entries, 4KB) + L1 dTLB (32 entries, 2MB)
     *   Level 1: L2 TLB (Unified, 4K + 2M pages)
     *   Level 2: [Optional] L3 TLB in POM-TLB or prefetch buffer
     * 
     * Page Size Prediction (PSP):
     * ~~~~~~~~~~~~~~~~~~~~~~~~~~~
     * For L2 TLB hits, PSP predicts whether the page is 4KB or 2MB.
     * - Correct prediction: Lower latency (parallel L2 4KB and 2MB lookups)
     * - Misprediction: Higher latency (serial lookup required)
     * 
     */
    void MemoryManagementUnitVTSA::instantiateTLBSubsystem()
    {
        tlb_subsystem = new TLBHierarchy(name, core, memory_manager, shmem_perf_model);

        // Page Size Prediction configuration
        page_size_prediction_enabled = Sim()->getCfg()->getBool("perf_model/" + name + "/page_size_prediction_enabled");
        l2_tlb_correct_prediction_latency = ComponentLatency(
            core->getDvfsDomain(), 
            Sim()->getCfg()->getInt("perf_model/" + name + "/correct_prediction_latency")
        ).getLatency();
        l2_tlb_misprediction_latency = ComponentLatency(
            core->getDvfsDomain(), 
            Sim()->getCfg()->getInt("perf_model/" + name + "/misprediction_latency")
        ).getLatency();
    }

// ============================================================================
// Statistics Registration
// ============================================================================
    
    /**
     * @brief Register all MMU statistics with Sniper's statistics framework.
     * 
     * Statistics Categories:
     * ~~~~~~~~~~~~~~~~~~~~~~
     * 1. Translation Counts:
     *    - num_translations: Total address translations performed
     *    - page_table_walks: Number of PTW operations (TLB misses)
     *    - page_faults: Pages not present in memory
     * 
     * 2. Latency Breakdown:
     *    - total_tlb_latency: Cumulative TLB lookup time
     *    - total_table_walk_latency: Cumulative PTW time
     *    - total_translation_latency: End-to-end translation time
     *    - total_fault_latency: Time spent handling page faults
     *    - tlb_latency_N: Per-level TLB latency breakdown
     * 
     * 3. Page Size Prediction:
     *    - page_size_prediction_hits: Correct 4KB/2MB predictions
     *    - page_size_prediction_misses: Incorrect predictions
     * 
     * 4. Walker Activity:
     *    - walker_is_active: Cycles with active page table walks
     * 
     * These statistics map to hardware performance counters found in
     * modern CPUs (e.g., Intel's DTLB_LOAD_MISSES.WALK_CYCLES).
     */
    void MemoryManagementUnitVTSA::registerMMUStats()
    {
        bzero(&translation_stats, sizeof(translation_stats));

        // Initialize sanity check state
        try { sanity_checks_enabled = Sim()->getCfg()->getBool("perf_model/mmu/sanity_checks_enabled"); } 
        catch (...) { sanity_checks_enabled = false; }
        sanity_check_violations = 0;

        registerStatsMetric(name, core->getId(), "sanity_check_violations", &sanity_check_violations);

        // Core translation statistics
        registerStatsMetric(name, core->getId(), "num_translations", &translation_stats.num_translations);
        registerStatsMetric(name, core->getId(), "page_faults", &translation_stats.page_faults);
        registerStatsMetric(name, core->getId(), "page_table_walks", &translation_stats.page_table_walks);
        
        // Latency statistics
        registerStatsMetric(name, core->getId(), "total_table_walk_latency", &translation_stats.total_walk_latency);
        registerStatsMetric(name, core->getId(), "total_tlb_latency", &translation_stats.total_tlb_latency);
        registerStatsMetric(name, core->getId(), "total_translation_latency", &translation_stats.total_translation_latency);
        registerStatsMetric(name, core->getId(), "total_fault_latency", &translation_stats.total_fault_latency);

        // Page size prediction statistics
        registerStatsMetric(name, core->getId(), "page_size_prediction_hits", &translation_stats.page_size_prediction_hits);
        registerStatsMetric(name, core->getId(), "page_size_prediction_misses", &translation_stats.page_size_prediction_misses);

        // Walker activity (comparable to hardware perf counters)
        registerStatsMetric(name, core->getId(), "walker_is_active", &translation_stats.walker_is_active);

        // Instruction vs Data breakdown statistics
        registerStatsMetric(name, core->getId(), "num_translations_instruction", &translation_stats.num_translations_instruction);
        registerStatsMetric(name, core->getId(), "num_translations_data", &translation_stats.num_translations_data);
        registerStatsMetric(name, core->getId(), "page_faults_instruction", &translation_stats.page_faults_instruction);
        registerStatsMetric(name, core->getId(), "page_faults_data", &translation_stats.page_faults_data);
        registerStatsMetric(name, core->getId(), "page_table_walks_instruction", &translation_stats.page_table_walks_instruction);
        registerStatsMetric(name, core->getId(), "page_table_walks_data", &translation_stats.page_table_walks_data);
        registerStatsMetric(name, core->getId(), "tlb_misses_instruction", &translation_stats.tlb_misses_instruction);
        registerStatsMetric(name, core->getId(), "tlb_misses_data", &translation_stats.tlb_misses_data);
        registerStatsMetric(name, core->getId(), "tlb_hits_instruction", &translation_stats.tlb_hits_instruction);
        registerStatsMetric(name, core->getId(), "tlb_hits_data", &translation_stats.tlb_hits_data);
        registerStatsMetric(name, core->getId(), "total_walk_latency_instruction", &translation_stats.total_walk_latency_instruction);
        registerStatsMetric(name, core->getId(), "total_walk_latency_data", &translation_stats.total_walk_latency_data);
        registerStatsMetric(name, core->getId(), "total_tlb_latency_instruction", &translation_stats.total_tlb_latency_instruction);
        registerStatsMetric(name, core->getId(), "total_tlb_latency_data", &translation_stats.total_tlb_latency_data);
        registerStatsMetric(name, core->getId(), "total_translation_latency_instruction", &translation_stats.total_translation_latency_instruction);
        registerStatsMetric(name, core->getId(), "total_translation_latency_data", &translation_stats.total_translation_latency_data);

        // Statistics for TLB subsystem - one counter per TLB level
        translation_stats.tlb_latency_per_level = new SubsecondTime[tlb_subsystem->getTLBSubsystem().size()];

        // Keep track of the TLB latency for each level in the hierarchy
        for (UInt32 i = 0; i < tlb_subsystem->getTLBSubsystem().size(); i++){
            registerStatsMetric(name, core->getId(), "tlb_latency_" + itostr(i), &translation_stats.tlb_latency_per_level[i]);
        }
    }

// ============================================================================
// Address Translation - Core MMU Operation
// ============================================================================

    /**
     * @brief Perform virtual-to-physical address translation.
     *
     * This is the main entry point for address translation, modeling the
     * complete hardware MMU pipeline. The function implements a multi-level
     * TLB lookup followed by page table walk on miss.
     *
     * ┌─────────────────────────────────────────────────────────────────────┐
     * │                    TRANSLATION FLOW DIAGRAM                          │
     * ├─────────────────────────────────────────────────────────────────────┤
     * │                                                                      │
     * │   Virtual Address ──► TLB Lookup ──┬──► HIT ──► Physical Address     │
     * │                                    │                                 │
     * │                                    └──► MISS ──► Page Table Walk     │
     * │                                              │                       │
     * │                                              ├──► Translation Found  │
     * │                                              │    └──► Allocate TLB  │
     * │                                              │                       │
     * │                                              └──► Page Fault         │
     * │                                                   ├──► Sniper-space  │
     * │                                                   │    (handle here) │
     * │                                                   └──► Userspace     │
     * │                                                        (return -1)   │
     * └─────────────────────────────────────────────────────────────────────┘
     *
     * PHASE 1: TLB Hierarchy Lookup (Lines ~300-380)
     * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     * Searches through all TLB levels (L1i/L1d, L2, etc.) for a cached
     * translation. Within each level, checks appropriate TLBs based on
     * instruction vs data access. Stops at first hit.
     *
     * PHASE 2: TLB Latency Calculation (Lines ~390-500)
     * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     * On HIT:  Sum latencies of all levels up to and including hit level.
     *          For L2 hits, apply page size prediction penalty if wrong.
     * On MISS: Sum latencies of all levels (must check everything).
     *
     * PHASE 3: Page Table Walk (Lines ~510-620)
     * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     * Only on TLB miss. Allocates a page table walker from the MSHR pool,
     * performs the walk via performPTW(), handles page faults if needed.
     * - Sniper-space mode: Faults handled internally, walk retried
     * - Userspace mode: Returns -1 for kernel handling
     *
     * PHASE 4: TLB Allocation (Lines ~630-720)
     * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     * After successful translation, allocates entry in all "allocate on miss"
     * TLBs from L1 up through the hierarchy. Handles eviction cascades where
     * evicted entries from lower levels get pushed to higher levels.
     *
     * PHASE 5: Physical Address Calculation (Lines ~750-770)
     * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     * Combines the Physical Page Number (PPN) with the page offset:
     *   physical_addr = (PPN * 4KB) + (virtual_addr & page_mask)
     * The physical page number is ALWAYS at 4KB granularity.
     *
     * @param eip          Instruction pointer causing this access (for tracing)
     * @param address      Virtual address to translate
     * @param instruction  True if this is an instruction fetch, false for data
     * @param lock         Cache coherence lock signal
     * @param modeled      True to model timing (false for warmup/functional)
     * @param count        True to update statistics counters
     * 
     * @return Physical address on success, or -1 on page fault (userspace mode)
     *
     * @note The timing model advances shmem_perf_model time during translation.
     * @note DRAM accesses during PTW are tracked in dram_accesses_during_last_walk.
     */

    IntPtr MemoryManagementUnitVTSA::performAddressTranslation(IntPtr eip, IntPtr address, bool instruction, Core::lock_signal_t lock, bool modeled, bool count)
    {
        // Adaptive gate: the causal clock counts EVERY region access.
        if (m_vtsa_mode == VTSA_MODE_ADAPTIVE && count && !instruction)
        {
            vtsa::AdaptiveCowEstimator *vtsa_est = Sim()->getMimicOS()->getVtsaEstimatorRaw();
            if (vtsa_est)
            {
                vtsa::HintRegion vtsa_hr;
                if (Sim()->getMimicOS()->vtsaHintFor(core->getThread()->getAppId(), (uint64_t)address, &vtsa_hr))
                    vtsa_est->note_access(vtsa_hr.site_id);
            }
        }

        // Track DRAM accesses for this walk (useful for power/performance analysis)
        dram_accesses_during_last_walk = 0;

        // ====================================================================
        // PERFECT TRANSLATION MODE
        // ====================================================================
        // In perfect translation mode:
        // - We perform the translation to get VA→PA mapping (for PA remapping benefit)
        // - Page faults are handled internally (pages allocated on first access)
        // - L1 dTLB latency is charged (models the minimum 1-cycle lookup cost)
        // - NO actual TLB lookups or allocations
        // - NO PTW latency charges  
        // This isolates the cache behavior benefit of PA remapping from translation overhead,
        // while still accounting for the unavoidable L1 TLB access cost.
        if (perfect_translation_enabled) {
            int app_id = core->getThread()->getAppId();
            PageTable *page_table = Sim()->getMimicOS()->getPageTable(app_id);
            
            // Use the zero-latency translation path from mmu_base
            auto [physical_address, page_size] = translateWithoutTiming(address, page_table);
            
            // Update only the basic translation count (no latency stats)
            if (count) {
                translation_stats.num_translations++;
                if (instruction)
                    translation_stats.num_translations_instruction++;
                else
                    translation_stats.num_translations_data++;
            }

            // Charge L1 dTLB latency (1-cycle hit) to model realistic lookup cost
            SubsecondTime l1_dtlb_latency = SubsecondTime::Zero();
            const TLBSubsystem& tlbs = tlb_subsystem->getTLBSubsystem();
            if (!tlbs.empty()) {
                for (UInt32 j = 0; j < tlbs[0].size(); j++) {
                    // Find the L1 dTLB (Data or Unified, not Instruction-only)
                    if (tlbs[0][j]->getType() != TLBtype::Instruction) {
                        l1_dtlb_latency = tlbs[0][j]->getLatency();
                        break;
                    }
                }
            }

            if (l1_dtlb_latency > SubsecondTime::Zero()) {
                SubsecondTime time = shmem_perf_model->getElapsedTime(ShmemPerfModel::_USER_THREAD);
                shmem_perf_model->setElapsedTime(ShmemPerfModel::_USER_THREAD, time + l1_dtlb_latency);
                translation_stats.total_tlb_latency += l1_dtlb_latency;
                translation_stats.total_translation_latency += l1_dtlb_latency;
            }
            
            mmu_log->debug("Perfect translation: VA " + mmu_log->hex(address) + 
                          " -> PA " + mmu_log->hex(physical_address) + 
                          " (L1 dTLB latency: " + std::to_string(l1_dtlb_latency.getNS()) + "ns)");
            
            return physical_address;
        }

        mmu_log->section("Starting address translation for virtual address: " + 
                        mmu_log->hex(address) + " at time " + 
                        std::to_string(shmem_perf_model->getElapsedTime(ShmemPerfModel::_USER_THREAD).getNS()) + "ns");

        // Capture the start time for latency calculations
        SubsecondTime time = shmem_perf_model->getElapsedTime(ShmemPerfModel::_USER_THREAD); 

        // Cleanup completed PTW entries from MSHR to free up walker slots
        pt_walkers->removeCompletedEntries(time);

#if ENABLE_MMU_CSV_LOGS
        UInt64 translation_index = 0;
#endif
        if (count)
        {
            translation_stats.num_translations++;
            if (instruction)
                translation_stats.num_translations_instruction++;
            else
                translation_stats.num_translations_data++;
#if ENABLE_MMU_CSV_LOGS
            translation_index = ++translation_sequence_counter;
#endif
        }

        int app_id = core->getThread()->getAppId();
        PageTable *page_table = Sim()->getMimicOS()->getPageTable(app_id);

        // Get reference to TLB hierarchy (const ref avoids expensive vector copy)
        const TLBSubsystem& tlbs = tlb_subsystem->getTLBSubsystem();

        // ====================================================================
        // PHASE 1: TLB Hierarchy Lookup
        // ====================================================================
        // Search through TLB levels for a cached translation.
        // The hierarchy is organized as: tlbs[level][index]
        //   Level 0: L1 TLBs (separate iTLB and dTLB typically)
        //   Level 1: L2 TLB (unified, larger)
        //   Level N: Higher-level TLBs if configured
        //
        // For instruction fetches, only iTLB and unified TLBs are searched.
        // For data accesses, only dTLB and unified TLBs are searched.

        bool hit = false;                        // Did we find a cached translation?
        TLB *hit_tlb = NULL;                     // Which TLB had the hit?
        CacheBlockInfo *tlb_block_info_hit = NULL;  // Block info from hitting TLB
        CacheBlockInfo *tlb_block_info = NULL;      // Temporary for lookup results
        int hit_level = -1;                      // Level where hit occurred (-1 = miss)
        int page_size = -1;                      // Page size: 12 for 4KB, 21 for 2MB
        IntPtr ppn_result = 0;                   // Physical Page Number result

        // Page Size Prediction: Predict 4KB vs 2MB before L2 lookup
        // This allows parallel L2 TLB bank access in hardware
        int predicted_page_size = -1;
		if (page_size_prediction_enabled)
			predicted_page_size = tlb_subsystem->predictPagesize(address);

		
        // Iterate through TLB hierarchy levels (0 = L1, 1 = L2, ...)
        for (UInt32 i = 0; i < tlbs.size(); i++)
        {
            mmu_log->debug("Searching TLB at level: " + std::to_string(i));
            
            // Search all TLBs at this level (may have separate i/d TLBs)
            for (UInt32 j = 0; j < tlbs[i].size(); j++)
            {
                // Check if this TLB handles instruction addresses
                bool tlb_stores_instructions = (tlbs[i][j]->getType() == TLBtype::Instruction) || (tlbs[i][j]->getType() == TLBtype::Unified);

                // For instruction fetches, only check iTLB or unified TLB
                if (tlb_stores_instructions && instruction)
                {
                    // @kanellok: Passing the page table to the TLB lookup function is a legacy from the old TLB implementation. 
                    // It is not used in the current implementation.

                    tlb_block_info = tlbs[i][j]->lookup(address, time, count, lock, eip, modeled, count, page_table, true /* instruction */);

                    if (tlb_block_info != NULL) // TLB HIT!
                    {
                        tlb_block_info_hit = tlb_block_info;
                        hit_tlb = tlbs[i][j];
                        hit_level = i;
                        hit = true;
                    }
                }
                // For data accesses, check dTLB or unified TLB
                else if (!instruction)
                {
                    bool tlb_stores_data = !(tlbs[i][j]->getType() == TLBtype::Instruction);
                    if (tlb_stores_data)
                    {
                        tlb_block_info = tlbs[i][j]->lookup(address, time, count, lock, eip, modeled, count, page_table, false /* data */);
                        if (tlb_block_info != NULL)  // TLB HIT!
                        {
                            tlb_block_info_hit = tlb_block_info;
                            hit_tlb = tlbs[i][j];
                            hit_level = i;
                            hit = true;
                        }
                    }
                }
            }
            // Stop searching once we find a hit at any level
            // (we search all TLBs at the same level in parallel, but levels are serial)
            if (hit)
            {
                mmu_log->log("TLB Hit at level " + std::to_string(hit_level) + 
                           " at TLB " + std::string(hit_tlb->getName().c_str()));
                break;
            }
        }


        // ====================================================================
        // Track TLB hits between PTWs (for temporal analysis)
        // ====================================================================
        if (hit)
        {
            tlb_hits_since_last_ptw++;
        }

        // ====================================================================
        // PHASE 2: TLB Latency Calculation
        // ====================================================================
        // Calculate the TLB access latency based on hit/miss and hit level.
        // TLB latency is charged regardless of hit or miss (we must check).
        //
        // Latency Model:
        // - TLBs at the same level are accessed in PARALLEL (take max)
        // - TLB levels are accessed SERIALLY (sum all levels until hit/end)
        //
        // Example: L1 iTLB=1cy, L1 dTLB=1cy, L2=10cy
        // - L1 hit:  1 cycle (max of iTLB and dTLB)
        // - L2 hit:  1 + 10 = 11 cycles
        // - L2 miss: 1 + 10 = 11 cycles (must check everything)

        SubsecondTime charged_tlb_latency = SubsecondTime::Zero();



		/* @kanellok: Tips and Hints:
		We performed the TLB lookup and we now need to decide what latency to charge based on whether we had a TLB hit or a TLB miss.
		*/
        
        // ----------------------------------------------------------------
        // CASE 1: TLB HIT - Charge latency up to hit level
        // ----------------------------------------------------------------
        if (hit)
        {
            // Extract translation data from the hitting TLB entry
            ppn_result = tlb_block_info_hit->getPPN();
            page_size = tlb_block_info_hit->getPageSize();

            mmu_log->log("TLB Hit at level " + std::to_string(hit_level) + 
                        " at TLB " + std::string(hit_tlb->getName().c_str()));
            
            // Get the appropriate TLB path (instruction or data) for latency
            const TLBSubsystem& tlb_path = instruction ? 
                tlb_subsystem->getInstructionPath() : tlb_subsystem->getDataPath();

            // Allocate array for per-level latencies
            SubsecondTime tlb_latency[hit_level + 1];

            // Sum latencies for all levels BEFORE the hit level
            // (we had to check these levels before finding the hit)
            for (int i = 0; i < hit_level; i++) 
            {
                tlb_latency[i] = SubsecondTime::Zero();
                // Find slowest TLB at this level (parallel access)
                for (UInt32 j = 0; j < tlb_path[i].size(); j++) 
                {
                    tlb_latency[i] = max(tlb_path[i][j]->getLatency(), tlb_latency[i]);
                }
                mmu_log->debug("Charging TLB Latency: " + std::to_string(tlb_latency[i].getNS()) + 
                             "ns at level " + std::to_string(i));
                translation_stats.total_tlb_latency += tlb_latency[i];
                translation_stats.tlb_latency_per_level[i] += tlb_latency[i];
                charged_tlb_latency += tlb_latency[i];
            }

            // Handle latency for the hit level itself
            for (UInt32 j = 0; j < tlb_path[hit_level].size(); j++)
            { 
                // For any TLB level other than L2 (level 1), charge the 
                // latency of the specific TLB that scored a hit.
                if (hit_level != 1 ){

                    if (tlb_path[hit_level][j] == hit_tlb)
					{
						translation_stats.total_tlb_latency += hit_tlb->getLatency();
						charged_tlb_latency += hit_tlb->getLatency();
						translation_stats.tlb_latency_per_level[hit_level] += hit_tlb->getLatency();
					}
                    mmu_log->debug("Charging TLB Hit Latency: " + std::to_string(hit_tlb->getLatency().getNS()) + 
                                 "ns at level " + std::to_string(hit_level));
                }

				// @kanellok: Page Size Prediction hit latency logic for L2 TLB hits
				// ================================================================
				// L2 TLB (level 1) has special handling for page size prediction.
				// Modern L2 TLBs store both 4KB and 2MB translations in separate
				// banks that can be accessed in parallel IF we predict correctly.
				//
				// Correct prediction: Access only the predicted bank (faster)
				// Wrong prediction:   Must check both banks serially (slower)
				else if (hit_level == 1 && page_size_prediction_enabled)
				{
					bool prediction_success = (predicted_page_size == page_size);
					if (prediction_success)
					{
						if (count)
							translation_stats.page_size_prediction_hits++;
						translation_stats.total_tlb_latency += l2_tlb_correct_prediction_latency;
						charged_tlb_latency += l2_tlb_correct_prediction_latency;
						translation_stats.tlb_latency_per_level[hit_level] += l2_tlb_correct_prediction_latency;
					}
					else
					{
						if (count)
							translation_stats.page_size_prediction_misses++;
						
						translation_stats.total_tlb_latency += l2_tlb_misprediction_latency;
						charged_tlb_latency += l2_tlb_misprediction_latency;
						translation_stats.tlb_latency_per_level[hit_level] += l2_tlb_misprediction_latency;
					}
					// L2 latency charged once based on prediction, exit loop
					break;
				}

            }

            // Advance simulation time by TLB latency
            // This ensures PTW (if any) starts after TLB lookup completes
            // @kanellok: Be very careful if you want to play around with the timing model
            shmem_perf_model->setElapsedTime(ShmemPerfModel::_USER_THREAD, time + charged_tlb_latency); 
            mmu_log->debug("New time after charging TLB latency: " + 
                          std::to_string(shmem_perf_model->getElapsedTime(ShmemPerfModel::_USER_THREAD).getNS()) + "ns");

            // Track instruction vs data TLB hits and latency
            if (count)
            {
                if (instruction) {
                    translation_stats.tlb_hits_instruction++;
                    translation_stats.total_tlb_latency_instruction += charged_tlb_latency;
                } else {
                    translation_stats.tlb_hits_data++;
                    translation_stats.total_tlb_latency_data += charged_tlb_latency;
                }
            }
        }

        // ----------------------------------------------------------------
        // CASE 2: TLB MISS - Charge latency for all levels
        // ----------------------------------------------------------------
        // On a complete TLB miss, we must search all levels before
        // concluding the translation is not cached. Charge the maximum
        // latency at each level (parallel TLBs within level).

        if (!hit)
        {
            SubsecondTime tlb_latency[tlbs.size()];  // VLA for TLB latencies
            
            mmu_log->log("TLB Miss");
            for (UInt32 i = 0; i < tlbs.size(); i++) 
            {
                tlb_latency[i] = SubsecondTime::Zero();
                // Take max latency at each level (parallel access)
                for (UInt32 j = 0; j < tlbs[i].size(); j++)
                {
                    tlb_latency[i] = max(tlbs[i][j]->getLatency(), tlb_latency[i]);
                }
                mmu_log->debug("Charging TLB Latency: " + std::to_string(tlb_latency[i].getNS()) + 
                             "ns at level " + std::to_string(i));
                translation_stats.total_tlb_latency += tlb_latency[i];
                charged_tlb_latency += tlb_latency[i];
            }
            
            // Advance time so PTW starts after TLB miss is confirmed
            shmem_perf_model->setElapsedTime(ShmemPerfModel::_USER_THREAD, time + charged_tlb_latency);
            mmu_log->debug("New time after charging TLB latency: " + 
                          std::to_string(shmem_perf_model->getElapsedTime(ShmemPerfModel::_USER_THREAD).getNS()) + "ns");

            // Track instruction vs data TLB misses and latency
            if (count)
            {
                if (instruction) {
                    translation_stats.tlb_misses_instruction++;
                    translation_stats.total_tlb_latency_instruction += charged_tlb_latency;
                } else {
                    translation_stats.tlb_misses_data++;
                    translation_stats.total_tlb_latency_data += charged_tlb_latency;
                }
            }
        }

        // ====================================================================
        // PHASE 3: Page Table Walk (on TLB Miss)
        // ====================================================================
        // On a TLB miss, we must walk the page table to find the translation.
        // This is an expensive operation that may involve multiple memory
        // accesses (one per page table level, typically 4 for x86-64).
        //
        // The PTW uses MSHRs to track concurrent walks. If all walkers are
        // busy, the new walk must wait for a slot (modeled as queuing delay).
        //
        // Page Fault Handling:
        // - Sniper-space mode: Handle fault internally and retry walk
        // - Userspace mode: Return -1 to trigger kernel page fault handler

        SubsecondTime total_walk_latency = SubsecondTime::Zero();
        SubsecondTime total_fault_latency = SubsecondTime::Zero();
        SubsecondTime translation_latency = charged_tlb_latency;
        [[maybe_unused]] bool performed_ptw = false;
        bool vtsa_suppress_fill = false;  // COW read: keep the page missing so writes stay detectable
#if ENABLE_MMU_CSV_LOGS
        bool page_metrics_updated = false;
#endif



        // Only perform PTW on TLB miss
        if (!hit)
        {   
            // Record time before PTW for latency calculation
            SubsecondTime time_for_pt = shmem_perf_model->getElapsedTime(ShmemPerfModel::_USER_THREAD);

            // Create MSHR entry to track this page table walk
            struct MSHREntry pt_walker_entry; 
            pt_walker_entry.request_time = time_for_pt;

        
            // Check for queuing delay if all page table walkers are busy
            // Modern CPUs have 2-4 parallel walkers (Intel Skylake: 2)
            SubsecondTime delay = pt_walkers->getSlotAllocationDelay(pt_walker_entry.request_time); 

            // Advance time to when a walker becomes available
            shmem_perf_model->setElapsedTime(ShmemPerfModel::_USER_THREAD, time_for_pt + delay);
            mmu_log->debug("New time after charging PTW allocation delay: " + 
                          std::to_string(shmem_perf_model->getElapsedTime(ShmemPerfModel::_USER_THREAD).getNS()) + "ns");

            // Determine page fault handling mode
            bool userspace_mimicos_enabled = Sim()->getMimicOS()->isUserspaceMimicosEnabled();
            
            // @kanellok: restart_walk_after_fault is now false by default
            // In sniper-space mode, faults are handled here and walk retried automatically
            bool restart_walk_after_fault = false;
            bool caused_page_fault = false;
            bool had_page_fault = false;  // Persists across loop iterations for fault latency tracking
            
            // PTW result: <walk_latency, caused_fault, ppn, page_size>
            PTWOutcome ptw_result;

            // ----------------------------------------------------------------
            // Page Table Walk Loop (with fault retry for sniper-space mode)
            // ----------------------------------------------------------------
            // In sniper-space mode, if a fault occurs, we handle it and
            // retry the walk. This continues until the walk succeeds.
            do {
                ptw_result = performPTW(address, modeled, count, false, eip, lock, page_table, restart_walk_after_fault, instruction);
                total_walk_latency = ptw_result.latency;  // PTW latency (excludes fault handling)
                caused_page_fault = ptw_result.page_fault;
                performed_ptw = true;
                translation_latency = charged_tlb_latency + total_walk_latency;

                // Update statistics
                if (count)
                {
                    translation_stats.total_walk_latency += total_walk_latency;
                    translation_stats.page_table_walks++;
                    if (instruction) {
                        translation_stats.page_table_walks_instruction++;
                        translation_stats.total_walk_latency_instruction += total_walk_latency;
                    } else {
                        translation_stats.page_table_walks_data++;
                        translation_stats.total_walk_latency_data += total_walk_latency;
                    }
                }

                // Handle page fault if one occurred
                if (caused_page_fault)
                {
                    had_page_fault = true;  // Track that a fault occurred (persists after retry)
                    mmu_log->log("Page Fault caused by address " + mmu_log->hex(address) + 
                               " at time " + std::to_string(shmem_perf_model->getElapsedTime(ShmemPerfModel::_USER_THREAD).getNS()) + "ns");
                    translation_stats.page_faults++;
                    if (instruction)
                        translation_stats.page_faults_instruction++;
                    else
                        translation_stats.page_faults_data++;
                    
                    // Sniper-space mode: Handle fault at simulator level (fast path)
                    // This avoids context switch overhead for better simulation speed
                    if (!userspace_mimicos_enabled)
                    {
                        mmu_log->log("Handling page fault in sniper-space mode, calling exception handler");

                        // Get the exception handler for this core (works with any handler type:
                        // SniperExceptionHandler, SpotExceptionHandler, UtopiaExceptionHandler, etc.)
                        ExceptionHandlerBase *handler = Sim()->getCoreManager()->getCoreFromID(core->getId())->getExceptionHandler();

                        // Initialize fault context and handle the fault
                        ExceptionHandlerBase::FaultCtx fault_ctx{};
                        fault_ctx.vpn = address >> 12;
                        fault_ctx.page_table = page_table;
                        fault_ctx.alloc_in.metadata_frames = ptw_result.requested_frames;
                        fault_ctx.alloc_in.is_instruction = instruction;
                        handler->handle_page_fault(fault_ctx);
                        
                        mmu_log->log("Page fault handled, restarting PTW for address " + mmu_log->hex(address));
                        // Loop will retry PTW now that page is mapped
                    }
                }
            } while (caused_page_fault && !userspace_mimicos_enabled);

            
            // ----------------------------------------------------------------
            // Userspace MimicOS: Return to let kernel handle page fault
            // ----------------------------------------------------------------
            // In userspace mode, we don't handle faults in the simulator.
            // Instead, return -1 to signal that a context switch to VirtuOS
            // is needed to handle the page fault.
            if(caused_page_fault && userspace_mimicos_enabled)
            {
                mmu_log->log("Page Fault in userspace mode - address " + mmu_log->hex(address) + 
                           " at time " + std::to_string(shmem_perf_model->getElapsedTime(ShmemPerfModel::_USER_THREAD).getNS()) + "ns");
                mmu_log->log("Will trigger context switch to VirtuOS");
#if ENABLE_MMU_CSV_LOGS
                if (count)
                {
                    updatePageMetrics(address, translation_latency, true, time, translation_index, total_walk_latency, SubsecondTime::Zero(), charged_tlb_latency);
                    page_metrics_updated = true;
                }
#endif
                return static_cast<IntPtr>(-1);  // Signal page fault to caller
            }

            // ----------------------------------------------------------------
            // Calculate PTW completion time and allocate MSHR entry
            // ----------------------------------------------------------------
            // Completion time = start + walker_delay + walk_latency + fault_latency
            
            // Charge page fault handling latency if a fault occurred during the loop
            // (caused_page_fault is false after sniper-space retry, so use had_page_fault)
            if (had_page_fault && !userspace_mimicos_enabled)
            {
                total_fault_latency = Sim()->getMimicOS()->getPageFaultLatency();
                if (count)
                {
                    translation_stats.total_fault_latency += total_fault_latency;
                }
            }
            
            pt_walker_entry.completion_time = time_for_pt + delay + total_walk_latency + total_fault_latency;
            pt_walkers->allocate(pt_walker_entry);

            // Advance simulation time to after PTW completes
            // This ensures subsequent cache accesses happen at the right time
            if (had_page_fault && !userspace_mimicos_enabled){
                // Queue pseudo-instruction to model fault handling overhead
                PseudoInstruction *i = new PageFaultRoutineInstruction(total_fault_latency);
                getCore()->getPerformanceModel()->queuePseudoInstruction(i);
                shmem_perf_model->setElapsedTime(ShmemPerfModel::_USER_THREAD, pt_walker_entry.completion_time);
            }
            else{
                shmem_perf_model->setElapsedTime(ShmemPerfModel::_USER_THREAD, pt_walker_entry.completion_time);
            }

            // Extract results from PTW
            ppn_result = ptw_result.ppn;  // Physical Page Number
            page_size = ptw_result.page_size;    // Page size (12=4KB, 21=2MB)

            // ============ V-TSA: consult the certification layer ============
            // Runs strictly AFTER the authoritative walk, only for 4KB-backed
            // translations (2MB THP leaves already have full reach).
            if (m_vtsa_mode != VTSA_MODE_OFF && page_size == 12 && !caused_page_fault)
            {
                SubsecondTime vtsa_latency = SubsecondTime::Zero();
                int vtsa_bits = 0;
                IntPtr vtsa_ppn = 0;

                // Emulated COW: a write miss to a COW page resolves the
                // fault (copy or reuse; revoke + sweep); a read miss stays
                // uncached so the eventual write is still detectable.
                MimicOS *vtsa_os = Sim()->getMimicOS();
                if (vtsa_os->vtsaIsCow(core->getThread()->getAppId(), (uint64_t)address))
                {
                    if (m_vtsa_access_is_write)
                    {
                        bool vtsa_copied = vtsa_os->vtsaCowResolve(core->getThread()->getAppId(), address, core->getId());
                        vtsa_latency += m_vtsa_cow_fault_latency->getLatency();
                        if (vtsa_copied)
                            vtsa_latency += m_vtsa_cow_copy_latency->getLatency();
                        if (count)
                        {
                            vtsa_stats.cow_faults++;
                            if (vtsa_copied) vtsa_stats.cow_copies++;
                        }
                        // the frame may have moved: refresh the walked ppn
                        vtsa::RadixAddressSpaceView *vtsa_view = vtsa_os->getVtsaView(core->getThread()->getAppId());
                        vtsa::PageInfo vtsa_pi;
                        if (vtsa_view && vtsa_view->translate((uint64_t)address & ~(uint64_t)4095, vtsa_pi) && vtsa_pi.present)
                            ppn_result = (IntPtr)vtsa_pi.frame;
                    }
                    else
                    {
                        vtsa_suppress_fill = true;
                        if (count) vtsa_stats.cow_read_suppressed++;
                    }
                }

                if (!vtsa_suppress_fill && vtsaConsult(address, count, vtsa_latency, vtsa_bits, vtsa_ppn))
                {
                    page_size = vtsa_bits;
                    ppn_result = vtsa_ppn;
                }
                if (vtsa_latency > SubsecondTime::Zero())
                {
                    total_walk_latency += vtsa_latency;
                    shmem_perf_model->setElapsedTime(ShmemPerfModel::_USER_THREAD,
                        shmem_perf_model->getElapsedTime(ShmemPerfModel::_USER_THREAD) + vtsa_latency);
                }
            }

            mmu_log->debug("New time after charging PTW completion: " + 
                          std::to_string(shmem_perf_model->getElapsedTime(ShmemPerfModel::_USER_THREAD).getNS()) + "ns");

        }


        mmu_log->debug("Total Walk Latency: " + std::to_string(total_walk_latency.getNS()) + "ns");
        mmu_log->debug("Total Fault Latency: " + std::to_string(total_fault_latency.getNS()) + "ns");

        // ====================================================================
        // PHASE 4: TLB Allocation (populate TLBs with new translation)
        // ====================================================================
        // After a successful translation (either from TLB hit at higher level
        // or from PTW), we need to allocate the translation into the appropriate
        // TLBs. This implements the "allocate on miss" policy.
        //
        // Allocation Rules:
        // 1. Only allocate if TLB supports the page size (4KB or 2MB)
        // 2. Only allocate if TLB has "allocate on miss" enabled
        // 3. Only allocate if TLB miss OR hit was at higher level
        //
        // Eviction Cascade:
        // When allocating causes an eviction, the evicted entry may be pushed
        // to the next level TLB (if it supports that page size). This mimics
        // inclusive TLB hierarchies.
        //
        // Example: L1 dTLB evicts entry → pushed to L2 TLB → may cause
        //          another eviction at L2 which is just dropped.

        // Get the appropriate TLB path for allocation (instruction or data)
        const TLBSubsystem& alloc_tlbs = instruction ? 
            tlb_subsystem->getInstructionPath() : tlb_subsystem->getDataPath();

        // Track evicted translations for cascade allocation to higher levels
        // Map: level → vector of evicted translations
        std::map<int, vector<EvictedTranslation>> evicted_translations;

        // Determine how many levels to allocate to
        // NOTE: We iterate through ALL levels. The PQ is at the same level as L2 TLB,
        // but we skip PQs during normal allocation (they only receive prefetched entries
        // or L1 evictions). We use getPrefetch() to distinguish PQs from regular TLBs.
        int tlb_levels = alloc_tlbs.size();

        // Iterate through TLB levels for allocation
        for (int i = 0; i < tlb_levels; i++)
        {
            // Process each TLB at this level
            for (UInt32 j = 0; j < alloc_tlbs[i].size(); j++)
            {
                // Skip PQs - they only receive prefetched entries, not demand allocations or evictions
                if (alloc_tlbs[i][j]->getPrefetch())
                    continue;

                // --------------------------------------------------------
                // First: Handle evicted translations from previous level
                // --------------------------------------------------------
                // Evicted entries from L(i-1) may be pushed to L(i) if
                // the TLB supports that page size.
                if ((i > 0) && (evicted_translations[i - 1].size() != 0))
                {
                    TLBAllocResult result;

                    mmu_log->debug("Processing evicted translations from level " + std::to_string(i - 1));
                    
                    // Try to allocate each evicted translation
                    for (UInt32 k = 0; k < evicted_translations[i - 1].size(); k++)
                    {
                        const EvictedTranslation& evicted = evicted_translations[i - 1][k];
                        mmu_log->detailed("Evicted Translation: " + mmu_log->hex(evicted.address));
                        
                        IntPtr evicted_address = evicted.address;
                        int evicted_page_size = evicted.page_size;
                        IntPtr evicted_ppn = evicted.ppn;
                        
                        // Only allocate if TLB supports this page size
                        if (alloc_tlbs[i][j]->supportsPageSize(evicted_page_size))
                        {
                            mmu_log->detailed("Allocating evicted entry in TLB: Level=" + std::to_string(i) + 
                                           " Index=" + std::to_string(j));

                            result = alloc_tlbs[i][j]->allocate(evicted_address, time, count, lock, evicted_page_size, evicted_ppn, false /* not self_alloc */, instruction);

                            // If allocation caused another eviction, track it for next level
                            if (result.evicted)
                            {
                                evicted_translations[i].emplace_back(result.address, result.page_size, result.ppn);
#if ENABLE_MMU_CSV_LOGS
                                if (count && (i == tlb_levels - 1))
                                {
                                    IntPtr evicted_page_number = evicted_address >> evicted_page_size;
                                    last_eviction_index[evicted_page_number] = translation_index;
                                }
#endif
                            }
                        }
                    }
                }

                // --------------------------------------------------------
                // Second: Allocate the current translation
                // --------------------------------------------------------
                // Allocate if:
                // 1) TLB supports this page size (4KB or 2MB)
                // 2) TLB policy is "allocate on miss"
                // 3) Either TLB missed OR hit was at higher level (need to fill lower)
                
                if (!vtsa_suppress_fill && alloc_tlbs[i][j]->supportsPageSize(page_size) && alloc_tlbs[i][j]->getAllocateOnMiss() && (!hit || hit_level > i))
                {
                    mmu_log->detailed(std::string(alloc_tlbs[i][j]->getName().c_str()) + " supports page size " + std::to_string(page_size));
                    mmu_log->detailed("Allocating in TLB: Level=" + std::to_string(i) + " Index=" + std::to_string(j) + 
                                    " PageSize=" + std::to_string(page_size) + " VPN=" + mmu_log->hex(address >> page_size));
                    TLBAllocResult result;

                    result = alloc_tlbs[i][j]->allocate(address, time, count, lock, page_size, ppn_result, false /* not self_alloc */, instruction);
                    if (result.evicted)
                    {
                        evicted_translations[i].emplace_back(result.address, result.page_size, result.ppn);
#if ENABLE_MMU_CSV_LOGS
                        if (count && (i == tlb_levels - 1))
                        {
                            IntPtr evicted_page_number = result.address >> result.page_size;
                            last_eviction_index[evicted_page_number] = translation_index;
                        }
#endif
                    }
                }

            }
        }

        
        // ====================================================================
        // PHASE 5: Physical Address Calculation
        // ====================================================================
        // Compute the final physical address by combining:
        //   1. Physical Page Number (PPN) from PTW or TLB
        //   2. Page offset from the original virtual address
        //
        // For x86-64:
        //   4KB pages:  PA = PPN * 4KB  + VA[11:0]   (12-bit offset)
        //   2MB pages:  PA = PPN * 4KB  + VA[20:0]   (21-bit offset)
        //   1GB pages:  PA = PPN * 4KB  + VA[29:0]   (30-bit offset)
        //
        // Note: PPN is always at 4KB granularity in our page table.
        // For huge pages, the offset includes the sub-page bits.

        translation_latency = charged_tlb_latency + total_walk_latency;
        translation_stats.total_translation_latency += translation_latency;
        
        // ====================================================================
        // Update MimicOS Per-Core Stats (for adaptive policies like MPLRU)
        // ====================================================================
        // Update centralized stats in MimicOS that can be accessed by any component.
        // The MPLRU controller pulls from these stats in processEpoch().
        if (count)
        {
            MimicOS* mimicos = Sim()->getMimicOS();
            if (mimicos && mimicos->isPerCoreStatsInitialized())
            {
                bool is_l2_miss = !hit;  // L2 TLB miss triggers page walk
                mimicos->updateTranslationStats(core->getId(), 
                                                translation_latency,
                                                is_l2_miss,
                                                total_walk_latency);
            }
            
            // Note: MPLRU epoch processing is triggered from memory_manager
            // after data accesses, where the controller checks timing internally
        }
        
#if ENABLE_MMU_CSV_LOGS
        if (count && performed_ptw)
        {
            IntPtr page_number = address >> PAGE_SHIFT;
            auto it = last_eviction_index.find(page_number);
            if (it != last_eviction_index.end() && translation_index > it->second)
            {
                UInt64 use_after_eviction_distance = translation_index - it->second;
                if (use_after_eviction_log.is_open())
                {
                    use_after_eviction_log << page_number << ","
                                           << use_after_eviction_distance << ","
                                           << total_walk_latency << std::endl;
                }
                last_eviction_index.erase(it);
            }
        }
        if (count && !page_metrics_updated)
        {
            SubsecondTime tlb_hit_component = hit ? charged_tlb_latency : SubsecondTime::Zero();
            SubsecondTime tlb_miss_component = hit ? SubsecondTime::Zero() : charged_tlb_latency;
            SubsecondTime ptw_component = performed_ptw ? total_walk_latency : SubsecondTime::Zero();
            updatePageMetrics(address, translation_latency, performed_ptw, time, translation_index, ptw_component, tlb_hit_component, tlb_miss_component);
            page_metrics_updated = true;
        }
#endif

        // Calculate page size in bytes using bit shift (much faster than pow())
        // page_size=12 → 4KB (1 << 12 = 4096)
        // page_size=21 → 2MB (1 << 21 = 2097152)
        IntPtr page_size_in_bytes = 1ULL << page_size;
        constexpr IntPtr base_page_size_in_bytes = 1ULL << 12;  // 4KB base

        // Extract page offset using bitwise AND (faster than modulo)
        // For 4KB: offset = address & 0xFFF
        // For 2MB: offset = address & 0x1FFFFF
        IntPtr offset = address & (page_size_in_bytes - 1);
        
        // Combine PPN and offset to form physical address
        // PPN is stored at 4KB granularity, so multiply by base page size
        IntPtr final_physical_address = (ppn_result * base_page_size_in_bytes) + offset;

        mmu_log->debug("Physical Address: " + mmu_log->hex(final_physical_address) + 
                      " PPN: " + mmu_log->hex(ppn_result * base_page_size_in_bytes) + 
                      " Page Size: " + std::to_string(page_size) + " Offset: " + mmu_log->hex(offset));
        // Track instruction vs data total translation latency
        if (count)
        {
            SubsecondTime total_latency = charged_tlb_latency + total_walk_latency;
            if (instruction)
                translation_stats.total_translation_latency_instruction += total_latency;
            else
                translation_stats.total_translation_latency_data += total_latency;
        }

        mmu_log->debug("Total translation latency: " + std::to_string((charged_tlb_latency + total_walk_latency).getNS()) + "ns");
        mmu_log->debug("Total fault latency: " + std::to_string(total_fault_latency.getNS()) + "ns");
        mmu_log->section("Ending address translation for virtual address " + mmu_log->hex(address));

        // ====================================================================
        // Sanity Checks: Verify VA-PA mapping consistency
        // ====================================================================
        if (sanity_checks_enabled)
        {
            // Align to page boundary for consistency check
            IntPtr page_size_bytes = 1ULL << page_size;
            IntPtr va_page = address & ~(page_size_bytes - 1);
            IntPtr pa_page = final_physical_address & ~(page_size_bytes - 1);

            // Check 1: Same VA should always map to same PA
            auto va_it = va_to_pa_map.find(va_page);
            if (va_it != va_to_pa_map.end())
            {
                if (va_it->second != pa_page)
                {
                    sanity_check_violations++;
                    std::cerr << "[MMU SANITY ERROR] Core " << core->getId()
                              << " VA=0x" << std::hex << va_page
                              << " mapped to different PAs! Previous=0x" << va_it->second
                              << " Current=0x" << pa_page << std::dec << std::endl;
                    assert(false && "VA-PA mapping inconsistency detected!");
                }
            }
            else
            {
                // First time seeing this VA, record the mapping
                va_to_pa_map[va_page] = pa_page;
            }

            // Check 2: Each PA should be assigned to only one VA
            auto pa_it = pa_to_va_map.find(pa_page);
            if (pa_it != pa_to_va_map.end())
            {
                if (pa_it->second != va_page)
                {
                    sanity_check_violations++;
                    std::cerr << "[MMU SANITY ERROR] Core " << core->getId()
                              << " PA=0x" << std::hex << pa_page
                              << " assigned to multiple VAs! Previous=0x" << pa_it->second
                              << " Current=0x" << va_page << std::dec << std::endl;
                    assert(false && "PA assigned to multiple VAs detected!");
                }
            }
            else
            {
                // First time seeing this PA, record the mapping
                pa_to_va_map[pa_page] = va_page;
            }
        }

        return final_physical_address;
    }

// ============================================================================
// Helper Methods
// ============================================================================

    /**
     * @brief Filter PTW results through the PTW filter subsystem.
     * 
     * The PTW filter can modify or suppress page table walk results based on
     * various policies (e.g., speculative filtering, security filtering).
     * 
     * @param virtual_address The virtual address being translated
     * @param ptw_result      The raw result from the page table walk
     * @param page_table      Pointer to the page table
     * @param count           Whether to count this in statistics
     * @return Filtered PTW result
     */
    PTWResult MemoryManagementUnitVTSA::filterPTWResult(IntPtr virtual_address, PTWResult ptw_result, PageTable *page_table, bool count) 
    {
        return ptw_filter->filterPTWResult(virtual_address, ptw_result, page_table, count);
    }

    /**
     * @brief Discover Virtual Memory Areas (VMAs) for the current process.
     * 
     * This method is reserved for future implementation of VMA tracking.
     * VMAs define the memory layout of a process (code, data, stack, heap,
     * mmap regions, etc.) and can be used for:
     * - Prefetching decisions
     * - Page replacement policies
     * - Security analysis
     * 
     * @note Currently not implemented.
     */
    void MemoryManagementUnitVTSA::discoverVMAs()
    {
        // Reserved for future VMA discovery implementation
    }

// ============================================================================
// CSV Logging & Metrics
// ============================================================================
// These methods provide detailed per-page and per-region analysis capabilities.
// They are expensive (O(n) storage) so are disabled by default.
// Enable with ENABLE_MMU_CSV_LOGS=1 for offline analysis.

    /**
     * @brief Initialize per-page logging files.
     * 
     * Creates CSV files for detailed analysis:
     * - mmu_translation_latency_per_page: Per-page translation statistics
     * - mmu_translation_events: Time-series of translation events
     * - mmu_reuse_distance_hist: Reuse distance histogram
     * - mmu_ptw_per_page: Page table walks per page
     * - mmu_use_after_eviction: Tracks re-access after TLB eviction
     */
    void MemoryManagementUnitVTSA::initializePerPageLogs()
    {
#if ENABLE_MMU_CSV_LOGS
        std::string output_dir = std::string(Sim()->getConfig()->getOutputDirectory().c_str());
        std::string core_suffix = std::to_string(core->getId());

        // Per-page translation latency log
        translation_latency_log_name = output_dir + "/mmu_translation_latency_per_page." + core_suffix + ".csv";
        // Translation events log (time, page, PTW occurred)
        translation_events_log_name = output_dir + "/mmu_translation_events." + core_suffix + ".csv";
        // Reuse distance histogram
        reuse_distance_log_name = output_dir + "/mmu_reuse_distance_hist." + core_suffix + ".csv";
        // PTW count per page
        ptw_per_page_log_name = output_dir + "/mmu_ptw_per_page." + core_suffix + ".csv";
        // Use-after-eviction tracking
        use_after_eviction_log_name = output_dir + "/mmu_use_after_eviction." + core_suffix + ".csv";

        translation_latency_log.open(translation_latency_log_name.c_str());
#ifdef ENABLE_TRANSLATION_EVENTS_LOG
        // WARNING: This log can become extremely large!
        translation_events_log.open(translation_events_log_name.c_str());
#endif
        reuse_distance_log.open(reuse_distance_log_name.c_str());
        ptw_per_page_log.open(ptw_per_page_log_name.c_str());
        use_after_eviction_log.open(use_after_eviction_log_name.c_str());
        if (use_after_eviction_log.is_open())
        {
            use_after_eviction_log << "page_number,use_after_eviction_distance,ptw_latency" << std::endl;
        }
#endif
    }

    /**
     * @brief Update per-page metrics after each translation.
     * 
     * Tracks detailed metrics for analysis including:
     * - Translation count and latency per page
     * - TLB hit vs miss latency breakdown
     * - PTW latency bucketing (cheap/mid/costly/expensive)
     * - Reuse distance analysis at multiple granularities
     * 
     * @param virtual_address        The translated virtual address
     * @param translation_latency    Total translation latency
     * @param performed_ptw          Whether a page table walk occurred
     * @param translation_start_time When translation started
     * @param translation_index      Unique index for reuse analysis
     * @param walk_latency           PTW component of latency
     * @param tlb_hit_latency        TLB hit component of latency
     * @param tlb_miss_latency       TLB miss component of latency
     */
    void MemoryManagementUnitVTSA::updatePageMetrics(IntPtr virtual_address, SubsecondTime translation_latency, bool performed_ptw, SubsecondTime translation_start_time, UInt64 translation_index, SubsecondTime walk_latency, SubsecondTime tlb_hit_latency, SubsecondTime tlb_miss_latency)
    {
#if ENABLE_MMU_CSV_LOGS
        IntPtr page_number = virtual_address >> PAGE_SHIFT;
        PageMetrics &metrics = page_metrics[page_number];

        metrics.translations++;
        metrics.total_translation_latency += translation_latency;
        metrics.tlb_hit_latency += tlb_hit_latency;
        metrics.tlb_miss_latency += tlb_miss_latency;
        metrics.ptw_latency += walk_latency;
        if (performed_ptw)
        {
            metrics.page_table_walks++;
            // bucketize PTW latency
            if (walk_latency < PTW_BUCKET_CHEAP)
                metrics.ptw_latency_buckets[0]++;
            else if (walk_latency < PTW_BUCKET_MID)
                metrics.ptw_latency_buckets[1]++;
            else if (walk_latency < PTW_BUCKET_COSTLY)
                metrics.ptw_latency_buckets[2]++;
            else
                metrics.ptw_latency_buckets[3]++;
        }

        for (int shift : LATENCY_GRANULARITY_SHIFTS)
        {
            IntPtr region_number = virtual_address >> shift;
            GranularityMetrics &gran_metrics = granularity_metrics[shift][region_number];
            gran_metrics.translations++;
            gran_metrics.total_translation_latency += translation_latency;
            gran_metrics.tlb_hit_latency += tlb_hit_latency;
            gran_metrics.tlb_miss_latency += tlb_miss_latency;
            gran_metrics.ptw_latency += walk_latency;
            if (performed_ptw)
            {
                gran_metrics.page_table_walks++;
            }

            GranularityReuse &reuse_state = granularity_reuse_state[shift][region_number];
            if (reuse_state.has_last_access && translation_index > reuse_state.last_access_index)
            {
                UInt64 distance = translation_index - reuse_state.last_access_index;
                reuse_distance_histogram_granular[shift][distance]++;
                reuse_distance_latency_granular[shift][distance] += translation_latency;
            }
            reuse_state.last_access_index = translation_index;
            reuse_state.has_last_access = true;
        }

#ifdef ENABLE_TRANSLATION_EVENTS_LOG
        if (translation_events_log.is_open())
        {
            // Changed to CSV format (decimals are default)
            translation_events_log << translation_start_time.getNS() << "," << page_number << "," << (performed_ptw ? 1 : 0) << std::endl;
        }
#endif

        if (metrics.has_last_access && translation_index > metrics.last_access_index)
        {
            UInt64 distance = translation_index - metrics.last_access_index;
            reuse_distance_histogram[distance]++;
            reuse_distance_latency[distance] += translation_latency;
        }

        metrics.last_access_index = translation_index;
        metrics.has_last_access = true;
#else
        (void)virtual_address;
        (void)translation_latency;
        (void)performed_ptw;
        (void)translation_start_time;
        (void)translation_index;
        (void)walk_latency;
        (void)tlb_hit_latency;
        (void)tlb_miss_latency;
#endif
    }

    /**
     * @brief Dump all accumulated per-page logs to CSV files.
     * 
     * Called at simulation end to write out all collected metrics.
     * Generates multiple CSV files for different analysis:
     * 
     * 1. translation_latency_per_page.csv: Per-page statistics
     *    - page_number, total_latency, translations, avg_latency, etc.
     * 
     * 2. ptw_per_page.csv: PTW frequency and latency buckets
     *    - page_number, walks, cheap, mid_cost, costly, ultra_expensive
     * 
     * 3. reuse_distance_hist.csv: Reuse distance histogram
     *    - distance, count, total_latency, avg_latency
     * 
     * 4. Per-granularity files (16KB to 2MB regions):
     *    - mmu_translation_latency_per_region_NKB.csv
     *    - mmu_reuse_distance_hist_NKB.csv
     */
    void MemoryManagementUnitVTSA::dumpPerPageLogs()
    {
#if ENABLE_MMU_CSV_LOGS
        if (translation_latency_log.is_open())
        {
            // CSV Header
            translation_latency_log << "page_number,total_translation_latency,translations,avg_translation_latency,tlb_hit_latency,tlb_miss_latency,ptw_latency" << std::endl;
            for (const auto &kv : page_metrics)
            {
                const PageMetrics &metrics = kv.second;
                // CSV Data (decimals are default for integer types in C++ streams)
                translation_latency_log << kv.first << ","
                                        << metrics.total_translation_latency << ","
                                        << metrics.translations << ","
                                        << (metrics.translations ? metrics.total_translation_latency / metrics.translations : SubsecondTime::Zero()) << ","
                                        << metrics.tlb_hit_latency << ","
                                        << metrics.tlb_miss_latency << ","
                                        << metrics.ptw_latency << std::endl;
            }
        }

        if (ptw_per_page_log.is_open())
        {
            // CSV Header
            ptw_per_page_log << "page_number,page_table_walks,cheap,mid_cost,costly,ultra_expensive" << std::endl;
            for (const auto &kv : page_metrics)
            {
                const PageMetrics &metrics = kv.second;
                // CSV Data
                ptw_per_page_log << kv.first << "," << metrics.page_table_walks << ","
                                 << metrics.ptw_latency_buckets[0] << ","
                                 << metrics.ptw_latency_buckets[1] << ","
                                 << metrics.ptw_latency_buckets[2] << ","
                                 << metrics.ptw_latency_buckets[3] << std::endl;
            }
        }

        std::string output_dir = std::string(Sim()->getConfig()->getOutputDirectory().c_str());
        std::string core_suffix = std::to_string(core->getId());
        auto granularity_label = [](int shift) {
            UInt64 bytes = 1ULL << shift;
            if (bytes >= (1ULL << 20))
                return std::to_string(bytes >> 20) + "MB";
            return std::to_string(bytes >> 10) + "KB";
        };

        for (int shift : LATENCY_GRANULARITY_SHIFTS)
        {
            std::string size_label = granularity_label(shift);
            // Changed to .csv
            std::string file_name = output_dir + "/mmu_translation_latency_per_region_" + size_label + "." + core_suffix + ".csv";
            std::ofstream out(file_name.c_str());
            if (!out.is_open())
                continue;

            // CSV Header
            out << "region_id,translations,total_translation_latency,avg_translation_latency,tlb_hit_latency,tlb_miss_latency,ptw_latency,page_table_walks" << std::endl;

            auto it = granularity_metrics.find(shift);
            if (it == granularity_metrics.end())
                continue;

            for (const auto &kv : it->second)
            {
                const GranularityMetrics &metrics = kv.second;
                // CSV Data
                out << kv.first << ","
                    << metrics.translations << ","
                    << metrics.total_translation_latency << ","
                    << (metrics.translations ? metrics.total_translation_latency / metrics.translations : SubsecondTime::Zero()) << ","
                    << metrics.tlb_hit_latency << ","
                    << metrics.tlb_miss_latency << ","
                    << metrics.ptw_latency << ","
                    << metrics.page_table_walks << std::endl;
            }
        }

        if (reuse_distance_log.is_open())
        {
            // CSV Header
            reuse_distance_log << "reuse_distance,translations,total_translation_latency,avg_translation_latency" << std::endl;
            for (const auto &kv : reuse_distance_histogram)
            {
                SubsecondTime total_lat = SubsecondTime::Zero();
                auto lat_it = reuse_distance_latency.find(kv.first);
                if (lat_it != reuse_distance_latency.end())
                    total_lat = lat_it->second;
                
                // CSV Data
                reuse_distance_log << kv.first << ","
                                   << kv.second << ","
                                   << total_lat << ","
                                   << (kv.second ? total_lat / kv.second : SubsecondTime::Zero()) << std::endl;
            }
        }

        for (int shift : LATENCY_GRANULARITY_SHIFTS)
        {
            std::string size_label = granularity_label(shift);
            // Changed to .csv
            std::string file_name = output_dir + "/mmu_reuse_distance_hist_" + size_label + "." + core_suffix + ".csv";
            std::ofstream out(file_name.c_str());
            if (!out.is_open())
                continue;

            // CSV Header
            out << "reuse_distance,translations,total_translation_latency,avg_translation_latency" << std::endl;
            auto it = reuse_distance_histogram_granular.find(shift);
            if (it == reuse_distance_histogram_granular.end())
                continue;

            std::vector<std::pair<UInt64, UInt64>> entries;
            entries.reserve(it->second.size());
            for (const auto &kv : it->second)
                entries.emplace_back(kv.first, kv.second);
            std::sort(entries.begin(), entries.end(),
                      [](const auto &a, const auto &b) { return a.first < b.first; });

            const auto lat_map_it = reuse_distance_latency_granular.find(shift);
            const auto *lat_map = (lat_map_it != reuse_distance_latency_granular.end()) ? &lat_map_it->second : nullptr;

            for (const auto &kv : entries)
            {
                SubsecondTime total_lat = SubsecondTime::Zero();
                if (lat_map)
                {
                    auto lat_it = lat_map->find(kv.first);
                    if (lat_it != lat_map->end())
                        total_lat = lat_it->second;
                }
                // CSV Data
                out << kv.first << "," << kv.second << ","
                    << total_lat << ","
                    << (kv.second ? total_lat / kv.second : SubsecondTime::Zero()) << std::endl;
            }
        }
#endif
    }

// ============================================================================
// Static Constants
// ============================================================================
// These constants define thresholds and granularities used throughout the MMU.

    /**
     * PTW Latency Buckets for Histogram Classification
     * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     * Used to categorize page table walks by their latency for analysis.
     * The buckets correspond to typical cache/memory hierarchy levels:
     * 
     * - CHEAP  (<10ns):  L1/L2 cache hits - PTE found in data cache
     * - MID    (<30ns):  L3 cache hits - PTE found in LLC
     * - COSTLY (<60ns):  Single DRAM access - typical case
     * - ULTRA  (>=60ns): Multiple DRAM accesses, THP faults, etc.
     * 
     * These thresholds are based on typical DDR4/DDR5 memory latencies
     * and modern cache hierarchies.
     */
    const SubsecondTime MemoryManagementUnitVTSA::PTW_BUCKET_CHEAP  = SubsecondTime::NS(10);
    const SubsecondTime MemoryManagementUnitVTSA::PTW_BUCKET_MID    = SubsecondTime::NS(30);
    const SubsecondTime MemoryManagementUnitVTSA::PTW_BUCKET_COSTLY = SubsecondTime::NS(60);

    /**
     * Granularity Shifts for Multi-Scale Reuse Analysis
     * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     * These bit shifts define the region sizes for analyzing translation
     * behavior at different spatial granularities:
     * 
     *   Shift 14 → 16KB  (4 pages)
     *   Shift 15 → 32KB  (8 pages)
     *   Shift 16 → 64KB  (16 pages)
     *   Shift 17 → 128KB (32 pages)
     *   Shift 18 → 256KB (64 pages)
     *   Shift 19 → 512KB (128 pages)
     *   Shift 20 → 1MB   (256 pages)
     *   Shift 21 → 2MB   (huge page size)
     * 
     * Multi-scale analysis helps identify:
     * - Hot memory regions at different scales
     * - Potential huge page promotion candidates
     * - Memory access patterns and locality
     */
    const std::array<int, 8> MemoryManagementUnitVTSA::LATENCY_GRANULARITY_SHIFTS = {14, 15, 16, 17, 18, 19, 20, 21};


	static void vtsaCountRefusal(const char *why, UInt64 *absent, UInt64 *perms, UInt64 *align, UInt64 *contig, UInt64 *geom)
	{
		if (strcmp(why, "page_absent") == 0) (*absent)++;
		else if (strcmp(why, "perms_not_uniform") == 0) (*perms)++;
		else if (strcmp(why, "window_not_aligned") == 0) (*align)++;
		else if (strcmp(why, "window_not_contiguous") == 0) (*contig)++;
		else if (strcmp(why, "bad_geometry") == 0 || strcmp(why, "out_of_bounds") == 0) (*geom)++;
	}

	void MemoryManagementUnitVTSA::registerVTSAStats()
	{
		registerStatsMetric(name, core->getId(), "vtsa_certifications", &vtsa_stats.certifications);
		registerStatsMetric(name, core->getId(), "vtsa_certify_refusals", &vtsa_stats.certify_refusals);
		registerStatsMetric(name, core->getId(), "vtsa_cert_installs", &vtsa_stats.cert_installs);
		registerStatsMetric(name, core->getId(), "vtsa_cert_checks", &vtsa_stats.cert_checks);
		registerStatsMetric(name, core->getId(), "vtsa_rlb_reloads", &vtsa_stats.rlb_reloads);
		registerStatsMetric(name, core->getId(), "vtsa_cert_pte_reads", &vtsa_stats.cert_pte_reads);
		registerStatsMetric(name, core->getId(), "vtsa_probe_pte_reads", &vtsa_stats.probe_pte_reads);
		registerStatsMetric(name, core->getId(), "vtsa_bounded_installs_16k", &vtsa_stats.bounded_installs_16k);
		registerStatsMetric(name, core->getId(), "vtsa_bounded_installs_64k", &vtsa_stats.bounded_installs_64k);
		registerStatsMetric(name, core->getId(), "vtsa_bounded_installs_256k", &vtsa_stats.bounded_installs_256k);
		registerStatsMetric(name, core->getId(), "vtsa_bounded_installs_2m", &vtsa_stats.bounded_installs_2m);
		registerStatsMetric(name, core->getId(), "vtsa_bounded_skipped_budget", &vtsa_stats.bounded_skipped_budget);
		registerStatsMetric(name, core->getId(), "vtsa_refuse_absent", &vtsa_stats.refuse_absent);
		registerStatsMetric(name, core->getId(), "vtsa_refuse_perms", &vtsa_stats.refuse_perms);
		registerStatsMetric(name, core->getId(), "vtsa_refuse_align", &vtsa_stats.refuse_align);
		registerStatsMetric(name, core->getId(), "vtsa_refuse_contig", &vtsa_stats.refuse_contig);
		registerStatsMetric(name, core->getId(), "vtsa_refuse_geometry", &vtsa_stats.refuse_geometry);
		registerStatsMetric(name, core->getId(), "vtsa_sweeps", &vtsa_stats.sweeps);
		registerStatsMetric(name, core->getId(), "vtsa_tlb_shootdowns", &vtsa_stats.tlb_shootdowns);
		registerStatsMetric(name, core->getId(), "vtsa_hint_qualified", &vtsa_stats.hint_qualified);
		registerStatsMetric(name, core->getId(), "vtsa_hint_disqualified", &vtsa_stats.hint_disqualified);
		registerStatsMetric(name, core->getId(), "vtsa_hint_absent", &vtsa_stats.hint_absent);
		registerStatsMetric(name, core->getId(), "vtsa_cow_faults", &vtsa_stats.cow_faults);
		registerStatsMetric(name, core->getId(), "vtsa_cow_copies", &vtsa_stats.cow_copies);
		registerStatsMetric(name, core->getId(), "vtsa_cow_read_suppressed", &vtsa_stats.cow_read_suppressed);
		registerStatsMetric(name, core->getId(), "vtsa_adaptive_certifies", &vtsa_stats.adaptive_certifies);
		registerStatsMetric(name, core->getId(), "vtsa_adaptive_refusals", &vtsa_stats.adaptive_refusals);
		registerStatsMetric(name, core->getId(), "vtsa_certify_backoff", &vtsa_stats.certify_backoff);
		registerStatsMetric(name, core->getId(), "vtsa_upgrade_probes", &vtsa_stats.upgrade_probes);
		registerStatsMetric(name, core->getId(), "vtsa_upgrades", &vtsa_stats.upgrades);
		registerStatsMetric(name, core->getId(), "vtsa_certs_gran_16k", &vtsa_stats.certs_gran_16k);
		registerStatsMetric(name, core->getId(), "vtsa_certs_gran_64k", &vtsa_stats.certs_gran_64k);
		registerStatsMetric(name, core->getId(), "vtsa_certs_gran_256k", &vtsa_stats.certs_gran_256k);
		registerStatsMetric(name, core->getId(), "vtsa_certs_gran_2m", &vtsa_stats.certs_gran_2m);
		// P1 real fork counters live OS-side (one address-space clone per
		// fork, not per core); register once via core 0.
		if (core->getId() == 0 && Sim()->getMimicOS() != NULL)
		{
			registerStatsMetric(name, 0, "vtsa_fork_real_forks", Sim()->getMimicOS()->vtsaForkRealForksPtr());
			registerStatsMetric(name, 0, "vtsa_fork_real_pages", Sim()->getMimicOS()->vtsaForkRealPagesPtr());
			registerStatsMetric(name, 0, "vtsa_fork_real_skipped_vmas", Sim()->getMimicOS()->vtsaForkRealSkippedPtr());
		}
	}

	void MemoryManagementUnitVTSA::vtsaCountCertGran(UInt64 gran)
	{
		if (gran == (16ull << 10)) vtsa_stats.certs_gran_16k++;
		else if (gran == (64ull << 10)) vtsa_stats.certs_gran_64k++;
		else if (gran == (256ull << 10)) vtsa_stats.certs_gran_256k++;
		else if (gran == (2ull << 20)) vtsa_stats.certs_gran_2m++;
	}

	/* The V-TSA miss-path consult.  Page-table authority is preserved: this
	 * runs strictly AFTER the walk and can only widen the INSTALLED entry,
	 * never change the translation of the faulting access (certificate
	 * contiguity guarantees base_frame + offset == walked PTE).
	 *
	 * hardware_k mode  - bounded largest-feasible probing (the baseline):
	 *   probe sizes largest-first, refuse any needing more than k extra PTE
	 *   probes, charge every probe.  With k<=8 nothing above 16KB is
	 *   feasible: the structural validation ceiling.
	 * auto_certify mode - the certified design, blind-heuristic tier:
	 *   consult RLB/cert table (charged O(1)); on a live cert covering the
	 *   address install at the cert granularity.  Otherwise count the miss
	 *   per 2MB window and at the threshold attempt certification with
	 *   granularity fallback 2MB -> 256KB -> 64KB -> 16KB (validation
	 *   charged per PTE read; publish refusal leaves no state). */
	bool MemoryManagementUnitVTSA::vtsaConsult(IntPtr address, bool count, SubsecondTime &extra_latency, int &out_bits, IntPtr &out_ppn)
	{
		static const int kGranBitsDesc[4] = {21, 18, 16, 14};

		int app_id = core->getThread()->getAppId();
		MimicOS *os = Sim()->getMimicOS();
		vtsa::RadixAddressSpaceView *view = os->getVtsaView(app_id);
		vtsa::CertificateManager *mgr = os->getVtsaCertManager();
		if (!view || !mgr)
			return false;

		if (m_vtsa_mode == VTSA_MODE_HARDWARE_K)
			return vtsaBoundedProbe(view, address, count, extra_latency, out_bits, out_ppn);

		// ---- auto_certify ----
		vtsa::CertRLB::Entry ent;
		bool have_cert = false;
		if (m_vtsa_rlb->lookup(view, (uint64_t)address, *mgr, &ent))
		{
			extra_latency += m_vtsa_cert_check_latency->getLatency();
			if (count) vtsa_stats.cert_checks++;
			have_cert = true;
		}
		else
		{
			vtsa::CertStatus st;
			if (mgr->check(view, (uint64_t)address, &st) == 0)
			{
				extra_latency += m_vtsa_cert_check_latency->getLatency() + m_vtsa_rlb_miss_latency->getLatency();
				if (count) { vtsa_stats.cert_checks++; vtsa_stats.rlb_reloads++; }
				m_vtsa_rlb->insert(view, st);
				ent.va_base = st.va_base; ent.bytes = st.bytes; ent.gran = st.gran;
				ent.id = st.id; ent.version = st.version; ent.as = view;
				have_cert = true;
			}
		}
		if (have_cert)
		{
			// Granularity-upgrade probe: a hit on a below-max certificate
			// periodically re-validates the enclosing larger window (the
			// mosaic left by mid-population certification caps TLB reach;
			// see the citable-rows packet). Publish-first ordering keeps
			// coverage intact on ENOSPC; subsumed certs are then revoked
			// (version bump - stale RLB entries die on the version check;
			// no TLB sweep needed since no frame moved).
			if (m_vtsa_upgrade_interval > 0 && ent.gran < vtsa::kHugeSize &&
			    vtsaTryUpgrade(view, mgr, address, ent, count, extra_latency))
			{
				/* ent now describes the upgraded certificate */
			}
			UInt64 gran = ent.gran;
			IntPtr base = address & ~((IntPtr)gran - 1);
			if ((uint64_t)base >= ent.va_base && (uint64_t)base + gran <= ent.va_base + ent.bytes)
			{
				vtsa::PageInfo pi;
				view->translate(base, pi);
				if (pi.present)
				{
					out_bits = __builtin_ctzll(gran);
					out_ppn = (IntPtr)pi.frame;
					if (count) vtsa_stats.cert_installs++;
					return true;
				}
			}
			return false;
		}

		// certified (hint-gated) mode: the metadata gate decides whether
		// this window may certify at all. Verdict cached per 2MB window;
		// the metadata lookup + region check is charged once per window
		// epoch (tlb_sim.py constants). Disqualified/hint-less windows
		// fall back to nothing (bounded reach comes from the baseline
		// scheme, compared on identical state).
		if (m_vtsa_mode == VTSA_MODE_ADAPTIVE)
		{
			// hint-gated like certified, except COW-marked regions consult
			// the causal estimator instead of statically refusing. Non-COW
			// verdicts cache per window (metadata charged once per epoch,
			// as in tlb_sim); refusals fall back to bounded probing.
			IntPtr ad_window = address >> 21;
			auto adv = m_vtsa_hint_verdict_cache.find(ad_window);
			if (adv != m_vtsa_hint_verdict_cache.end())
			{
				if (!adv->second)
					return vtsaBoundedProbe(view, address, count, extra_latency, out_bits, out_ppn);
				goto adaptive_gate_ok;
			}
			extra_latency += m_vtsa_metadata_latency->getLatency();
			vtsa::HintRegion hr;
			if (!Sim()->getMimicOS()->vtsaHintFor(app_id, (uint64_t)address, &hr))
			{
				if (count) vtsa_stats.hint_absent++;
				m_vtsa_hint_verdict_cache[ad_window] = false;
				return vtsaBoundedProbe(view, address, count, extra_latency, out_bits, out_ppn);
			}
			bool gate_ok;
			if (hr.flags & vtsa::kHintCowSensitive)
			{
				uint32_t flags_ex_cow = hr.flags & ~vtsa::kHintCowSensitive;
				gate_ok = vtsa::hint_qualifies(flags_ex_cow);
				if (gate_ok)
				{
					vtsa::AdaptiveCowEstimator *est = Sim()->getMimicOS()->getVtsaEstimator(
						Sim()->getCfg()->getInt("perf_model/" + name + "/vtsa/estimator_walk_cycles"),
						Sim()->getCfg()->getInt("perf_model/" + name + "/vtsa/cert_check_cycles"),
						Sim()->getCfg()->getInt("perf_model/" + name + "/vtsa/rlb_miss_cycles"));
					gate_ok = est->decide(hr.site_id);
					if (count)
					{
						if (gate_ok) vtsa_stats.adaptive_certifies++;
						else vtsa_stats.adaptive_refusals++;
					}
				}
				else if (count)
					vtsa_stats.hint_disqualified++;
			}
			else
			{
				gate_ok = vtsa::hint_qualifies(hr.flags);
				if (count)
				{
					if (gate_ok) vtsa_stats.hint_qualified++;
					else vtsa_stats.hint_disqualified++;
				}
			}
			if (!(hr.flags & vtsa::kHintCowSensitive))
				m_vtsa_hint_verdict_cache[ad_window] = gate_ok;
			if (!gate_ok)
				return vtsaBoundedProbe(view, address, count, extra_latency, out_bits, out_ppn);
		}
		if (m_vtsa_mode == VTSA_MODE_ADAPTIVE)
		{
adaptive_gate_ok:;
		}
		else if (m_vtsa_mode == VTSA_MODE_CERTIFIED)
		{
			IntPtr hint_window = address >> 21;
			auto hv = m_vtsa_hint_verdict_cache.find(hint_window);
			bool qualified;
			if (hv != m_vtsa_hint_verdict_cache.end())
			{
				qualified = hv->second;
			}
			else
			{
				extra_latency += m_vtsa_metadata_latency->getLatency();
				vtsa::HintRegion hr;
				if (!Sim()->getMimicOS()->vtsaHintFor(app_id, (uint64_t)address, &hr))
				{
					if (count) vtsa_stats.hint_absent++;
					qualified = false;
				}
				else
				{
					qualified = vtsa::hint_qualifies(hr.flags);
					if (count)
					{
						if (qualified) vtsa_stats.hint_qualified++;
						else vtsa_stats.hint_disqualified++;
					}
				}
				m_vtsa_hint_verdict_cache[hint_window] = qualified;
			}
			if (!qualified)
				return vtsaBoundedProbe(view, address, count, extra_latency, out_bits, out_ppn);
		}

		// no cert: blind miss-count heuristic per 2MB window
		if (m_vtsa_cert_table_full)
		{
			// ENOSPC backoff: the OS stops certifying while the table is
			// full; the next revocation (sweep) lifts the backoff.
			if (count) vtsa_stats.certify_backoff++;
			return false;
		}
		UInt64 &window_misses = m_vtsa_window_misses[address >> 21];
		if (count)
			window_misses++;
		if (window_misses < m_vtsa_miss_threshold)
			return false;
		window_misses = 0;
		for (int gi = 0; gi < 4; gi++)
		{
			int bits = kGranBitsDesc[gi];
			if (bits > m_vtsa_max_gran_bits)
				continue; /* ablation cap */
			UInt64 gran = 1ull << bits;
			IntPtr base = address & ~((IntPtr)gran - 1);
			const char *why;
			uint64_t checked = 0;
			int rc = vtsa::CertificateManager::validate_range(view, base, gran, gran, &why, &checked);
			if (count) vtsa_stats.cert_pte_reads += checked;
			if (count && rc != 0) vtsaCountRefusal(why, &vtsa_stats.refuse_absent, &vtsa_stats.refuse_perms, &vtsa_stats.refuse_align, &vtsa_stats.refuse_contig, &vtsa_stats.refuse_geometry);
			extra_latency += m_vtsa_pte_probe_latency->getLatency() * checked;
			if (rc != 0)
				continue;
			int64_t id = mgr->publish(view, base, gran, gran);
			if (id == -ENOSPC)
			{
				m_vtsa_cert_table_full = true;
				return false;
			}
			if (id < 0)
				continue;
			if (count) { vtsa_stats.certifications++; vtsaCountCertGran(gran); }
			vtsa::CertStatus st;
			mgr->get(id, &st);
			m_vtsa_rlb->insert(view, st);
			vtsa::PageInfo pi;
			view->translate(base, pi);
			out_bits = bits;
			out_ppn = (IntPtr)pi.frame;
			if (count) vtsa_stats.cert_installs++;
			return true;
		}
		if (count) vtsa_stats.certify_refusals++;
		return false;
	}



	/* The MMU half of SweepMutatedPage: on any mutation of [va, va+bytes),
	 * drop dependent certificate-RLB entries and shoot down every coalesced
	 * TLB entry that could cover the range; unmap additionally shoots down
	 * the 4KB entries (their pages are gone, not merely re-described).
	 * Promotion does not require 4KB shootdown here: ReserveTHP promotion
	 * is a PTE rewrite with natural-offset placement, so surviving 4KB
	 * entries still translate to the same frames. */
	void MemoryManagementUnitVTSA::vtsaSweep(const vtsa::AddressSpaceView *as, uint64_t va, uint64_t bytes, bool unmap)
	{
		vtsa_stats.sweeps++;
		m_vtsa_cert_table_full = false; /* revocation frees slots */
		m_vtsa_rlb->invalidate_overlap(as, va, bytes);
		for (uint64_t w = va >> 21; w <= (va + bytes - 1) >> 21; w++)
			m_vtsa_hint_verdict_cache.erase((IntPtr)w);

		static const int kSweepBitsCoalesced[4] = {14, 16, 18, 21};
		const TLBSubsystem &levels = tlb_subsystem->getTLBSubsystem();
		for (UInt32 i = 0; i < levels.size(); i++)
		{
			for (UInt32 j = 0; j < levels[i].size(); j++)
			{
				TLB *tlb = levels[i][j];
				for (int gi = 0; gi < 4; gi++)
				{
					int bits = kSweepBitsCoalesced[gi];
					if (!tlb->supportsPageSize(bits))
						continue;
					uint64_t size = 1ull << bits;
					uint64_t start = va & ~(size - 1);
					for (uint64_t a = start; a < va + bytes; a += size)
						if (tlb->invalidate((IntPtr)a, bits))
							vtsa_stats.tlb_shootdowns++;
				}
				if (unmap && tlb->supportsPageSize(12))
				{
					uint64_t start = va & ~((uint64_t)4095);
					for (uint64_t a = start; a < va + bytes; a += 4096)
						if (tlb->invalidate((IntPtr)a, 12))
							vtsa_stats.tlb_shootdowns++;
				}
			}
		}
	}


	/* Bounded largest-feasible probing (the k-budget hardware path).
	 * Also the fallback for metadata-disqualified / hint-less windows in
	 * the certified and adaptive modes - tlb_sim.py's disqualified
	 * regions fell back to bounded best-fit, not to nothing. */
	bool MemoryManagementUnitVTSA::vtsaBoundedProbe(vtsa::RadixAddressSpaceView *view, IntPtr address, bool count, SubsecondTime &extra_latency, int &out_bits, IntPtr &out_ppn)
	{
		static const int kGranBitsDesc[4] = {21, 18, 16, 14};
		for (int gi = 0; gi < 4; gi++)
		{
			int bits = kGranBitsDesc[gi];
			UInt64 size = 1ull << bits;
			UInt64 pages = size >> 12;
			if (pages - 1 > m_vtsa_k_budget)
			{
				if (count) vtsa_stats.bounded_skipped_budget++;
				continue;
			}
			IntPtr base = address & ~((IntPtr)size - 1);
			const char *why;
			uint64_t checked = 0;
			int rc = vtsa::CertificateManager::validate_range(view, base, size, size, &why, &checked);
			if (count) vtsa_stats.probe_pte_reads += checked;
			if (count && rc != 0) vtsaCountRefusal(why, &vtsa_stats.refuse_absent, &vtsa_stats.refuse_perms, &vtsa_stats.refuse_align, &vtsa_stats.refuse_contig, &vtsa_stats.refuse_geometry);
			extra_latency += m_vtsa_pte_probe_latency->getLatency() * checked;
			if (rc == 0)
			{
				vtsa::PageInfo pi;
				view->translate(base, pi);
				out_bits = bits;
				out_ppn = (IntPtr)pi.frame;
				if (count)
				{
					if (bits == 14) vtsa_stats.bounded_installs_16k++;
					else if (bits == 16) vtsa_stats.bounded_installs_64k++;
					else if (bits == 18) vtsa_stats.bounded_installs_256k++;
					else vtsa_stats.bounded_installs_2m++;
				}
				return true;
			}
		}
		return false;
	}


	/* Attempt to upgrade the certificate covering `address` to a larger
	 * granularity.  Throttled per 2MB window (upgrade_probe_interval cert
	 * hits between attempts).  Tries granularities above ent.gran,
	 * largest first; validation charged per PTE read like any
	 * certification.  On success: publish the large cert, retire the
	 * subsumed smaller ones, refresh the RLB, and rewrite `ent`. */
	bool MemoryManagementUnitVTSA::vtsaTryUpgrade(vtsa::RadixAddressSpaceView *view, vtsa::CertificateManager *mgr, IntPtr address, vtsa::CertRLB::Entry &ent, bool count, SubsecondTime &extra_latency)
	{
		static const int kUpGranBitsDesc[4] = {21, 18, 16, 14};

		UInt64 &hits = m_vtsa_upgrade_hits[address >> 21];
		hits++;
		if (hits < m_vtsa_upgrade_interval)
			return false;
		hits = 0;
		/* NOTE: no table-full bail here. Upgrades are the mechanism that
		 * FREES slots (each retires the subsumed smaller certs), so they
		 * must run even - especially - when the table is full; the
		 * full-table path below validates first, then frees, then
		 * publishes. */
		if (count) vtsa_stats.upgrade_probes++;

		for (int gi = 0; gi < 4; gi++)
		{
			int bits = kUpGranBitsDesc[gi];
			if (bits > m_vtsa_max_gran_bits)
				continue; /* ablation cap */
			UInt64 gran = 1ull << bits;
			if (gran <= ent.gran)
				break; /* descending list: nothing larger left */
			IntPtr base = address & ~((IntPtr)gran - 1);
			const char *why;
			uint64_t checked = 0;
			int rc = vtsa::CertificateManager::validate_range(view, base, gran, gran, &why, &checked);
			if (count) vtsa_stats.cert_pte_reads += checked;
			extra_latency += m_vtsa_pte_probe_latency->getLatency() * checked;
			if (rc != 0)
				continue;
			/* publish FIRST so a full table aborts without losing the
			 * existing coverage */
			int64_t id = mgr->publish(view, base, gran, gran);
			if (id == -ENOSPC)
			{
				/* Full table: validation above already proved the window
				 * certifiable, so retiring the subsumed smaller certs
				 * first is safe (frees their slots), then publish into a
				 * freed slot. Deterministic in-sim: no intervening
				 * mutation can invalidate the window between these
				 * steps. */
				mgr->revoke_overlapping_except(view, (uint64_t)base, gran, -1);
				id = mgr->publish(view, base, gran, gran);
				if (id == -ENOSPC)
				{
					m_vtsa_cert_table_full = true;
					return false;
				}
				if (id < 0)
					continue;
				m_vtsa_cert_table_full = false; /* slots freed */
			}
			else if (id < 0)
				continue;
			mgr->revoke_overlapping_except(view, (uint64_t)base, gran, id);
			m_vtsa_rlb->invalidate_overlap(view, (uint64_t)base, gran);
			vtsa::CertStatus st;
			mgr->get(id, &st);
			m_vtsa_rlb->insert(view, st);
			ent.va_base = st.va_base; ent.bytes = st.bytes; ent.gran = st.gran;
			ent.id = st.id; ent.version = st.version; ent.as = view;
			if (count)
			{
				vtsa_stats.upgrades++;
				vtsa_stats.certifications++;
				vtsaCountCertGran(gran);
			}
			return true;
		}
		return false;
	}

} // namespace ParametricDramDirectoryMSI
