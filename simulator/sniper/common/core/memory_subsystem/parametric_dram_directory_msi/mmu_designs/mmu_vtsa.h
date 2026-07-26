
#pragma once
#include "../memory_manager.h"
#include "cache_cntlr.h"
#include "subsecond_time.h"
#include "fixed_types.h"
#include "core.h"
#include "shmem_perf_model.h"
#include "pagetable.h"
#include "tlb_subsystem.h"
#include "mmu_base.h"
#include "memory_management/certificates/cert_manager.h"
#include "memory_management/certificates/cert_rlb.h"
#include "memory_management/certificates/radix_address_space_view.h"
#include "memory_management/certificates/mutation_listener.h"
#include "metadata_table_base.h"
#include "ptmshrs.h"
#include "base_filter.h"
#include "sim_log.h"
#include <array>
#include <unordered_map>

namespace ParametricDramDirectoryMSI
{
	
	class TLBHierarchy;

	class MemoryManagementUnitVTSA : public MemoryManagementUnitBase, public vtsa::MutationSweepListener
	{

	private:

		// Backpointer to the memory manager
		MemoryManagerBase *memory_manager;

		// The TLB hierarchy for this MMU - gets instantiated in instantiateTLBSubsystem()
		TLBHierarchy *tlb_subsystem;

		// The metadata table for this MMU - gets instantiated in instantiateMetadataTable()
		// This is useful for ARM-type architectures with tagged memory support
		MetadataTableBase *metadata_table;
		MSHR *pt_walkers; 
		BaseFilter *ptw_filter;

		// Page size prediction-related members
		bool page_size_prediction_enabled;
		SubsecondTime l2_tlb_correct_prediction_latency;
		SubsecondTime l2_tlb_misprediction_latency;


		// Centralized logging
		SimLog *mmu_log;


		// For statistics-based logs 
		std::ofstream translation_latency_log;
		std::ofstream translation_events_log;
		std::ofstream reuse_distance_log;
		std::ofstream ptw_per_page_log;
		std::ofstream use_after_eviction_log;
		std::string translation_latency_log_name;
		std::string translation_events_log_name;
		std::string reuse_distance_log_name;
		std::string ptw_per_page_log_name;
		std::string use_after_eviction_log_name;
		static const SubsecondTime PTW_BUCKET_CHEAP;
		static const SubsecondTime PTW_BUCKET_MID;
		static const SubsecondTime PTW_BUCKET_COSTLY;
		static const std::array<int, 8> LATENCY_GRANULARITY_SHIFTS;
		static const IntPtr PAGE_SHIFT = 12; // 4KB pages


		struct PageMetrics
		{
			SubsecondTime total_translation_latency = SubsecondTime::Zero();
			SubsecondTime tlb_hit_latency = SubsecondTime::Zero();
			SubsecondTime tlb_miss_latency = SubsecondTime::Zero();
			SubsecondTime ptw_latency = SubsecondTime::Zero();
			UInt64 translations = 0;
			UInt64 page_table_walks = 0;
			UInt64 last_access_index = 0;
			bool has_last_access = false;
			UInt64 ptw_latency_buckets[4] = {0, 0, 0, 0}; // cheap, mid, costly, ultra
		};

		struct GranularityMetrics
		{
			SubsecondTime total_translation_latency = SubsecondTime::Zero();
			SubsecondTime tlb_hit_latency = SubsecondTime::Zero();
			SubsecondTime tlb_miss_latency = SubsecondTime::Zero();
			SubsecondTime ptw_latency = SubsecondTime::Zero();
			UInt64 translations = 0;
			UInt64 page_table_walks = 0;
		};

		struct GranularityReuse
		{
			UInt64 last_access_index = 0;
			bool has_last_access = false;
		};

		UInt64 translation_sequence_counter = 0;
		std::unordered_map<UInt64, UInt64> reuse_distance_histogram;
		std::unordered_map<UInt64, SubsecondTime> reuse_distance_latency;
		std::unordered_map<int, std::unordered_map<UInt64, UInt64>> reuse_distance_histogram_granular;
		std::unordered_map<int, std::unordered_map<UInt64, SubsecondTime>> reuse_distance_latency_granular;
		std::unordered_map<int, std::unordered_map<IntPtr, GranularityReuse>> granularity_reuse_state;
		std::unordered_map<IntPtr, PageMetrics> page_metrics;
		std::unordered_map<int, std::unordered_map<IntPtr, GranularityMetrics>> granularity_metrics;
		std::unordered_map<IntPtr, UInt64> last_eviction_index;

		// ====================================================================
		// Translation Sanity Checks (VA-PA consistency)
		// ====================================================================
		// Maps to verify translation consistency:
		// - va_to_pa_map: VA (page-aligned) -> PA (page-aligned), ensures same VA always maps to same PA
		// - pa_to_va_map: PA (page-aligned) -> VA (page-aligned), ensures no two VAs map to same PA
		bool sanity_checks_enabled;  ///< Enable translation sanity checks
		std::unordered_map<IntPtr, IntPtr> va_to_pa_map;  ///< VA -> PA mapping for consistency check
		std::unordered_map<IntPtr, IntPtr> pa_to_va_map;  ///< PA -> VA mapping for uniqueness check
		UInt64 sanity_check_violations;  ///< Count of detected violations



		// Coarse-grained translation statistics

		struct
		{
			UInt64 num_translations;
			UInt64 page_faults;
			UInt64 page_table_walks;
			UInt64 page_size_prediction_hits;
			UInt64 page_size_prediction_misses;
			SubsecondTime total_walk_latency;
			SubsecondTime total_translation_latency;
			SubsecondTime total_tlb_latency;
			SubsecondTime total_fault_latency;
			SubsecondTime walker_is_active;
			SubsecondTime *tlb_latency_per_level;
			UInt64 *tlb_hit_page_sizes;

			// Instruction vs Data breakdown
			UInt64 num_translations_instruction;
			UInt64 num_translations_data;
			UInt64 page_faults_instruction;
			UInt64 page_faults_data;
			UInt64 page_table_walks_instruction;
			UInt64 page_table_walks_data;
			UInt64 tlb_misses_instruction;
			UInt64 tlb_misses_data;
			UInt64 tlb_hits_instruction;
			UInt64 tlb_hits_data;
			SubsecondTime total_walk_latency_instruction;
			SubsecondTime total_walk_latency_data;
			SubsecondTime total_tlb_latency_instruction;
			SubsecondTime total_tlb_latency_data;
			SubsecondTime total_translation_latency_instruction;
			SubsecondTime total_translation_latency_data;

		} translation_stats;


		

		// ================= V-TSA certification layer =================
		enum VtsaMode { VTSA_MODE_OFF = 0, VTSA_MODE_HARDWARE_K, VTSA_MODE_AUTO_CERTIFY, VTSA_MODE_CERTIFIED, VTSA_MODE_ADAPTIVE };
		VtsaMode m_vtsa_mode;
		UInt64 m_vtsa_k_budget;
		/* CoLT-mode baseline: probes limited to the faulting PTE's cache
		 * line (8 PTEs) but UNCHARGED (the walk fetched the line anyway);
		 * installs up to 32KB (15 bits). Baseline realism check vs k4. */
		bool m_vtsa_colt_mode;            // extra-PTE probe budget (bounded baseline)
		UInt64 m_vtsa_miss_threshold;      // misses per 2MB window before auto-certify
		UInt64 m_vtsa_upgrade_interval;    // cert hits per 2MB window between upgrade probes (0 = disabled)
		int m_vtsa_max_gran_bits;          // granularity-ladder cap (ablation knob; 21 = full ladder)
		std::unordered_map<IntPtr, UInt64> m_vtsa_upgrade_hits;  // per-window hits since last probe
		vtsa::CertRLB *m_vtsa_rlb;
		ComponentLatency *m_vtsa_cert_check_latency;
		ComponentLatency *m_vtsa_rlb_miss_latency;
		ComponentLatency *m_vtsa_pte_probe_latency;
		ComponentLatency *m_vtsa_metadata_latency;
		ComponentLatency *m_vtsa_cow_fault_latency;
		ComponentLatency *m_vtsa_cow_copy_latency;
		std::unordered_map<IntPtr, bool> m_vtsa_hint_verdict_cache;
		bool m_vtsa_cert_table_full = false;  // ENOSPC backoff until a revocation frees a slot
		std::unordered_map<IntPtr, UInt64> m_vtsa_window_misses;
		struct {
			UInt64 certifications;
			UInt64 certify_refusals;
			UInt64 cert_installs;
			UInt64 cert_checks;
			UInt64 rlb_reloads;
			UInt64 cert_pte_reads;
			UInt64 probe_pte_reads;
			UInt64 bounded_installs_16k;
			UInt64 bounded_installs_32k;
			UInt64 bounded_installs_64k;
			UInt64 bounded_installs_256k;
			UInt64 bounded_installs_2m;
			UInt64 bounded_skipped_budget;
			UInt64 refuse_absent;
			UInt64 refuse_perms;
			UInt64 refuse_align;
			UInt64 refuse_contig;
			UInt64 refuse_geometry;
			UInt64 sweeps;
			UInt64 tlb_shootdowns;
			UInt64 hint_qualified;
			UInt64 hint_disqualified;
			UInt64 hint_absent;
			UInt64 cow_faults;
			UInt64 cow_copies;
			UInt64 cow_read_suppressed;
			UInt64 adaptive_certifies;
			UInt64 adaptive_refusals;
			UInt64 certify_backoff;
			UInt64 upgrade_probes;
			UInt64 upgrades;
			UInt64 certs_gran_16k;
			UInt64 certs_gran_64k;
			UInt64 certs_gran_256k;
			UInt64 certs_gran_2m;
		} vtsa_stats;
		void registerVTSAStats();
		bool vtsaConsult(IntPtr address, bool count, SubsecondTime &extra_latency, int &out_bits, IntPtr &out_ppn);
		bool vtsaBoundedProbe(vtsa::RadixAddressSpaceView *view, IntPtr address, bool count, SubsecondTime &extra_latency, int &out_bits, IntPtr &out_ppn);
		bool vtsaTryUpgrade(vtsa::RadixAddressSpaceView *view, vtsa::CertificateManager *mgr, IntPtr address, vtsa::CertRLB::Entry &ent, bool count, SubsecondTime &extra_latency);
		void vtsaCountCertGran(UInt64 gran);
		void vtsaSweep(const vtsa::AddressSpaceView *as, uint64_t va, uint64_t bytes, bool unmap) override;

	public:
		MemoryManagementUnitVTSA(Core *core, MemoryManagerBase *memory_manager, ShmemPerfModel *shmem_perf_model, String name, MemoryManagementUnitBase *nested_mmu);
		~MemoryManagementUnitVTSA();

		// MMU initialization helpers
		void instantiatePageTableWalker();
		void instantiateMetadataTable();
		void instantiateTLBSubsystem();
		void registerMMUStats();
		void discoverVMAs();
		
		// Translation helpers
		BaseFilter *getPTWFilter() override { return ptw_filter; }
		PTWResult filterPTWResult(IntPtr virtual_address, PTWResult ptw_result, PageTable *page_table, bool count);
		IntPtr performAddressTranslation(IntPtr eip, IntPtr virtual_address, bool instruction, Core::lock_signal_t lock, bool modeled, bool count);
		
		// Per-page translation metrics
		void updatePageMetrics(IntPtr virtual_address, SubsecondTime translation_latency, bool performed_ptw, SubsecondTime translation_start_time, UInt64 translation_index, SubsecondTime walk_latency, SubsecondTime tlb_hit_latency, SubsecondTime tlb_miss_latency);
		void dumpPerPageLogs();
		void initializePerPageLogs();
	};

}
