
#pragma once
#include "pagetable.h"
#include "sim_log.h"
#include <functional>

namespace ParametricDramDirectoryMSI
{

	class PageTableRadix : public PageTable
	{

	private:
		struct PTFrame;

		struct PTE
		{
			bool valid; // Valid bit
			IntPtr ppn; // Physical page number
		};

	
		struct PTEntry
		{
			bool is_pte; // Whether the entry is a PTE or a pointer to the next level of the page table
			union
			{
				PTE translation;
				PTFrame *next_level;
			} data; // Stores whether the entry is a PTE or a pointer to the next level of the page table
		};

		struct PTFrame
		{
			PTEntry *entries;	 // 512 entries, 4KB page table frames
			IntPtr emulated_ppn; // Address of the frame in the physical memory (this is emulated)
		};

		typedef struct PTFrame PT;

		PT *root;		  // Root of the radix tree
		int m_frame_size; // Size of the frame in bytes
		int levels;		  // Number of levels in the radix tree

		// We use 3 page walk caches, one for the first three levels of the radix tree

		SimLog* m_log;    // Logging instance for the page table

		struct Stats
		{
			UInt64 page_table_walks;
			UInt64 ptw_num_cache_accesses; // Number of cache accesses for page table walks
			UInt64 pf_num_cache_accesses;  // Number of cache accesses for page faults
			UInt64 page_faults;
			UInt64 *page_size_discovery; // Number of times each page size is discovered
			UInt64 allocated_frames;	 // Number of frames allocated for the page table
		} stats;

	public:
		PageTableRadix(int core_id, String name, String type, int page_sizes, int *page_size_list, int levels, int frame_size, bool is_guest = false);
		~PageTableRadix();
		PTWResult initializeWalk(IntPtr address, bool count, bool is_prefetch = false, bool restart_walk = false);
		bool functionalLookup(IntPtr address, IntPtr *ppn, int *page_size) override;
		/* V-TSA fork support: invoke cb(va, ppn, page_size_bits) for every
		 * valid leaf mapping (page_size_bits 12 or 21; ppn is always
		 * 4KB-granular). Functional walk - no timing, no stats. */
		void enumerateMappings(const std::function<void(IntPtr, IntPtr, int)> &cb);
		int updatePageTableFrames(IntPtr address, IntPtr core_id, IntPtr ppn, int page_size, std::vector<UInt64> frames);
		void deletePage(IntPtr address);
		IntPtr getPhysicalSpace(int size);
	private:
		void enumerateFrame(PTFrame *frame, IntPtr va_base, int depth,
		                    const std::function<void(IntPtr, IntPtr, int)> &cb);
	public:
		String getType() { return "radix"; };
		int getMaxLevel() { return levels; };
	};
}