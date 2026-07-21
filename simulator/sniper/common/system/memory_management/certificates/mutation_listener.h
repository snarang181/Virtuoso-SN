/* mutation_listener.h - V-TSA: the sweep half of SweepMutatedPage.
 *
 * The certificate manager revokes descriptors on mutation (the OS half);
 * a real simulated TLB additionally requires dependent TLB/RLB entries to
 * die before the next hit (the MMU half, which ukern's check-time guard
 * only emulated).  MMU designs register themselves with MimicOS; every
 * mutation entry point (promotion, munmap, mprotect, later fork/COW) calls
 * CertificateManager::on_mutation FIRST, then fans out to the registered
 * listeners so each core's TLB hierarchy and certificate RLB are swept.
 */
#pragma once
#include "address_space_view.h"

namespace vtsa
{

class MutationSweepListener
{
public:
    virtual ~MutationSweepListener() = default;

    /* Invalidate all coalesced TLB entries and RLB entries dependent on
     * [va, va+bytes) of the given address space.  `unmap` additionally
     * requires 4KB-entry shootdown (the pages are gone, not just
     * re-described). */
    virtual void vtsaSweep(const AddressSpaceView *as, uint64_t va,
                           uint64_t bytes, bool unmap) = 0;
};

} // namespace vtsa
