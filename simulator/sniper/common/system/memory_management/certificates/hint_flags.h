/* hint_flags.h - V-TSA: compiler-hint flag encoding and the metadata gate.
 *
 * Bit encoding of the region-descriptor flag vocabulary from the v-tsa
 * pipeline (simulator/tlb_sim.py flag strings), carried from the traced
 * binary via SimUser magic ops.  hint_qualifies() is the verbatim port of
 * tlb_sim.py::certification_metadata_qualifies:
 *   - DENSE required
 *   - any of {SPARSE, NO_COALESCE, SHARED_SENSITIVE, COW_SENSITIVE} refuses
 *   - DEMAND_FRAGMENTED regions additionally need a reuse flag
 *     {HOT, REUSE_LIKELY, PHASE_LOCAL}
 * Metadata is a hint: qualifying only *permits* certification, whose
 * validation still runs against the page tables (the authority).
 */
#pragma once
#include <cstdint>

namespace vtsa
{

enum HintFlag : uint32_t
{
    kHintDense           = 1u << 0,
    kHintSparse          = 1u << 1,
    kHintNoCoalesce      = 1u << 2,
    kHintSharedSensitive = 1u << 3,
    kHintCowSensitive    = 1u << 4,
    kHintHot             = 1u << 5,
    kHintReuseLikely     = 1u << 6,
    kHintPhaseLocal      = 1u << 7,
    kHintDemandFragmented= 1u << 8,
};

constexpr uint32_t kHintForbiddenMask =
    kHintSparse | kHintNoCoalesce | kHintSharedSensitive | kHintCowSensitive;
constexpr uint32_t kHintReuseMask =
    kHintHot | kHintReuseLikely | kHintPhaseLocal;

inline bool hint_qualifies(uint32_t flags)
{
    if (!(flags & kHintDense))
        return false;
    if (flags & kHintForbiddenMask)
        return false;
    if ((flags & kHintDemandFragmented) && !(flags & kHintReuseMask))
        return false;
    return true;
}

/* Magic-op command space (SimUser arg0).  arg1 = pointer, in traced-app
 * memory, to the packed descriptor the backend reads via accessMemory. */
enum HintMagicCmd : uint64_t
{
    kVtsaCmdRegionRegister   = 0x75A0, /* {u64 base, len, flags, site_id} */
    kVtsaCmdRegionUnregister = 0x75A1, /* {u64 base, len}                 */
    kVtsaCmdMprotect         = 0x75A2, /* {u64 base, len, perms}          */
};

struct HintRegion
{
    uint64_t base = 0;
    uint64_t len = 0;
    uint32_t flags = 0;
    uint64_t site_id = 0;
};

} // namespace vtsa
