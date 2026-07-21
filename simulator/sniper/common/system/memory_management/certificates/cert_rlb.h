/* cert_rlb.h - V-TSA: the region-lookaside buffer of certificates.
 *
 * A small MMU-side cache of certificate descriptors, LRU, fully
 * associative (capacity = rlb_entries, in-repo default 16).  Entries carry
 * FULL certificate identity {address space, va_base, bytes, gran, version,
 * id} - unlike the RMM RLB's bare ranges - so a hit can be verified
 * against the live certificate table and a stale version can never
 * authorize a fill.
 *
 * Cost accounting mirrors simulator/tlb_sim.py: a fill consulting a cached
 * entry charges cert_check cycles; a fill that must reload from the
 * OS-owned table charges rlb_miss cycles on top.  Phase 3's revocation
 * sweep calls invalidate_*() so dependent entries die with their cert.
 */
#pragma once
#include "cert_manager.h"

#include <cstdint>
#include <vector>

namespace vtsa
{

class CertRLB
{
public:
    struct Entry
    {
        const AddressSpaceView *as = nullptr;
        int64_t id = -1;
        uint64_t version = 0;
        uint64_t va_base = 0;
        uint64_t bytes = 0;
        uint64_t gran = 0;
        uint64_t lru = 0;
    };

    struct Stats
    {
        uint64_t accesses = 0;
        uint64_t hits = 0;
        uint64_t misses = 0;
        uint64_t stale_rejects = 0;
    };

    explicit CertRLB(uint64_t entries) : m_capacity(entries) {}

    /* Lookup a cached certificate covering (as, va).  Hit only if the
     * cached version still matches the live cert table (mgr) - a stale
     * entry is dropped and counted, never returned. */
    bool lookup(const AddressSpaceView *as, uint64_t va,
                const CertificateManager &mgr, Entry *out)
    {
        m_stats.accesses++;
        for (size_t i = 0; i < m_entries.size(); i++) {
            Entry &e = m_entries[i];
            if (e.as == as && va >= e.va_base && va < e.va_base + e.bytes) {
                CertStatus live;
                if (mgr.get(e.id, &live) != 0 || !live.live ||
                    live.version != e.version) {
                    m_stats.stale_rejects++;
                    m_entries.erase(m_entries.begin() + i);
                    break; /* fall through to miss */
                }
                e.lru = ++m_clock;
                m_stats.hits++;
                if (out)
                    *out = e;
                return true;
            }
        }
        m_stats.misses++;
        return false;
    }

    void insert(const AddressSpaceView *as, const CertStatus &st)
    {
        Entry e;
        e.as = as;
        e.id = st.id;
        e.version = st.version;
        e.va_base = st.va_base;
        e.bytes = st.bytes;
        e.gran = st.gran;
        e.lru = ++m_clock;
        if (m_entries.size() >= m_capacity) {
            size_t victim = 0;
            for (size_t i = 1; i < m_entries.size(); i++)
                if (m_entries[i].lru < m_entries[victim].lru)
                    victim = i;
            m_entries[victim] = e;
        } else {
            m_entries.push_back(e);
        }
    }

    /* Phase 3 sweep hooks. */
    void invalidate_cert(int64_t id)
    {
        for (size_t i = 0; i < m_entries.size();)
            if (m_entries[i].id == id)
                m_entries.erase(m_entries.begin() + i);
            else
                i++;
    }

    void invalidate_overlap(const AddressSpaceView *as, uint64_t va,
                            uint64_t bytes)
    {
        for (size_t i = 0; i < m_entries.size();)
            if (m_entries[i].as == as && va < m_entries[i].va_base + m_entries[i].bytes &&
                m_entries[i].va_base < va + bytes)
                m_entries.erase(m_entries.begin() + i);
            else
                i++;
    }

    const Stats &stats() const { return m_stats; }
    Stats &mutable_stats() { return m_stats; }

private:
    uint64_t m_capacity;
    uint64_t m_clock = 0;
    std::vector<Entry> m_entries;
    Stats m_stats;
};

} // namespace vtsa
