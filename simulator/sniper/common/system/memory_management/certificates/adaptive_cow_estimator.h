/* adaptive_cow_estimator.h - V-TSA: the adaptive certification gate.
 *
 * Port of simulator/tlb_sim.py::AdaptiveCowEstimator (v-tsa repo).  For a
 * COW-marked region the static metadata gate's refusal is replaced by a
 * causal cost estimator:
 *
 *   reach_benefit_rate = page_walk_cycles - cert_check_cycles   (per access)
 *   recert_cost        = page_walk_cycles + cert_check_cycles + rlb_miss
 *   CERTIFY  iff  predicted_interval * reach_benefit_rate > recert_cost
 *
 * where predicted_interval is the mean of the last K=4 observed
 * inter-revocation intervals measured in region-accesses (the causal
 * clock).  Epoch 0 (never revoked) certifies optimistically.  With the
 * charged-constants costs (180/2/20) the threshold is 202/178 ~= 1.1348
 * accesses - DERIVED from the cost constants, never fitted to results.
 *
 * Causality: decisions use only past events; same-clock revocations
 * coalesce into one event (a single mutation sweeping many certs is one
 * eviction of reach, not many).
 */
#pragma once
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace vtsa
{

class AdaptiveCowEstimator
{
public:
    static constexpr int kIntervalWindowK = 4;

    AdaptiveCowEstimator(uint64_t page_walk_cycles, uint64_t cert_check_cycles,
                         uint64_t rlb_miss_cycles)
        : m_reach_benefit_rate(page_walk_cycles - cert_check_cycles),
          m_recert_cost(page_walk_cycles + cert_check_cycles +
                        rlb_miss_cycles)
    {
    }

    void note_access(uint64_t region_key) { m_slots[region_key].accesses++; }

    /* One revocation event over [va, va+bytes) at the current causal
     * clock of each overlapping region key (keys are range-based:
     * caller passes each affected region key). */
    void observe_revocation(uint64_t region_key)
    {
        Slot &s = m_slots[region_key];
        if (s.revocations > 0 && s.last_revocation_clock == s.accesses) {
            s.coalesced_same_clock++;
            return;
        }
        if (s.revocations > 0)
            push_interval(s, s.accesses - s.last_revocation_clock);
        else if (s.accesses > 0)
            push_interval(s, s.accesses);
        s.last_revocation_clock = s.accesses;
        s.revocations++;
    }

    /* The gate: certify or refuse, epoch-cached. */
    bool decide(uint64_t region_key)
    {
        Slot &s = m_slots[region_key];
        if (s.answer_epoch == s.revocations && s.decided)
            return s.answer;
        s.decided = true;
        s.answer_epoch = s.revocations;
        if (s.revocations == 0) {
            s.answer = true; /* optimistic start */
        } else {
            uint64_t sum = 0;
            for (uint64_t v : s.intervals)
                sum += v;
            double predicted =
                s.intervals.empty()
                    ? 0.0
                    : (double)sum / (double)s.intervals.size();
            s.answer = predicted * (double)m_reach_benefit_rate >
                       (double)m_recert_cost;
        }
        return s.answer;
    }

    double certify_threshold_accesses() const
    {
        return (double)m_recert_cost / (double)m_reach_benefit_rate;
    }

    struct Slot
    {
        uint64_t accesses = 0;
        uint64_t revocations = 0;
        uint64_t coalesced_same_clock = 0;
        uint64_t last_revocation_clock = 0;
        std::vector<uint64_t> intervals;
        bool decided = false;
        bool answer = false;
        uint64_t answer_epoch = 0;
    };

    const Slot *slot(uint64_t region_key) const
    {
        auto it = m_slots.find(region_key);
        return it == m_slots.end() ? nullptr : &it->second;
    }

private:
    void push_interval(Slot &s, uint64_t interval)
    {
        s.intervals.push_back(interval);
        if (s.intervals.size() > kIntervalWindowK)
            s.intervals.erase(s.intervals.begin());
    }

    uint64_t m_reach_benefit_rate;
    uint64_t m_recert_cost;
    std::unordered_map<uint64_t, Slot> m_slots;
};

} // namespace vtsa
