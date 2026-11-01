//! Formulas from section 4 of the plan: percentiles, jitter, loss and counter deltas.

use crate::model::RttStats;

/// Sorts a copy of `values` in ascending order.
pub fn sorted(values: &[f64]) -> Vec<f64> {
    let mut v = values.to_vec();
    v.sort_by(f64::total_cmp);
    v
}

/// Linear-interpolated percentile of an already sorted slice, `p` in 0..=100.
pub fn percentile_sorted(sorted: &[f64], p: f64) -> Option<f64> {
    match sorted.len() {
        0 => None,
        1 => Some(sorted[0]),
        n => {
            let rank = (p / 100.0).clamp(0.0, 1.0) * (n - 1) as f64;
            let lo = rank.floor() as usize;
            let hi = rank.ceil() as usize;
            Some(sorted[lo] + (sorted[hi] - sorted[lo]) * (rank - lo as f64))
        }
    }
}

pub fn percentile(values: &[f64], p: f64) -> Option<f64> {
    percentile_sorted(&sorted(values), p)
}

pub fn median(values: &[f64]) -> Option<f64> {
    percentile(values, 50.0)
}

pub fn mean(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().sum::<f64>() / values.len() as f64)
    }
}

pub fn std_dev(values: &[f64]) -> Option<f64> {
    let m = mean(values)?;
    let var = values.iter().map(|v| (v - m).powi(2)).sum::<f64>() / values.len() as f64;
    Some(var.sqrt())
}

/// min / median / p95 / max of a set of RTTs in milliseconds.
pub fn rtt_stats(values: &[f64]) -> Option<RttStats> {
    let s = sorted(values);
    Some(RttStats {
        min: round2(*s.first()?),
        median: round2(percentile_sorted(&s, 50.0)?),
        p95: round2(percentile_sorted(&s, 95.0)?),
        max: round2(*s.last()?),
    })
}

/// Mean absolute difference between consecutive RTTs (the jitter most speed tests report).
/// `rtts` must be in send order; lost packets are simply absent.
pub fn jitter_ipdv(rtts: &[f64]) -> Option<f64> {
    if rtts.len() < 2 {
        return None;
    }
    let sum: f64 = rtts.windows(2).map(|w| (w[1] - w[0]).abs()).sum();
    Some(sum / (rtts.len() - 1) as f64)
}

/// RFC 3550 interarrival jitter estimator applied to RTTs: J += (|D| - J) / 16.
pub fn jitter_rfc3550(rtts: &[f64]) -> Option<f64> {
    if rtts.len() < 2 {
        return None;
    }
    let mut j = 0.0;
    for w in rtts.windows(2) {
        j += ((w[1] - w[0]).abs() - j) / 16.0;
    }
    Some(j)
}

pub fn loss_pct(sent: u32, received: u32) -> f64 {
    if sent == 0 {
        return 0.0;
    }
    f64::from(sent.saturating_sub(received)) / f64::from(sent) * 100.0
}

/// `num / den * 100`, or `None` when the denominator is zero.
pub fn ratio_pct(num: f64, den: f64) -> Option<f64> {
    (den > 0.0).then(|| num / den * 100.0)
}

/// Difference between two readings of a counter that wraps at `bits` width.
pub fn counter_delta(prev: u64, cur: u64, bits: u32) -> u64 {
    if cur >= prev {
        cur - prev
    } else if bits >= 64 {
        cur.wrapping_sub(prev)
    } else {
        (1u64 << bits) - prev + cur
    }
}

pub fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_interpolates() {
        let v = [10.0, 20.0, 30.0, 40.0];
        assert_eq!(percentile(&v, 0.0), Some(10.0));
        assert_eq!(percentile(&v, 100.0), Some(40.0));
        assert_eq!(percentile(&v, 50.0), Some(25.0));
        assert_eq!(percentile(&[7.0], 95.0), Some(7.0));
        assert_eq!(percentile(&[], 50.0), None);
    }

    #[test]
    fn percentile_ignores_input_order() {
        assert_eq!(median(&[3.0, 1.0, 2.0]), Some(2.0));
    }

    #[test]
    fn jitter_is_mean_abs_diff() {
        // diffs: 10, 5, 15 -> mean 10
        let rtts = [20.0, 30.0, 25.0, 40.0];
        assert_eq!(jitter_ipdv(&rtts), Some(10.0));
        assert_eq!(jitter_ipdv(&[20.0]), None);
    }

    #[test]
    fn jitter_constant_rtt_is_zero() {
        let rtts = [15.0; 20];
        assert_eq!(jitter_ipdv(&rtts), Some(0.0));
        assert_eq!(jitter_rfc3550(&rtts), Some(0.0));
    }

    #[test]
    fn rfc3550_smooths() {
        let j = jitter_rfc3550(&[10.0, 26.0]).unwrap();
        assert!((j - 1.0).abs() < 1e-9);
    }

    #[test]
    fn loss_counts_missing_packets() {
        assert_eq!(loss_pct(20, 19), 5.0);
        assert_eq!(loss_pct(20, 20), 0.0);
        assert_eq!(loss_pct(0, 0), 0.0);
        // duplicates must never push loss below zero
        assert_eq!(loss_pct(20, 22), 0.0);
    }

    #[test]
    fn counter_wraps_at_32_bits() {
        assert_eq!(counter_delta(100, 150, 32), 50);
        assert_eq!(counter_delta(u32::MAX as u64 - 9, 5, 32), 15);
        assert_eq!(counter_delta(10, 3, 64), u64::MAX - 6);
    }

    #[test]
    fn rtt_stats_rounds() {
        let s = rtt_stats(&[1.234, 2.0, 3.0]).unwrap();
        assert_eq!(s.min, 1.23);
        assert_eq!(s.median, 2.0);
        assert_eq!(s.max, 3.0);
    }
}
