//! Local storage: every record is kept as JSON in SQLite (WAL mode). Raw records are
//! kept for a week; hourly min/avg/max summaries for 90 days (section 10).

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context;
use netprobe_core::Record;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

pub const HOUR_MS: i64 = 3_600_000;
pub const DAY_MS: i64 = 24 * HOUR_MS;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS measurements (
    id         TEXT PRIMARY KEY,
    ts_ms      INTEGER NOT NULL,
    probe      TEXT NOT NULL,
    target     TEXT,
    network_id TEXT,
    data       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS measurements_probe_ts ON measurements(probe, ts_ms);
CREATE INDEX IF NOT EXISTS measurements_ts ON measurements(ts_ms);
CREATE TABLE IF NOT EXISTS hourly (
    hour_ms INTEGER NOT NULL,
    probe   TEXT NOT NULL,
    target  TEXT NOT NULL,
    metric  TEXT NOT NULL,
    count   INTEGER NOT NULL,
    min     REAL NOT NULL,
    avg     REAL NOT NULL,
    max     REAL NOT NULL,
    PRIMARY KEY (hour_ms, probe, target, metric)
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
";

pub struct Store {
    conn: Connection,
}

#[derive(Debug, Clone, Default)]
pub struct RecordQuery<'a> {
    pub probe: Option<&'a str>,
    pub target: Option<&'a str>,
    pub since_ms: Option<i64>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct HourlyRow {
    pub hour_ms: i64,
    pub probe: String,
    pub target: String,
    pub metric: String,
    pub count: u32,
    pub min: f64,
    pub avg: f64,
    pub max: f64,
}

impl Store {
    /// Opens (creating if needed) the database for writing.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("open {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Opens an existing database owned by another user (the service account).
    pub fn open_read_only(path: &Path) -> anyhow::Result<Self> {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        if let Ok(conn) = Connection::open_with_flags(path, flags)
            && conn.query_row("SELECT count(*) FROM measurements", [], |_| Ok(())).is_ok()
        {
            conn.busy_timeout(std::time::Duration::from_secs(5))?;
            return Ok(Self { conn });
        }
        // WAL readers need the -shm file; when the service is stopped it is gone and a
        // reader without write access to the directory cannot create it
        let uri = format!("file:{}?immutable=1", path.display());
        let conn = Connection::open_with_flags(uri, flags | OpenFlags::SQLITE_OPEN_URI)
            .with_context(|| format!("open {}", path.display()))?;
        Ok(Self { conn })
    }

    pub fn insert_all(&mut self, records: &[Record]) -> anyhow::Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT OR IGNORE INTO measurements (id, ts_ms, probe, target, network_id, data)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for r in records {
                stmt.execute(params![
                    r.id,
                    ts_ms(r),
                    r.probe(),
                    r.target,
                    r.network_id,
                    serde_json::to_string(r)?
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Records matching `q`, newest first.
    pub fn query(&self, q: &RecordQuery<'_>) -> anyhow::Result<Vec<Record>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT data FROM measurements
             WHERE (?1 IS NULL OR probe = ?1) AND (?2 IS NULL OR target = ?2) AND ts_ms >= ?3
             ORDER BY ts_ms DESC LIMIT ?4",
        )?;
        let limit = q.limit.map_or(-1, |l| l as i64);
        let rows = stmt.query_map(params![q.probe, q.target, q.since_ms.unwrap_or(0), limit], |row| {
            row.get::<_, String>(0)
        })?;
        let mut out = Vec::new();
        for json in rows {
            match serde_json::from_str(&json?) {
                Ok(r) => out.push(r),
                Err(e) => eprintln!("skipping unreadable record: {e}"),
            }
        }
        Ok(out)
    }

    pub fn last_ts_ms(&self, probe: &str) -> anyhow::Result<Option<i64>> {
        Ok(self.conn.query_row("SELECT MAX(ts_ms) FROM measurements WHERE probe = ?1", [probe], |r| r.get(0))?)
    }

    /// Bytes used by speed tests since `since_ms`, for the daily data budget.
    pub fn throughput_bytes_since(&self, since_ms: i64) -> anyhow::Result<u64> {
        let total: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(json_extract(data, '$.bytes_total')), 0)
             FROM measurements WHERE probe = 'throughput' AND ts_ms >= ?1",
            [since_ms],
            |r| r.get(0),
        )?;
        Ok(total.max(0) as u64)
    }

    /// Summarizes every complete hour that has not been summarized yet.
    pub fn rollup(&mut self, now_ms: i64) -> anyhow::Result<usize> {
        let current_hour = now_ms - now_ms.rem_euclid(HOUR_MS);
        let done: Option<i64> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key = 'rollup_until'", [], |r| r.get::<_, String>(0))
            .optional()?
            .and_then(|v| v.parse().ok());
        let first = match done {
            Some(d) => d,
            None => match self.conn.query_row("SELECT MIN(ts_ms) FROM measurements", [], |r| r.get::<_, Option<i64>>(0))? {
                Some(min) => min - min.rem_euclid(HOUR_MS),
                None => return Ok(0),
            },
        };
        let tx = self.conn.transaction()?;
        let mut rows = 0;
        let mut hour = first;
        while hour < current_hour {
            let mut stmt = tx.prepare_cached("SELECT data FROM measurements WHERE ts_ms >= ?1 AND ts_ms < ?2")?;
            let records: Vec<Record> = stmt
                .query_map([hour, hour + HOUR_MS], |r| r.get::<_, String>(0))?
                .filter_map(|j| serde_json::from_str(&j.ok()?).ok())
                .collect();
            for row in summarize_hour(hour, &records) {
                tx.execute(
                    "INSERT OR REPLACE INTO hourly (hour_ms, probe, target, metric, count, min, avg, max)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![row.hour_ms, row.probe, row.target, row.metric, row.count, row.min, row.avg, row.max],
                )?;
                rows += 1;
            }
            hour += HOUR_MS;
        }
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('rollup_until', ?1)",
            [current_hour.max(first).to_string()],
        )?;
        tx.commit()?;
        Ok(rows)
    }

    /// Deletes raw records and hourly summaries past their retention.
    pub fn prune(&self, now_ms: i64, raw_days: u32, hourly_days: u32) -> anyhow::Result<(usize, usize)> {
        let raw = self
            .conn
            .execute("DELETE FROM measurements WHERE ts_ms < ?1", [now_ms - i64::from(raw_days) * DAY_MS])?;
        let hourly = self
            .conn
            .execute("DELETE FROM hourly WHERE hour_ms < ?1", [now_ms - i64::from(hourly_days) * DAY_MS])?;
        Ok((raw, hourly))
    }

    pub fn hourly(&self, probe: Option<&str>, since_ms: i64) -> anyhow::Result<Vec<HourlyRow>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT hour_ms, probe, target, metric, count, min, avg, max FROM hourly
             WHERE (?1 IS NULL OR probe = ?1) AND hour_ms >= ?2
             ORDER BY hour_ms DESC, probe, target, metric",
        )?;
        let rows = stmt.query_map(params![probe, since_ms], |r| {
            Ok(HourlyRow {
                hour_ms: r.get(0)?,
                probe: r.get(1)?,
                target: r.get(2)?,
                metric: r.get(3)?,
                count: r.get(4)?,
                min: r.get(5)?,
                avg: r.get(6)?,
                max: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

pub fn ts_ms(r: &Record) -> i64 {
    (r.ts.unix_timestamp_nanos() / 1_000_000) as i64
}

fn summarize_hour(hour_ms: i64, records: &[Record]) -> Vec<HourlyRow> {
    #[derive(Default)]
    struct Agg {
        count: u32,
        min: f64,
        max: f64,
        sum: f64,
    }
    let mut groups: BTreeMap<(&str, String, &str), Agg> = BTreeMap::new();
    for r in records {
        for (metric, v) in r.metrics() {
            let a = groups.entry((r.probe(), r.target.clone().unwrap_or_default(), metric)).or_default();
            if a.count == 0 {
                a.min = v;
                a.max = v;
            }
            a.count += 1;
            a.min = a.min.min(v);
            a.max = a.max.max(v);
            a.sum += v;
        }
    }
    groups
        .into_iter()
        .map(|((probe, target, metric), a)| HourlyRow {
            hour_ms,
            probe: probe.to_string(),
            target,
            metric: metric.to_string(),
            count: a.count,
            min: a.min,
            avg: netprobe_core::stats::round2(a.sum / f64::from(a.count)),
            max: a.max,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use netprobe_core::model::{Loss, LatencyData, ProbeData, RttStats, ThroughputData};
    use time::OffsetDateTime;

    fn latency(id: &str, ts_ms: i64, median: f64) -> Record {
        Record {
            id: id.into(),
            agent_id: "a".into(),
            ts: OffsetDateTime::from_unix_timestamp_nanos(i128::from(ts_ms) * 1_000_000).unwrap(),
            platform: "test".into(),
            network_id: None,
            iface: None,
            target: Some("1.1.1.1".into()),
            data: ProbeData::Latency(LatencyData {
                addr: "1.1.1.1".into(),
                method: "icmp".into(),
                sent: 20,
                received: 20,
                late: 0,
                duplicates: 0,
                rtt_ms: Some(RttStats { min: median, median, p95: median, max: median }),
                jitter_ms: None,
                loss_pct: Loss { total: 0.0, up: None, down: None },
            }),
            flags: vec![],
        }
    }

    fn temp_db() -> (tempdir::Dir, Store) {
        let dir = tempdir::Dir::new();
        let store = Store::open(&dir.path.join("t.db")).unwrap();
        (dir, store)
    }

    #[test]
    fn insert_query_and_dedupe() {
        let (_d, mut s) = temp_db();
        let r = latency("1", 1_000, 10.0);
        s.insert_all(&[r.clone(), r]).unwrap();
        s.insert_all(&[latency("2", 2_000, 20.0)]).unwrap();
        let all = s.query(&RecordQuery { probe: Some("latency"), ..Default::default() }).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, "2", "newest first");
        assert_eq!(s.last_ts_ms("latency").unwrap(), Some(2_000));
        assert_eq!(s.last_ts_ms("dns").unwrap(), None);
    }

    #[test]
    fn rollup_summarizes_complete_hours_once() {
        let (_d, mut s) = temp_db();
        let h0 = 10 * HOUR_MS;
        s.insert_all(&[latency("1", h0 + 5, 10.0), latency("2", h0 + 10, 30.0), latency("3", h0 + HOUR_MS + 1, 99.0)])
            .unwrap();
        s.rollup(h0 + HOUR_MS + 100).unwrap();
        let rows = s.hourly(Some("latency"), 0).unwrap();
        let median = rows.iter().find(|r| r.metric == "rtt_median_ms").unwrap();
        assert_eq!((median.hour_ms, median.count, median.min, median.avg, median.max), (h0, 2, 10.0, 20.0, 30.0));
        // the current hour is not summarized yet, and a second run adds nothing
        assert!(rows.iter().all(|r| r.hour_ms == h0));
        assert_eq!(s.rollup(h0 + HOUR_MS + 200).unwrap(), 0);
    }

    #[test]
    fn prune_and_budget() {
        let (_d, mut s) = temp_db();
        let now = 30 * DAY_MS;
        let mut t = latency("t", now - HOUR_MS, 0.0);
        t.data = ProbeData::Throughput(ThroughputData { bytes_total: 120_000_000, ..Default::default() });
        s.insert_all(&[latency("old", now - 8 * DAY_MS, 1.0), t]).unwrap();
        assert_eq!(s.throughput_bytes_since(now - DAY_MS).unwrap(), 120_000_000);
        assert_eq!(s.prune(now, 7, 90).unwrap().0, 1);
    }

    #[test]
    fn read_only_open_sees_data() {
        let (d, mut s) = temp_db();
        s.insert_all(&[latency("1", 1_000, 10.0)]).unwrap();
        let ro = Store::open_read_only(&d.path.join("t.db")).unwrap();
        assert_eq!(ro.query(&RecordQuery::default()).unwrap().len(), 1);
    }

    /// Minimal temp directory helper to avoid a dev-dependency.
    mod tempdir {
        pub struct Dir {
            pub path: std::path::PathBuf,
        }
        impl Dir {
            pub fn new() -> Self {
                let path = std::env::temp_dir().join(format!("netprobe-test-{}", ulid_like()));
                std::fs::create_dir_all(&path).unwrap();
                Self { path }
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
        fn ulid_like() -> String {
            let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            format!("{n}-{:?}", std::thread::current().id()).replace(['(', ')'], "")
        }
    }
}
