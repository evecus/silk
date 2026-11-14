//! [方案五/六] 用户态流表 janitor + per-CPU 统计聚合。
//!
//! 对应 honk 的 `control/janitor.rs` 与 `stats.rs` 用户态侧。每 30 s 在
//! `spawn_blocking` 里做两件事：
//!   1. 扫 FLOW_TRACK 的 key，把 `last_seen_ns` 超过 120 s 的条目删掉。
//!      内核侧换成普通 HashMap 后不再有静默 LRU 驱逐，回收责任明确归
//!      用户态；长连接因为有节流刷新不会被误删。
//!   2. 读 DATAPATH_STATS 的各 CPU 槽位求和，输出一条累计统计日志。
//!
//! 时钟基准必须与内核的 `bpf_ktime_get_ns()` 一致，所以这里用
//! `CLOCK_MONOTONIC`（不是 `Instant`，也不是墙钟）。

use crate::rules::StaticMaps;
use aya::maps::{MapData, PerCpuArray};
use silk_ebpf_common::{FlowKey, StatsCounters, FLOW_TRACK_IDLE_NS};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify};

const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// 启动维护任务。`stop` 由主流程在退出时通知，避免 janitor 晚于清理。
pub fn spawn(maps: Arc<Mutex<StaticMaps>>, stop: Arc<Notify>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            let stopping = tokio::select! {
                _ = tick.tick() => false,
                _ = stop.notified() => true,
            };
            if stopping {
                break;
            }
            let task_maps = maps.clone();
            match tokio::task::spawn_blocking(move || sweep(&task_maps)).await {
                Ok((removed, alive, s, temp_fail)) => {
                    tracing::info!(
                        removed,
                        alive,
                        temp_fail,
                        direct_pkts = s.direct_pkts,
                        direct_bytes = s.direct_bytes,
                        proxy_pkts = s.proxy_pkts,
                        proxy_bytes = s.proxy_bytes,
                        reply_pkts = s.reply_pkts,
                        reply_bytes = s.reply_bytes,
                        block_pkts = s.block_pkts,
                        frag_inherited = s.frag_inherited,
                        new_flow_limited = s.new_flow_limited,
                        "flow janitor / datapath stats"
                    );
                }
                Err(e) => tracing::warn!(error = %e, "janitor task join failed"),
            }
        }
    })
}

/// 单调时钟纳秒，与 `bpf_ktime_get_ns()` 同一基准。
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

/// 一次扫描。返回 (删除数, 存活数, 统计聚合, 时钟失败标志)。
fn sweep(maps: &Arc<Mutex<StaticMaps>>) -> (usize, usize, StatsCounters, bool) {
    let now = monotonic_ns();
    let temp_fail = now == 0;
    // 控制面用的是 tokio 的异步 Mutex；spawn_blocking 的线程上要用
    // blocking_lock()，在 async 上下文里调用它会 panic。
    let mut guard = maps.blocking_lock();

    // 先收集 key：`keys()` 借的是不可变引用，不能与后面的 remove 同时持有。
    let keys: Vec<FlowKey> = guard
        .flow_track
        .keys()
        .filter_map(Result::ok)
        .collect();

    let mut removed = 0usize;
    if !temp_fail {
        for key in &keys {
            match guard.flow_track.get(key, 0) {
                Ok(entry) => {
                    if now.saturating_sub(entry.last_seen_ns) > FLOW_TRACK_IDLE_NS
                        && guard.flow_track.remove(key).is_ok()
                    {
                        removed += 1;
                    }
                }
                // KeyNotFound 只说明扫描期间内核刚好删了它，忽略即可。
                Err(_) => {}
            }
        }
    }

    let stats = aggregate(&guard.datapath_stats);
    (removed, keys.len() - removed, stats, temp_fail)
}

/// PerCpuArray 的每个条目是「每 CPU 一份」，求和才是全局计数。
fn aggregate(map: &PerCpuArray<MapData, StatsCounters>) -> StatsCounters {
    let mut sum = StatsCounters::zeroed();
    let Ok(values) = map.get(&0u32, 0) else {
        return sum;
    };
    for v in values.iter() {
        sum.direct_pkts += v.direct_pkts;
        sum.direct_bytes += v.direct_bytes;
        sum.proxy_pkts += v.proxy_pkts;
        sum.proxy_bytes += v.proxy_bytes;
        sum.reply_pkts += v.reply_pkts;
        sum.reply_bytes += v.reply_bytes;
        sum.block_pkts += v.block_pkts;
        sum.frag_inherited += v.frag_inherited;
        sum.new_flow_limited += v.new_flow_limited;
    }
    sum
}
