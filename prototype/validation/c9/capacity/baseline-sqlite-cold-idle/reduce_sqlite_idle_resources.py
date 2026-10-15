#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline streaming reduction only: no process probes, HTTP, SQL, or product imports."""
import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
AUDIT = BASE.parent.parent / 'audit'
WINDOWS = [('all', 0, 1261), ('cold_0_5', 0, 5), ('steady_ge5', 5, 1261),
           ('0_60', 0, 60), ('60_600', 60, 600), ('600_1200', 600, 1200), ('1200_1260', 1200, 1261)]

def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for part in iter(lambda: f.read(1024 * 1024), b''):
            h.update(part)
    return h.hexdigest()

def add_scalar(a, key, value):
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return
    v = a.setdefault(key, {'samples': 0, 'sum': 0, 'min': value, 'max': value, 'first': value, 'last': value})
    v['samples'] += 1
    v['sum'] += value
    v['min'] = min(v['min'], value)
    v['max'] = max(v['max'], value)
    v['last'] = value

def finish(a):
    for v in a.values():
        if isinstance(v, dict) and 'sum' in v:
            v['arithmetic_sample_mean'] = v.pop('sum') / v['samples']
    return a

def os_point(row):
    m = row['metrics']
    return {'elapsed_seconds': row['elapsed_seconds'], **{k: m[k] for k in ['userCPU_ns', 'systemCPU_ns', 'RSSbytes', 'interrupt_wakes', 'pkgIdle_wakes']}}

def os_reduce():
    groups = {label: {n: {} for n, _, _ in WINDOWS} for label in ['gateway', 'harness']}
    bounds = {label: {str(b): {'before': None, 'after': None} for b in [600, 1200]} for label in groups}
    errors = 0
    with (BASE / 'os-samples.jsonl').open() as f:
        for line in f:
            r = json.loads(line)
            if r.get('raw', {}).get('status') != 'ok':
                errors += 1
                continue
            label = r['label']; t = r['elapsed_seconds']; p = os_point(r)
            for b, data in bounds[label].items():
                if t < float(b): data['before'] = p
                elif data['after'] is None: data['after'] = p
            for name, lo, hi in WINDOWS:
                if lo <= t < hi:
                    g = groups[label][name]
                    g.setdefault('first', p); g['last'] = p
                    a = g.setdefault('sample_distribution', {})
                    add_scalar(a, 'RSSbytes', p['RSSbytes'])
                    add_scalar(a, 'sampler_elapsed_seconds', r['sampler_elapsed_seconds'])
    for label, wins in groups.items():
        for name, g in wins.items():
            finish(g['sample_distribution'])
            a, b = g['first'], g['last']; span = b['elapsed_seconds'] - a['elapsed_seconds']
            user = b['userCPU_ns'] - a['userCPU_ns']; system = b['systemCPU_ns'] - a['systemCPU_ns']
            g['endpoint_delta'] = {'sample_span_seconds': span, 'userCPU_ns': user, 'systemCPU_ns': system,
                                   'totalCPU_ns': user + system, 'one_core_average_percent': (user + system) / span / 1e7 if span else None,
                                   'interrupt_wakes': b['interrupt_wakes'] - a['interrupt_wakes'], 'pkgIdle_wakes': b['pkgIdle_wakes'] - a['pkgIdle_wakes']}
    return {'processes': groups, 'boundary_brackets': bounds, 'invalid_samples': errors}

GAUGES = ['tasks', 'num_alive', 'owned_attempts', 'network_inflight', 'receipts_owned', 'http_connections', 'sql_operations', 'claim_queries', 'admission_commits', 'receipt_commits', 'ack_commits', 'db_errors']

def stats_point(x, t):
    return {'natural_stats_relative_seconds': t, 'unix_ms': x['unix_ms'], 'allocator': x['allocator'],
            'gauges': {k: x[k] for k in GAUGES}, 'provider_owned': x['provider_owned'],
            'provider_targets': x['provider_targets'], 'claim_reservations': x['claim_reservations'],
            'provider_resources': x['provider_resources'], 'dbcounts': x['dbcounts']}

def stats_reduce():
    groups = {n: {} for n, _, _ in WINDOWS}; first_ms = None; n = 0; changes = []; previous = None
    bounds = {str(b): {'before': None, 'after': None} for b in [600, 1200]}
    with (BASE / 'gateway.log').open() as f:
        for line in f:
            if not line.startswith('{'): continue
            x = json.loads(line)
            if x.get('kind') != 'stats': continue
            first_ms = x['unix_ms'] if first_ms is None else first_ms
            t = (x['unix_ms'] - first_ms) / 1000; p = stats_point(x, t); n += 1
            counters = {'dbcounts': x['dbcounts'], **{k: x[k] for k in ['sql_operations', 'claim_queries', 'admission_commits', 'receipt_commits', 'ack_commits']}}
            if previous is not None and previous != counters:
                assert len(changes) < 100, 'counter transition bound exceeded; preserve first reduction failure'
                changes.append({'natural_stats_relative_seconds': t, 'before': previous, 'after': counters})
            previous = counters
            for b, data in bounds.items():
                if t < float(b): data['before'] = p
                elif data['after'] is None: data['after'] = p
            for name, lo, hi in WINDOWS:
                if lo <= t < hi:
                    g = groups[name]; g.setdefault('first', p); g['last'] = p
                    a = g.setdefault('sample_distribution', {})
                    for k in ['bytes_in_use', 'bytes_reserved', 'blocks_in_use']: add_scalar(a, k, x['allocator'][k])
                    for k in GAUGES: add_scalar(a, k, x[k])
                    for k in ['provider_owned', 'provider_targets', 'claim_reservations']:
                        for i, v in enumerate(x[k]): add_scalar(a, f'{k}_{i}', v)
                    for i, v in enumerate(x['provider_resources']['provider_client_owners']): add_scalar(a, f'provider_client_owner_{i}', int(v))
    for g in groups.values():
        finish(g['sample_distribution'])
        a, b = g['first'], g['last']
        g['dbcounts_delta'] = {k: b['dbcounts'].get(k, 0) - a['dbcounts'].get(k, 0) for k in set(a['dbcounts']) | set(b['dbcounts'])}
    return {'samples': n, 'first_unix_ms': first_ms, 'clock': 'Natural STATS unix_ms relative to first STATS; no recorded exact pairing to driver monotonic idle origin. Do not claim precise cross-stream event simultaneity.', 'windows': groups, 'counter_transitions': changes, 'boundary_brackets': bounds}

def main():
    names = ['result.json', 'idle-start.json', 'idle-end.json', 'os-samples.jsonl', 'gateway.log', 'executed-run_sqlite_cold_idle.py', 'resource-lease.json']
    inputs = [{'path': str(BASE / n), 'bytes': (BASE / n).stat().st_size, 'sha256': sha(BASE / n)} for n in names]
    for n in ['sqlite-cold-owned-vmmap.txt', 'sqlite-cold-owned-vmmap.json']:
        inputs.append({'path': str(AUDIT / n), 'bytes': (AUDIT / n).stat().st_size, 'sha256': sha(AUDIT / n)})
    result = json.loads((BASE / 'result.json').read_text())
    assert result['clean_shutdown'] and result['quiet'] and result['exit_code'] == 0 and result['failure'] is None
    output = {'kind': 'offline_streaming_sqlite_idle_resource_reduction', 'input_identity': inputs,
              'reducer_source_sha256': sha(Path(__file__)), 'execution_result': result,
              'os': os_reduce(), 'stats': stats_reduce(),
              'sqlite_data_file_stat': [{'name': p.name, 'bytes': p.stat().st_size} for p in BASE.glob('c9-owned-empty.sqlite*') if p.name.endswith(('.sqlite', '-wal', '-shm'))],
              'unmeasured': ['OS sampler child CPU; not zero', 'precise STATS-to-driver clock offset', 'connection close/reopen identity', '1800s max_lifetime boundary', 'all Rust object bytes', 'time-weighted RSS or percentiles'],
              'notes': ['Fixture 1Hz STATS CPU/allocation/logging is included.', 'OS CPU is endpoint cumulative-counter delta over actual sample span, not a sum of samples; distribution means are unweighted sample means.', 'Independent windows omit the inter-boundary sample gap; do not sum their deltas as whole-window totals.', 'Queue0 denotes bounded claim/owned gauges only; no application input offered, no direct command queue depth measurement.', 'No HTTP or SQL observation queries; vmmap was an existing one-time read-only OS observation.', 'SQLite min=max1; observed PRAGMA changes do not prove connection close/reopen or shrink0.', 'Database file stat excludes source/log/collector/binary and is not a history storage quota.', 'vmmap TOTAL/shared virtual sizes must not be added to process RSS; zone allocated/live/fragment totals use rounded different scopes.']}
    j = BASE / 'sqlite-idle-resource-summary.json'
    with j.open('x') as f: json.dump(output, f, ensure_ascii=False, indent=2); f.write('\n')
    lines = ['# SQLite 1260s 冷闲置资源归约', '', '仅离线流式读取既有收据；未探测进程、调用 HTTP/SQL、构建或复跑。PID99175已exit0且quiet。', '', '## OS采样（CPU为实际首末采样累计计数差）', '', '|进程/窗口|采样跨度s|CPU ns|单核平均%|RSS首/末/最小/最大 B|', '|---|---:|---:|---:|---|']
    for label, wins in output['os']['processes'].items():
        for name, g in wins.items():
            d=g['endpoint_delta']; r=g['sample_distribution']['RSSbytes']
            lines.append(f"|{label}/{name}|{d['sample_span_seconds']:.6f}|{d['totalCPU_ns']}|{d['one_core_average_percent']:.6f}|{r['first']}/{r['last']}/{r['min']}/{r['max']}|")
    lines += ['', 'cold定义[0,5)s；steady≥5s。0–60/60–600/600–1200/1200–1260为half-open采样归属，最终桶含实际终点以内样本。CPU只覆盖桶内实际首末采样，分桶间跨界间隔未分配；全窗口total独立计算，不由分桶累加。没有CPU/RSS分位值，均值不是时间加权。Harness自身CPU不包括spawn采样器child；child CPU未测，不能填0或归入Gateway。result.json另有完整driver生命周期self rusage，与idle采样范围不同。', '', '## 自然1Hz STATS', '', '|窗口|malloc inuse首/末/最小/最大 B|reserved首/末 B|blocks首/末|tasks范围|SQL名义计数首/末|', '|---|---|---|---|---|---|']
    for name,g in output['stats']['windows'].items():
        a=g['sample_distribution']; u=a['bytes_in_use'];r=a['bytes_reserved'];b=a['blocks_in_use'];t=a['tasks'];q=a['sql_operations']
        lines.append(f"|{name}|{u['first']}/{u['last']}/{u['min']}/{u['max']}|{r['first']}/{r['last']}|{b['first']}/{b['last']}|{t['min']}–{t['max']}|{q['first']}/{q['last']}|")
    lines += ['', 'STATS按首条unix_ms归零，不与driver monotonic伪造精确配对；±600/1200附近逐条快照和全部SQL计数变化见JSON。claim/owned/provider/network/receipt/http gauge范围见JSON；无输入，未额外主动查询队列。', '', '## 边界与解释', '', '1260s跨过600及1200 reaper时间边界，但pool min=max1；PRAGMA变化不能证明连接close/reopen，更不能声称缩为0。1800s max_lifetime未覆盖。fixture1Hz统计的CPU、临时分配和stdout成本包含在内。原观察为0HTTP/0SQL主动query，已有vmmap是只读外部OS观察，不改变该事实。', '', 'malloc in-use是malloc zone存活分配口径，reserved是zone保留，不等于resident；blocks是分配块数，不等于Rust对象数。现有vmmap一次快照TOTAL约387.2G virtual/687.5M resident含共享映射；不得与进程RSS相加。其malloc-zone表rounded allocated962K/dirty2896K/fragment1934K（67%）与STATS时点和口径不同，不能用差值认定泄漏。', '', 'SQLite关闭后自身数据文件：' + ', '.join(f"{x['name']}={x['bytes']}B" for x in output['sqlite_data_file_stat']) + '。不把log/collector/binary计入数据库最小空间；这只是空库文件stat，不是历史磁盘quota。', '', '## 输入与复现源码', '', f"归约源码 `{Path(__file__).name}` SHA256 `{output['reducer_source_sha256']}`。输入全部流式SHA绑定如下；原始文件未修改。", '']
    lines.extend(f"- `{x['path']}`：`{x['sha256']}` ({x['bytes']}B)" for x in inputs)
    with (BASE / 'sqlite-idle-resource-summary.md').open('x') as f: f.write('\n'.join(lines)+'\n')
    print(json.dumps({'output_json_sha256': sha(j), 'output_md_sha256': sha(BASE/'sqlite-idle-resource-summary.md'), 'source_sha256': output['reducer_source_sha256'], 'gateway_all': output['os']['processes']['gateway']['all'], 'harness_all': output['os']['processes']['harness']['all'], 'stats_counter_transitions': output['stats']['counter_transitions'], 'sqlite':output['sqlite_data_file_stat']}, ensure_ascii=False))

if __name__ == '__main__': main()
