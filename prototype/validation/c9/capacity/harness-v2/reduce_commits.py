#!/usr/bin/env python3
"""Bounded-memory offline reduction. No daemon, build, or workload execution.

expected.jsonl: exactly one row per OFFERED target, including failed admission:
{op_id, device_key, delivery_id: str|null, offer_mach_ticks, final_outcome}.
final_outcome is accepted/provider_failed/admission_failed/timeout/unfinished.
telemetry.json: {mach_numer, mach_denom, dropped, invalid_ids, write_errors,
 writer_joined, emitted, expected_targets, final_sql_verified}.
commits.bin follows PLAN.md. Successful quantiles use actual successful records;
coverage retains all offered targets. SQLite scratch is disk-backed, not RAM.
"""
import argparse
import json
import math
import pathlib
import sqlite3
import struct

RECORD = struct.Struct('<QQQ32s32sB7x')
OUTCOMES = {'accepted', 'provider_failed', 'admission_failed', 'timeout', 'unfinished'}


def reduce(expected, stream, telemetry, scratch):
    meta = json.loads(telemetry.read_text())
    assert meta['mach_numer'] > 0 and meta['mach_denom'] > 0
    assert meta['writer_joined'] and meta['final_sql_verified']
    assert all(meta[name] == 0 for name in ('dropped', 'invalid_ids', 'write_errors'))
    # Refuse overwriting evidence or a prior scratch failure.
    scratch.touch(exist_ok=False)
    con = sqlite3.connect(scratch)
    con.execute('PRAGMA temp_store=FILE')
    con.execute('PRAGMA cache_size=-2048')
    con.executescript('''
      CREATE TABLE expected(op TEXT, device TEXT, delivery TEXT, offer INTEGER,
        outcome TEXT, PRIMARY KEY(op,device));
      CREATE UNIQUE INDEX expected_identity ON expected(delivery,device);
      CREATE TABLE events(ticks INTEGER, attempt INTEGER, sequence INTEGER PRIMARY KEY,
        delivery TEXT, device TEXT, state INTEGER);
      CREATE INDEX events_identity ON events(delivery,device,state,ticks);
    ''')
    with expected.open() as handle:
        for line in handle:
            row = json.loads(line)
            assert row['final_outcome'] in OUTCOMES
            con.execute('INSERT INTO expected VALUES(?,?,?,?,?)',
                        (row['op_id'], row['device_key'], row['delivery_id'],
                         row['offer_mach_ticks'], row['final_outcome']))
    emitted = 0
    warmup = 0
    late = 0
    cutoff = meta.get('measurement_cutoff_mach_ticks')
    with stream.open('rb') as handle:
        while True:
            raw = handle.read(RECORD.size)
            if not raw:
                break
            assert len(raw) == RECORD.size, 'partial telemetry record'
            ticks, attempt, sequence, delivery, device, state = RECORD.unpack(raw)
            assert state in range(1, 6)
            delivery, device = delivery.decode('ascii'), device.decode('ascii')
            assert '\x00' not in delivery + device, 'identity padded or truncated'
            emitted += 1
            if delivery in meta.get('excluded_acknowledged_warmup_ids', []):
                warmup += 1
                continue
            if cutoff is not None and ticks > cutoff:
                late += 1
                continue
            con.execute('INSERT INTO events VALUES(?,?,?,?,?,?)',
                        (ticks, attempt, sequence, delivery, device, state))
    assert emitted == meta['emitted'], 'stream count mismatch'
    count = con.execute('SELECT COUNT(*) FROM expected').fetchone()[0]
    assert count == meta['expected_targets'], 'offered denominator mismatch'
    # Every event must map to an expected offered target, including retries.
    assert con.execute('''SELECT COUNT(*) FROM events v LEFT JOIN expected e
      ON v.delivery=e.delivery AND v.device=e.device WHERE e.op IS NULL''').fetchone()[0] == 0
    con.execute('''CREATE TABLE samples AS SELECT e.op,e.device,e.outcome,
      MIN(CASE WHEN v.state=1 THEN v.ticks END)-e.offer AS success_ticks,
      MIN(CASE WHEN v.state BETWEEN 1 AND 4 THEN v.ticks END)-e.offer AS terminal_ticks
      FROM expected e LEFT JOIN events v ON v.delivery=e.delivery AND v.device=e.device
      GROUP BY e.op,e.device''')
    con.execute('CREATE INDEX samples_success ON samples(success_ticks)')
    con.execute('CREATE INDEX samples_terminal ON samples(terminal_ticks)')
    assert con.execute('SELECT COUNT(*) FROM samples WHERE success_ticks<0 OR terminal_ticks<0').fetchone()[0] == 0
    assert con.execute("SELECT COUNT(*) FROM samples WHERE outcome='accepted' AND success_ticks IS NULL").fetchone()[0] == 0
    assert con.execute("SELECT COUNT(*) FROM samples WHERE outcome!='accepted' AND success_ticks IS NOT NULL").fetchone()[0] == 0
    counts = dict(con.execute('SELECT outcome,COUNT(*) FROM samples GROUP BY outcome'))
    scale = meta['mach_numer'] / meta['mach_denom'] / 1_000_000

    def distribution(column):
        n = con.execute(f'SELECT COUNT({column}) FROM samples').fetchone()[0]
        answer = {'observed_targets': n, 'all_offered_targets': count,
                  'coverage': n / count if count else None}
        for p in (50, 95, 99):
            rank = math.ceil(n * p / 100)
            ticks = con.execute(f'SELECT {column} FROM samples WHERE {column} IS NOT NULL '
                                f'ORDER BY {column} LIMIT 1 OFFSET ?', (rank - 1,)).fetchone() if rank else None
            answer[f'p{p}_observed_ms'] = ticks[0] * scale if ticks else None
        return answer

    result = {'scope': 'exact post-successful-COMMIT-await observer boundary; local synthetic fixture',
              'offered_targets': count, 'outcomes': counts, 'commit_events': emitted,
              'excluded_verified_warmup_events': warmup,
              'post_cutoff_events_preserved_but_censored':late,
              'measurement_cutoff_mach_ticks':cutoff,
              'success': distribution('success_ticks'), 'terminal': distribution('terminal_ticks'),
              'all_offered_success_quantiles_identified': counts.get('accepted', 0) == count,
              'censoring': 'failed and unfinished targets remain denominator; observed quantiles are conditional on recorded completion',
              'method': 'nearest-rank exact samples; shared Mach clock; no receipt_at or histogram reconstruction'}
    con.commit()
    con.close()
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('expected', 'stream', 'telemetry', 'scratch'):
        parser.add_argument('--' + name, type=pathlib.Path, required=True)
    args = parser.parse_args()
    print(json.dumps(reduce(args.expected, args.stream, args.telemetry, args.scratch), indent=2))
