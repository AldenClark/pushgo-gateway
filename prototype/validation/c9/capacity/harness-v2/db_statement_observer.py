#!/usr/bin/env python3
"""Bounded read-only statement snapshots at whole-lane boundaries, never idle/load polls.
These counters cover setup/warmup/idle/ACK/shutdown too, not exact offer-window stats.
Normalized digest prefixes only, no bindings/SQL_TEXT/URL/credentials are collected.
"""
import json,re,time
def query(engine):
    if engine=='mysql':
        return """SELECT /*+ MAX_EXECUTION_TIME(2000) */ JSON_OBJECT(
          'digest',DIGEST,'normalized_prefix',LEFT(DIGEST_TEXT,256),
          'calls',COUNT_STAR,'timer_wait_ps',SUM_TIMER_WAIT,
          'statement_table_lock_wait_ps',SUM_LOCK_TIME,'rows_affected',SUM_ROWS_AFFECTED,
          'rows_examined',SUM_ROWS_EXAMINED,'rows_sent',SUM_ROWS_SENT,
          'tmp_tables',SUM_CREATED_TMP_TABLES,'tmp_disk_tables',SUM_CREATED_TMP_DISK_TABLES,
          'sort_rows',SUM_SORT_ROWS,'no_index_used',SUM_NO_INDEX_USED)
          FROM performance_schema.events_statements_summary_by_digest
          WHERE SCHEMA_NAME=DATABASE() ORDER BY DIGEST LIMIT 1000;"""
    return """SELECT row_to_json(x) FROM (SELECT queryid::text AS digest,
      left(query,256) AS normalized_prefix,calls,total_exec_time,rows,
      shared_blks_hit,shared_blks_read,temp_blks_read,temp_blks_written
      FROM public.pg_stat_statements WHERE dbid=(SELECT oid FROM pg_database
      WHERE datname=current_database()) ORDER BY queryid LIMIT 1000) x;"""
def capture(helper,engine,database):
    assert engine=='mysql' and helper.KEY=='io.pushgo.c7.isolated.synthetic.owner'
    assert re.fullmatch('c5_synthetic_[a-z0-9_]+',database)
    state,inspect=helper.owned(engine);assert database in state['cases']
    begin=time.monotonic();rows=[json.loads(line) for line in helper.sql(engine,query(engine),database).splitlines()]
    assert len(rows)<=1000
    global_row_locks=None;digest_lost=None
    if engine=='mysql':
        raw=helper.sql(engine,"SHOW GLOBAL STATUS WHERE Variable_name IN ('Innodb_row_lock_time','Innodb_row_lock_waits','Innodb_row_lock_current_waits','Performance_schema_digest_lost');",database)
        values={parts[0].lower():int(parts[1]) for line in raw.splitlines() if (parts:=line.split())}
        assert set(values)=={'innodb_row_lock_time','innodb_row_lock_waits','innodb_row_lock_current_waits','performance_schema_digest_lost'}
        digest_lost=values['performance_schema_digest_lost']
        global_row_locks={'time_ms':values['innodb_row_lock_time'],'waits':values['innodb_row_lock_waits'],'current_waits_gauge':values['innodb_row_lock_current_waits']}
    return {'scope':'whole-lane boundary counters; includes setup/warmup/idle/ACK/shutdown, not exact performance window',
        'engine':engine,'database':database,'container_id':state['id'],'container_started_at':inspect['State']['StartedAt'],'unix_ns':time.time_ns(),'observer_seconds':time.monotonic()-begin,
        'max_rows':1000,'rows':rows,'normalized_only':True,'no_counter_reset':True,
        'may_be_incomplete_if_digest_capacity_exhausted':True,
        'global_innodb_row_locks':global_row_locks,'performance_schema_digest_lost_cumulative':digest_lost,
        'lock_semantics':'SUM_LOCK_TIME aggregates statement table-lock waiting, normalized picoseconds; not all InnoDB row-lock wait time. Global InnoDB counters are whole-server boundary values, never per-query or per-case.',
        'measurement_separation':'SQLx caller-wall phase labels remain unchanged; gate, connection checkout, BEGIN, statement and COMMIT timings stay separate.'}

def server_row_lock_delta(before,after):
    scope='whole-server whole-lane boundary delta; attribution to this arm requires quiet server ownership; never per-query/per-case; includes setup/warmup/idle/observers/shutdown'
    if before['engine']!='mysql' or after['engine']!='mysql':return {'available':False,'scope':scope,'reason':'not MySQL'}
    if any(before.get(k)!=after.get(k) for k in ('container_id','container_started_at')):return {'available':False,'scope':scope,'reason':'server identity/start changed'}
    first=before.get('global_innodb_row_locks');last=after.get('global_innodb_row_locks')
    if first is None or last is None:return {'available':False,'scope':scope,'reason':'missing boundary counters'}
    time_ms=last['time_ms']-first['time_ms'];waits=last['waits']-first['waits']
    if time_ms<0 or waits<0:return {'available':False,'scope':scope,'reason':'counter reset/decrease; no inferred delta'}
    return {'available':True,'scope':scope,'row_lock_time_ms_delta':time_ms,'row_lock_waits_delta':waits,
        'digest_lost_cumulative_before':before.get('performance_schema_digest_lost_cumulative'),
        'digest_lost_cumulative_after':after.get('performance_schema_digest_lost_cumulative'),
        'digest_lost_delta':after['performance_schema_digest_lost_cumulative']-before['performance_schema_digest_lost_cumulative'] if all(r.get('performance_schema_digest_lost_cumulative') is not None for r in (before,after)) and after['performance_schema_digest_lost_cumulative']>=before['performance_schema_digest_lost_cumulative'] else None,
        'current_waits_gauge_before':first['current_waits_gauge'],'current_waits_gauge_after':last['current_waits_gauge'],
        'current_waits_semantics':'endpoint gauges only; not total wait events or an interval peak',
        'does_not_measure':'per-query row locks, all locks, caller-wall SQL duration, gate/checkout/BEGIN/COMMIT duration'}
