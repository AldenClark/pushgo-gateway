"""Optional one-shot diagnostic after successful COMMIT witnesses, before ACK.
No raw SQL text or binding is returned. Failure never changes the capacity result.
"""
import json,re,time
SCOPE='post-completion live prepared-instance lifetime lower bounds, not offer-window deltas; includes setup/warmup and surviving cache entries; eviction/close/truncation/instrumentation may lose coverage; old arm UNAVAILABLE'
FILTER="t.PROCESSLIST_DB=DATABASE() AND t.PROCESSLIST_ID<>CONNECTION_ID() AND t.TYPE='FOREGROUND'"
def query():
    owner_filter=FILTER.replace('t.','o.')
    return "SELECT /*+ MAX_EXECUTION_TIME(2000) */ JSON_OBJECT("+\
        "'owner_count',(SELECT COUNT(*) FROM performance_schema.threads o WHERE "+owner_filter+"),"+\
        "'owner_statement_count',(SELECT COUNT(*) FROM performance_schema.prepared_statements_instances q JOIN performance_schema.threads o ON o.THREAD_ID=q.OWNER_THREAD_ID WHERE "+owner_filter+" AND q.OWNER_OBJECT_TYPE IS NULL),"+\
        "'thread_id',t.THREAD_ID,'process_id',t.PROCESSLIST_ID,'statement_id',p.STATEMENT_ID,"+\
        "'query_sha256',SHA2(p.SQL_TEXT,256),'sql_text_bytes',OCTET_LENGTH(p.SQL_TEXT),"+\
        "'count_execute',p.COUNT_EXECUTE,'timer_execute_ps',p.SUM_TIMER_EXECUTE,"+\
        "'rows_examined',p.SUM_ROWS_EXAMINED,'rows_sent',p.SUM_ROWS_SENT,'rows_affected',p.SUM_ROWS_AFFECTED,"+\
        "'statement_table_lock_wait_ps',p.SUM_LOCK_TIME) FROM performance_schema.prepared_statements_instances p "+\
        "JOIN performance_schema.threads t ON t.THREAD_ID=p.OWNER_THREAD_ID WHERE "+FILTER+\
        " AND p.OWNER_OBJECT_TYPE IS NULL ORDER BY p.STATEMENT_ID LIMIT 256;"
def observe(sql,*,witness_targets,offered_targets,receipt_commits,warmup_targets,gateway_alive,query_names):
    guard={'verified_durable_accepted_targets':witness_targets,'offered_targets':offered_targets,'observed_postcallback_receipt_counter':receipt_commits,'expected_postcallback_counter':offered_targets+warmup_targets,'gateway_alive':gateway_alive}
    if witness_targets!=40960 or offered_targets!=40960 or receipt_commits!=offered_targets+warmup_targets or not gateway_alive:
        return {'available':False,'reason':'all-COMMIT counter/durable/owner liveness guard not independently satisfied; no wait/retry/query','scope':SCOPE,'guard':guard,'query_calls':0}
    started=time.monotonic()
    try:
        rows=[json.loads(line) for line in sql(query()).splitlines()];assert 0<len(rows)<=256
        assert all(r['owner_count']==1 and r['owner_statement_count']==len(rows) for r in rows)
        assert len({(r['thread_id'],r['process_id']) for r in rows})==1
        for row in rows:
            assert re.fullmatch('[0-9a-f]{64}',row['query_sha256'])
            assert all(isinstance(row[k],int) and row[k]>=0 for k in ['count_execute','timer_execute_ps','rows_examined','rows_sent','rows_affected','statement_table_lock_wait_ps','sql_text_bytes'])
            row['static_query_symbol']=query_names.get(row['query_sha256'],'UNMAPPED_HASH_ONLY')
        return {'available':True,'scope':SCOPE,'guard':guard,'query_calls':1,'observer_seconds':time.monotonic()-started,'rows':rows,'lock_semantics':'statement/table-lock wait picoseconds, not all InnoDB row-lock waiting','old_comparator':'UNAVAILABLE; no old rerun; new post-completion observation overhead differs'}
    except Exception as error:
        return {'available':False,'scope':SCOPE,'guard':guard,'query_calls':1,'observer_seconds':time.monotonic()-started,'reason':'bounded observation unavailable; no retry','error_class':type(error).__name__}
