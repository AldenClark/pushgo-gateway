#!/usr/bin/env python3
"""Bounded storage-layout probe. Direct SQLite; never a product API throughput test."""
import argparse, hashlib, json, platform, re, sqlite3, subprocess, sys, time
from pathlib import Path

def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def snap(db, path):
    db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchall()
    return {'identity_rows':db.execute('SELECT count(*) FROM messages').fetchone()[0], 'target_rows':db.execute('SELECT count(*) FROM targets').fetchone()[0], 'logical_payload_bytes':db.execute('SELECT coalesce(sum(payload_bytes),0) FROM messages').fetchone()[0], 'page_size':db.execute('PRAGMA page_size').fetchone()[0], 'page_count':db.execute('PRAGMA page_count').fetchone()[0], 'freelist_count':db.execute('PRAGMA freelist_count').fetchone()[0], 'db_bytes':path.stat().st_size, 'dbstat':dict(db.execute('SELECT name,sum(pgsize) FROM dbstat GROUP BY name'))}

def run(args):
    source=Path(args.source); identity=json.loads(Path(args.source_identity).read_text()); assert sha(source/'prototype/src/store.rs')==identity['source_sha256']['prototype/src/store.rs']; out=Path(args.out); out.mkdir(exist_ok=False)
    raw=(source/'prototype/src/store.rs').read_text()
    schema=re.search(r'const SCHEMA:\s*&str\s*=\s*"(.*?)";',raw,re.S).group(1)
    (out/'schema.sql').write_text(schema)
    cases=[]; at=1792022400000
    for fanout, body_bytes in [(1,448),(16,448),(32,448),(16,1024),(16,4096)]:
        path=out/f'fanout-{fanout}-body-{body_bytes}.sqlite'; db=sqlite3.connect(path)
        db.execute('PRAGMA journal_mode=WAL'); db.execute('PRAGMA synchronous=NORMAL'); db.execute('PRAGMA foreign_keys=ON'); db.executescript(schema)
        cold=snap(db,path); nmsg=256
        started=time.perf_counter_ns()
        # Fixed64/32/46/26 byte fingerprint/id/op/channel widths and163 byte token.
        for batch in range(0,nmsg,16):
            with db:
                for n in range(batch,batch+16):
                    delivery=f'{n:032x}'
                    db.execute('INSERT INTO messages(delivery_id,message_id,op_id,channel_id,fingerprint,payload_blob,payload_bytes,accepted_at,expires_at,dedupe_until,status,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(delivery,f'{n+1000000:032x}',f'{at:013x}-{n:032x}','0'*26,'f'*64,b'x'*body_bytes,body_bytes,at,at+604800000,at+2592000000,'queued',at))
                    db.executemany("INSERT INTO targets(delivery_id,device_key,platform,provider,provider_token,state,next_attempt_at,accepted_at,route_generation) VALUES(?,?,'android','FCM',?,'pending',?,?,1)",((delivery,f'{k:032x}',f'synthetic-{k:0153x}',at,at) for k in range(fanout)))
        elapsed_us=(time.perf_counter_ns()-started)//1000
        active=snap(db,path)
        assert active['target_rows']==nmsg*fanout and active['logical_payload_bytes']==nmsg*body_bytes
        assert db.execute('SELECT count(*) FROM targets WHERE pull_owner=device_key AND owner_generation=1 AND control_epoch=0').fetchone()[0]==nmsg*fanout
        target_names=[name for name in active['dbstat'] if name=='targets' or name.startswith('targets_') or name.startswith('sqlite_autoindex_targets_')]
        target_delta={name:active['dbstat'][name]-cold['dbstat'].get(name,0) for name in target_names}
        # Explicit logical transition is a layout probe only; native ACK semantics are separate.
        with db:
            db.execute('DELETE FROM targets')
            db.execute("UPDATE messages SET payload_blob=x'',payload_bytes=0,status='sent'")
        compact=snap(db,path)
        assert compact['identity_rows']==nmsg and compact['target_rows']==compact['logical_payload_bytes']==0
        cases.append({'fanout':fanout,'body_bytes':body_bytes,'messages':nmsg,'targets':nmsg*fanout,'seed_us':elapsed_us,'cold':cold,'active':active,'after_direct_sql_release':compact,'target_dbstat_delta':target_delta,'target_bytes_per_row':sum(target_delta.values())/(nmsg*fanout),'message_plus_index_bytes_per_row':sum(active['dbstat'][name]-cold['dbstat'].get(name,0) for name in active['dbstat'] if name=='messages' or name.startswith('messages_') or name.startswith('sqlite_autoindex_messages_'))/nmsg})
        db.close()
    result={'scope':'Python SQLite direct fixed-schema layout; no native admission, provider, HTTP, ACK or performance equivalence claimed','source_commit':identity['source_commit'],'source_tree':identity['source_tree'],'source_archive_sha256':identity['archive_sha256'],'source_store_sha256':sha(source/'prototype/src/store.rs'),'schema_sha256':sha(out/'schema.sql'),'schema_version_note':'prototype manifest schema_version=1; schema extracted verbatim from measured store.rs','sqlite_version':sqlite3.sqlite_version,'python':sys.version,'platform':platform.platform(),'sqlite_compile_options':[row[0] for row in sqlite3.connect(':memory:').execute('PRAGMA compile_options')],'cases':cases}
    (out/'fanout-body-results.json').write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--source',required=True); p.add_argument('--source-identity',required=True); p.add_argument('--out',required=True); run(p.parse_args())
