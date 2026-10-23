#!/usr/bin/env python3
"""Finite native PostgreSQL ACL/owner round-trip on an owned synthetic clone."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import traceback

sys.path.insert(0,str(Path(__file__).resolve().parent))
import remote_cutover_journey as journey
import legacy_cutover_probe as legacy


def acl(database):
    return json.loads(database.sql("""SELECT COALESCE(json_agg(json_build_object(
        'name',c.relname,'owner',pg_get_userbyid(c.relowner),
        'acl',COALESCE(c.relacl::text,'')) ORDER BY c.relname COLLATE "C"),'[]'::json)::text
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f','S') AND c.relname NOT IN
        ('pushgo_product_owner','pushgo_ordinary_cutover')""",label='relation-acl-and-owner'))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-binary',required=True,type=Path)
    parser.add_argument('--source-history',required=True,type=Path)
    parser.add_argument('--evidence-root',required=True,type=Path)
    args=parser.parse_args()
    os.umask(0o077)
    root=args.evidence_root.resolve()
    assert not root.exists(),'refuse reused evidence root'
    legacy.guard_disk(root.parent)
    root.mkdir(mode=0o700)
    tool=Path(__file__).resolve()
    binary=args.candidate_binary.resolve()
    assert binary.is_file() and os.access(binary,os.X_OK)
    source=args.source_history.resolve()
    history=json.loads(source.read_text())
    assert history['container']==journey.CONTAINER
    assert history['database_url']=='postgres://postgres@127.0.0.1:42772/'+history['database_name']
    assert history['source_sha256']==journey.SOURCE_SHA
    catalog=tool.parents[2]/'src/ordinary/pg_cutover/catalog.sql'
    journey.FROZEN_CATALOG_SQL=catalog.read_text()
    journey.FROZEN_BINARIES[str(binary)]=legacy.sha(binary)
    (root/tool.name).write_bytes(tool.read_bytes())
    (root/'catalog-oracle.sql').write_text(journey.FROZEN_CATALOG_SQL)
    journey.write_json(root/'tool-identity.json',{'argv':sys.argv,'helper_sha256':legacy.sha(tool),
        'candidate_binary':str(binary),'candidate_sha256':legacy.sha(binary),
        'source_history':str(source),'source_history_sha256':legacy.sha(source),
        'catalog_sha256':legacy.sha(catalog),'import_hashes':{
            name:legacy.sha(tool.parent/name) for name in ('remote_cutover_journey.py','sqlite_cutover_journey.py','legacy_cutover_probe.py')}})
    try:
        database=journey.clone_database(history['database_name'],root/'owned-pg-clone')
        database.sql("""DO $$ BEGIN
            IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='c16_acl_observer') THEN
                CREATE ROLE c16_acl_observer NOLOGIN;
            END IF;
        END $$;
        SELECT json_build_object('rolname',rolname,'rolcanlogin',rolcanlogin,'rolsuper',rolsuper)::text
        FROM pg_roles WHERE rolname='c16_acl_observer';""",label='owned-synthetic-nologin-role')
        role=json.loads(database.sql("SELECT json_build_object('login',rolcanlogin,'super',rolsuper)::text FROM pg_roles WHERE rolname='c16_acl_observer'",label='verify-observer-nologin'))
        assert role=={'login':False,'super':False}
        database.sql('GRANT SELECT ON TABLE sender_submit_status TO c16_acl_observer',label='synthetic-observer-select-grant')
        before=journey.snapshot(database)
        before_acl=acl(database)
        sender=next(row for row in before_acl if row['name']=='sender_submit_status')
        assert 'c16_acl_observer=r/' in sender['acl'],sender
        journey.write_json(root/'before.json',{'logical':before,'acl_owner':before_acl})
        backup=root/'native-backup'
        assert journey.invoke(binary,'plan',database,backup,'plan')==0
        assert journey.snapshot(database)==before and acl(database)==before_acl
        assert journey.invoke(binary,'run',database,backup,'run')==0
        assert journey.invoke(binary,'restore',database,backup,'restore')==0
        restored=journey.snapshot(database)
        restored_acl=acl(database)
        journey.write_json(root/'after.json',{'logical':restored,'acl_owner':restored_acl})
        assert restored==before,'restored schema/rows differ'
        assert restored_acl==before_acl,'restored ACL/owner differs'
        assert legacy.sha(binary)==journey.FROZEN_BINARIES[str(binary)]
        journey.write_json(root/'result.json',{'status':'NATIVE_PG_ACL_OWNER_RESTORE_PASSED',
            'candidate_sha256':legacy.sha(binary),'source_database':history['database_name'],
            'owned_clone':database.name,'normal_candidate_started':False,
            'explicit_select_grant_preserved':True,'all_relation_acl_owner_exact':True,
            'all_schema_and_rows_exact':True,'injected_business_rows':0})
    except BaseException:
        (root/'probe-failure.txt').write_text(traceback.format_exc())
        raise

if __name__=='__main__':
    main()
