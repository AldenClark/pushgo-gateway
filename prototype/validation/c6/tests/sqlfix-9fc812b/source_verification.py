#!/usr/bin/env python3
"""Exclusive C6 SQL-fix verification; preserve first failures; no provisioning."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

SOURCE = Path('/Users/ethan/Repo/PushGo/gateway/build/quality-results/c-single-ledger-contract-20261015/workspace-final')
OUT = Path('/Users/ethan/Repo/PushGo/gateway/build/quality-results/c6-private-capacity-20261015')
RESULT = OUT / 'tests/sqlfix-9fc812b'
COMMIT = '9fc812b40880e0ffd2375b4c83bb920292bdf880'
TEST = OUT / 'binaries/private-sqlfix-9fc812b-tests'
NORMAL = OUT / 'binaries/private-sqlfix-9fc812b-normal'

def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def save(name, value):
    (RESULT / name).write_text(json.dumps(value, indent=2, ensure_ascii=False)+'\n')

def inputs():
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=SOURCE,text=True).strip()==COMMIT
    paths=subprocess.check_output(['git','ls-files','-z'],cwd=SOURCE).decode().split('\0')
    return {p:digest(SOURCE/p) for p in paths if p and (p.endswith('.rs') or Path(p).name in ('Cargo.toml','Cargo.lock','build.rs'))}

def env():
    return {k:v for k,v in os.environ.items() if not k.startswith(('PUSHGO_','C4_','C5_','C6_','CARGO_PROFILE_')) and k not in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_TARGET_DIR')}

def run(label, command, extra=None):
    before=inputs(); start=time.monotonic(); path=RESULT/(label+'.log')
    with path.open('x') as log:
        os.chmod(path,0o600)
        proc=subprocess.run(command,cwd=SOURCE/'prototype',env=env()|(extra or {}),stdout=log,stderr=subprocess.STDOUT)
    receipt={'source_commit':COMMIT,'command':command,'exit':proc.returncode,'seconds':time.monotonic()-start,'log_sha256':digest(path),'source_unchanged_after':before==inputs(),'no_retry':True}
    save(label+'.json',receipt); print(json.dumps(receipt),flush=True)
    assert receipt['source_unchanged_after']
    assert proc.returncode==0,'first failure retained; stop without retry'
    return path

def build():
    before=inputs(); save('source-inputs.json',{'source_commit':COMMIT,'source_sha256':before,'input_count':len(before),'target':'prototype/target','profile':{'lto':'fat','codegen-units':1,'opt-level':3},'script_sha256':digest(Path(__file__))})
    command=['cargo','+1.97.1','test','--release','--offline','--locked','--lib','--no-run','--message-format=json']
    path=run('test-build',command)
    artifacts=[]
    for line in path.read_text().splitlines():
        try: row=json.loads(line)
        except ValueError: continue
        if row.get('reason')=='compiler-artifact' and row.get('profile',{}).get('test') and row.get('executable') and row['target']['kind']==['lib']:
            artifacts.append(Path(row['executable']))
    assert len(artifacts)==1
    assert not TEST.exists(); shutil.copy2(artifacts[0],TEST)
    save('test-identity.json',{'source_commit':COMMIT,'source_sha256':before,'binary':str(TEST),'binary_sha256':digest(TEST),'source_unchanged_after':before==inputs()})

def tests(case_manifest, db):
    identity=json.loads((RESULT/'test-identity.json').read_text()); assert inputs()==identity['source_sha256']; assert digest(TEST)==identity['binary_sha256']
    if not db:
        rows=[('default',[],{}),('wire-boundary',['--exact','private_boundary_tests::legal_http_input_private_wire_size_diagnostic','--ignored','--nocapture'],{})]
    else:
        active=json.loads(Path(case_manifest).read_text())
        def case(backend,label):
            matches=[r for r in active['cases'] if r['backend']==backend and r['label']==label]
            assert len(matches)==1
            ref=Path(matches[0]['url_file']); assert ref.stat().st_mode&0o777==0o600
            return ref
        rows=[]
        for backend,var in [('postgres','C6_PRIVATE_PG_URL_FILE'),('mysql','C6_PRIVATE_MYSQL_URL_FILE')]:
            ref=case(backend,'private_contract_sqlfix')
            rows.append(('private-'+backend,[backend+'_shared_private_ledger_contract','--ignored','--nocapture'],{var:str(ref),'C6_PRIVATE_DISPOSABLE':'YES_NEW_SYNTHETIC'}))
        for backend,var,flag in [('postgres','C4_PG_TEST_URL','C4_PG_DISPOSABLE'),('mysql','C5_MYSQL_TEST_URL','C5_MYSQL_DISPOSABLE')]:
            ref=case(backend,'native_base_sqlfix' if backend=='mysql' else 'native_base')
            rows.append(('ordinary-'+backend,[backend+'_shared_ordinary_contract_and_native_failures','--ignored','--nocapture'],{var:ref.read_text().strip(),flag:'YES_NEW_SYNTHETIC'}))
    for label,args,extra in rows:
        path=run(label,[str(TEST),*args],extra); text=path.read_text()
        assert 'test result: ok.' in text and '0 passed' not in text
        if label=='ordinary-mysql':
            assert 'acked_running=true, native1644' in text and 'acked_running=false, native1644' in text
            assert text.count('MYSQL_NEXT_DUE_NATIVE_OBSERVATION ')==2
    assert inputs()==identity['source_sha256']

def normal():
    identity=json.loads((RESULT/'test-identity.json').read_text()); assert inputs()==identity['source_sha256']
    run('normal-build',['cargo','+1.97.1','build','--release','--offline','--locked','--bin','free_architecture_fixture'])
    assert not NORMAL.exists(); shutil.copy2(SOURCE/'prototype/target/release/free_architecture_fixture',NORMAL)
    save('normal-identity.json',{'source_commit':COMMIT,'source_sha256':inputs(),'binary':str(NORMAL),'binary_sha256':digest(NORMAL),'test_binary_sha256':digest(TEST),'source_unchanged_after':inputs()==identity['source_sha256']})

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--exclusive-window',required=True,choices=['c6-sqlfix-rust']); parser.add_argument('phase',choices=['build','local-tests','db-tests','normal','checks']); parser.add_argument('--case-manifest'); args=parser.parse_args()
    if args.phase=='build': build()
    elif args.phase=='local-tests': tests(None,False)
    elif args.phase=='db-tests': assert args.case_manifest; tests(args.case_manifest,True)
    elif args.phase=='normal': normal()
    else:
        run('fmt',['cargo','+1.97.1','fmt','--all','--','--check'])
        run('diff',['git','diff','--check'])
        run('clippy',['cargo','+1.97.1','clippy','--release','--offline','--locked','--all-targets'])
