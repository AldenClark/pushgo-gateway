#!/usr/bin/env python3
"""Exclusive-window C6 final source verification. No retries or provisioning."""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, time

OUT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = OUT.parent / 'c-single-ledger-contract-20261015/workspace-final'
COMMIT = 'e3de1ebe1caac618ecdcc293e040752e36752fe4'

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False)+'\n')

def main():
    p=argparse.ArgumentParser(); p.add_argument('--exclusive-window', required=True)
    args=p.parse_args(); assert args.exclusive_window == 'c6-final-rust'
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=SOURCE,text=True).strip()==COMMIT
    result_dir=OUT/'tests/final-e3de1eb'; result_dir.mkdir(exist_ok=False)
    inputs={}
    for rel in subprocess.check_output(['git','ls-files','-z'],cwd=SOURCE).decode().split('\0'):
        if rel and (rel.endswith('.rs') or pathlib.Path(rel).name in ('Cargo.toml','Cargo.lock','build.rs')):
            inputs[rel]=digest(SOURCE/rel)
    env={k:v for k,v in os.environ.items() if not k.startswith(('PUSHGO_','C4_','C5_','C6_','CARGO_PROFILE_')) and k not in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_TARGET_DIR')}
    command=['cargo','+1.97.1','test','--release','--offline','--locked','--lib','--no-run','--message-format=json']
    started=time.monotonic()
    with (result_dir/'build-stdout.jsonl').open('x') as stdout, (result_dir/'build-stderr.log').open('x') as stderr:
        build=subprocess.run(command,cwd=SOURCE/'prototype',env=env,stdout=stdout,stderr=stderr)
    receipt={'source_commit':COMMIT,'source_sha256':inputs,'command':command,'build_exit':build.returncode,'build_seconds':time.monotonic()-started,'target':'prototype/target','no_retry':True}
    save(result_dir/'identity.json',receipt)
    assert build.returncode==0, 'build failed; first receipt retained'
    executables=[]
    for line in (result_dir/'build-stdout.jsonl').read_text().splitlines():
        try:r=json.loads(line)
        except ValueError:continue
        if r.get('reason')=='compiler-artifact' and r.get('profile',{}).get('test') and r.get('executable') and r['target']['kind']==['lib']:
            executables.append(pathlib.Path(r['executable']))
    assert len(executables)==1
    binary=OUT/'binaries/private-final-e3de1eb-tests'; assert not binary.exists()
    shutil.copy2(executables[0],binary)
    receipt.update(binary=str(binary),binary_sha256=digest(binary))
    save(result_dir/'identity.json',receipt)
    active=json.loads((OUT/'env/active-case-manifest.json').read_text())
    def case(backend,label):
        rows=[r for r in active['cases'] if r['backend']==backend and r['label']==label]
        assert len(rows)==1
        ref=pathlib.Path(rows[0]['url_file']); assert ref.stat().st_mode & 0o777 == 0o600
        return rows[0],ref
    tests=[('default',[],{}),('wire-boundary',['--exact','private_boundary_tests::legal_http_input_private_wire_size_diagnostic','--ignored','--nocapture'],{})]
    for backend,filter_name,var in [('postgres','postgres_shared_private_ledger_contract','C6_PRIVATE_PG_URL_FILE'),('mysql','mysql_shared_private_ledger_contract','C6_PRIVATE_MYSQL_URL_FILE')]:
        row,ref=case(backend,'private_contract_final')
        tests.append(('private-'+backend,[filter_name,'--ignored','--nocapture'],{var:str(ref),'C6_PRIVATE_DISPOSABLE':'YES_NEW_SYNTHETIC'}))
    for backend,name,var,flag in [('postgres','postgres_shared_ordinary_contract_and_native_failures','C4_PG_TEST_URL','C4_PG_DISPOSABLE'),('mysql','mysql_shared_ordinary_contract_and_native_failures','C5_MYSQL_TEST_URL','C5_MYSQL_DISPOSABLE')]:
        row,ref=case(backend,'native_base')
        tests.append(('ordinary-'+backend,[name,'--ignored','--nocapture'],{var:ref.read_text().strip(),flag:'YES_NEW_SYNTHETIC'}))
    results=[]
    for label,arguments,extra in tests:
        start=time.monotonic(); selected_env=env|extra
        path=result_dir/(label+'.log')
        with path.open('x') as log:
            os.chmod(path,0o600)
            run=subprocess.run([str(binary),*arguments],env=selected_env,cwd=SOURCE/'prototype',stdout=log,stderr=subprocess.STDOUT)
        selected={'label':label,'arguments':arguments,'exit':run.returncode,'seconds':time.monotonic()-start,'log_sha256':digest(path),'binary_sha256':receipt['binary_sha256']}
        results.append(selected); save(result_dir/'results.json',{'source_commit':COMMIT,'results':results,'no_retry':True})
        print(json.dumps(selected),flush=True)
        assert run.returncode==0, 'first failure retained; no subsequent test run'
        text=path.read_text()
        assert 'test result: ok.' in text and '0 passed' not in text, 'empty or invalid test selection'
    assert all(digest(SOURCE/rel)==expected for rel,expected in inputs.items())
    receipt['source_unchanged_after']=True;save(result_dir/'identity.json',receipt)

if __name__=='__main__':main()
