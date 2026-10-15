#!/usr/bin/env python3
"""Read source and write a sparse measurement overlay only. No build or DB calls.

Run against the final authorized commit again into a NEW directory before build.
This script never applies changes to source_root. The overlay is review material.
"""
import argparse, difflib, hashlib, json, pathlib, subprocess

HERE = pathlib.Path(__file__).resolve().parent
def sha(data): return hashlib.sha256(data).hexdigest()
def prepare(root, out):
    out.mkdir(parents=True, exist_ok=False)
    changes = {}; before_hash = {}; after_hash = {}
    def write(rel, old, updated):
        target = out/'overlay'/rel; target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(updated)
        changes[rel] = ''.join(difflib.unified_diff(old.splitlines(True), updated.splitlines(True),
            fromfile='a/'+rel if old else '/dev/null', tofile='b/'+rel))
        if old: before_hash[rel] = sha(old.encode())
        after_hash[rel] = sha(updated.encode())
    def edit(rel, replacements):
        original = (root/rel).read_text(); updated = original
        for old, new in replacements:
            assert updated.count(old) == 1, (rel, 'anchor count', updated.count(old))
            updated = updated.replace(old, new)
        write(rel, original, updated)
    edit('prototype/Cargo.toml', [('[dependencies]', '[features]\ncommit-observer = []\n\n[dependencies]')])
    edit('prototype/src/lib.rs', [('pub mod credentials;', '#[cfg(feature = "commit-observer")]\npub mod commit_observer;\npub mod credentials;')])
    anchor = '''            .phase(Path::Receipt, Phase::Commit, tx.commit())
            .await?;
        drop(profile_connection);'''
    replacement = '''            .phase(Path::Receipt, Phase::Commit, tx.commit())
            .await?;
        #[cfg(feature = "commit-observer")]
        if changed > 0 {
            crate::commit_observer::committed(&ticket.delivery_id, &ticket.device_key, ticket.attempt_id, state);
        }
        drop(profile_connection);'''
    for store in ('store.rs', 'pg_store.rs', 'mysql_store.rs'):
        edit('prototype/src/'+store, [(anchor, replacement)])
    edit('prototype/src/bin/free_architecture_fixture.rs', [
        ('use clap::Parser;', '#[cfg(feature = "commit-observer")]\n#[path = "support/commit_observer_fixture.rs"]\nmod commit_observer_fixture;\nuse clap::Parser;'),
        ('    let cli = Cli::parse();', '''    let cli = Cli::parse();
    #[cfg(feature = "commit-observer")]
    let commit_session = std::env::var_os("C5_COMMIT_STREAM").map(|path|
        commit_observer_fixture::Session::start(std::path::Path::new(&path))).transpose()?;'''),
        ('    if report.panicked != 0 || report.aborted != 0 || report.failed != 0 {', '''    #[cfg(feature = "commit-observer")]
    if let Some(session) = commit_session { session.finish()?; }
    if report.panicked != 0 || report.aborted != 0 || report.failed != 0 {''')])
    for src, dst in [('observer_library.rs', 'prototype/src/commit_observer.rs'),
                     ('observer_fixture.rs', 'prototype/src/bin/support/commit_observer_fixture.rs')]:
        assert not (root/dst).exists(), ('preexisting observer source', dst)
        write(dst, '', (HERE/src).read_text())
    (out/'observer.patch').write_text(''.join(changes.values()))
    lib = (out/'overlay/prototype/src/lib.rs').read_text()
    assert '#![forbid(unsafe_code)]' in lib
    assert 'unsafe' not in (HERE/'observer_library.rs').read_text().replace('No unsafe code', '')
    receipt = {'status':'SOURCE_ONLY_NOT_BUILT_NOT_RUN', 'source_root':str(root),
        'source_commit_at_preparation':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
        'dirty_diff_sha256':sha(subprocess.check_output(['git','diff','HEAD','--binary'],cwd=root)),
        'source_before_sha256':before_hash, 'overlay_sha256':after_hash,
        'patch_sha256':sha((out/'observer.patch').read_bytes()),
        'seam':'all 3 backends: successful receipt COMMIT await returned AND changed > 0',
        'bounded':{'channel_records':4096, 'record_bytes':96, 'writer_buffer_bytes':65536, 'os_writer_threads':1},
        'unsafe_scope':'fixture-only zero-argument Mach clock FFI; library forbid unchanged',
        'candidate_modified':False, 'builds':0, 'database_runtime_calls':0,
        'must_regenerate_after_final_commit':True}
    (out/'preparation.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=pathlib.Path,required=True)
    p.add_argument('--out',type=pathlib.Path,required=True)
    a=p.parse_args(); print(json.dumps(prepare(a.source_root.resolve(),a.out.resolve()),indent=2))
