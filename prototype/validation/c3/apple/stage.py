#!/usr/bin/env python3
"""Explicit source-only staging into a fresh external work directory.
Portable packaging adapter: NOT RUN. This command never builds or runs tests.
"""
import argparse
import hashlib
import json
import pathlib
import shutil

HERE = pathlib.Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apple-source', type=pathlib.Path, required=True,
                        help='Read-only Apple repository root containing Shared/')
    parser.add_argument('--work-root', type=pathlib.Path, required=True,
                        help='Fresh directory outside both bundle and source repository')
    parser.add_argument('--offline-cache', type=pathlib.Path,
                        help='Optional existing Swift scratch; only checkouts/repositories/workspace-state.json are copied')
    args = parser.parse_args()
    source = args.apple_source.resolve(strict=True)
    work = args.work_root.resolve()
    for protected in [HERE.parent, source]:
        if work == protected or protected in work.parents:
            parser.error('--work-root must be outside bundle and source repository')
    if work.exists():
        parser.error('--work-root must not already exist')
    manifest = json.loads((HERE / 'source-copy-manifest.json').read_text())
    checked = []
    for row in manifest['files']:
        relative = pathlib.PurePosixPath(row['path'])
        if relative.is_absolute() or '..' in relative.parts:
            parser.error('Unsafe source-manifest relative path')
        path = source / 'Shared' / relative
        if path.is_symlink() or not path.is_file() or sha(path) != row['sha256']:
            parser.error('Apple source differs from original executed snapshot: ' + str(relative))
        checked.append((path, relative))
    cache = args.offline_cache.resolve(strict=True) if args.offline_cache else None
    if cache:
        for name in ['checkouts', 'repositories', 'workspace-state.json']:
            if not (cache / name).exists():
                parser.error('Incomplete offline dependency cache: ' + name)
    work.mkdir(parents=True, exist_ok=False)
    package = work / 'package'
    package.mkdir()
    for name in ['Package.swift', 'Package.resolved']:
        shutil.copy2(HERE / name, package / name)
    shutil.copytree(HERE / 'Tests', package / 'Tests')
    for path, relative in checked:
        target = package / 'Shared' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    shutil.copy2(HERE / 'source-copy-manifest.json', work / 'source-copy-manifest.json')
    if cache:
        scratch = work / 'build'
        scratch.mkdir()
        for name in ['checkouts', 'repositories']:
            shutil.copytree(cache / name, scratch / name, symlinks=True)
        shutil.copy2(cache / 'workspace-state.json', scratch / 'workspace-state.json')
    receipt = {
        'portable_adapter_status': 'NOT RUN by packaging validation',
        'explicit_read_only_source': str(source),
        'external_work_root': str(work),
        'matched_production_shared_file_count': len(checked),
        'source_manifest_sha256': sha(HERE / 'source-copy-manifest.json'),
        'copied_old_compiled_products': False,
        'offline_dependency_sources_copied': cache is not None,
        'native_tests_executed': False,
        'build_executed': False,
    }
    (work / 'stage-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
