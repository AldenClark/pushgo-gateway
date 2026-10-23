#!/usr/bin/env python3
"""Explicit operator-only lifecycle for one new disposable synthetic PostgreSQL.
Never starts OrbStack, pulls an image, reuses a database, or removes named state.
"""
import json, os, pathlib, re, subprocess, sys, time, uuid
ROOT = pathlib.Path(__file__).resolve().parent
STATE = ROOT / 'owned-container.json'
IMAGE = 'postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777'
KEY = 'io.pushgo.c4.synthetic.owner'
DOCKER = ['docker', '--context', 'orbstack']
def call(args, **kw):
    return subprocess.check_output(DOCKER + args, text=True, **kw).strip()
def check_context():
    ctx = json.loads(call(['context', 'inspect', 'orbstack']))[0]
    expected = 'unix://' + str(pathlib.Path.home() / '.orbstack/run/docker.sock')
    if ctx['Endpoints']['docker']['Host'] != expected:
        raise RuntimeError('Refuse non-local or unexpected Docker endpoint')
def owned():
    state = json.loads(STATE.read_text())
    if not re.fullmatch(r'[a-f0-9]{64}', state['id']) or not re.fullmatch(r'[a-f0-9]{32}', state['owner']):
        raise RuntimeError('Invalid ownership receipt')
    info = json.loads(call(['inspect', state['id']]))[0]
    if info['Id'] != state['id'] or info['Config']['Labels'].get(KEY) != state['owner']:
        raise RuntimeError('Ownership mismatch; refuse removal')
    if info['Name'] != '/pushgo-c4-pg-' + state['owner']:
        raise RuntimeError('Name mismatch; refuse removal')
    return state, info

def start():
    if os.environ.get('C4_PG_LAUNCH_APPROVED') != 'YES_NEW_SYNTHETIC_ONLY':
        raise RuntimeError('Launch requires explicit operator approval environment')
    if STATE.exists():
        raise RuntimeError('Ownership receipt already exists; never reuse existing database')
    call(['image', 'inspect', IMAGE])  # Existing pinned image only. No pull.
    token = uuid.uuid4().hex
    name = 'pushgo-c4-pg-' + token
    db = 'c4_synthetic_' + token
    user = 'c4_test_' + token
    ident = call(['run', '--pull=never', '--detach', '--name', name,
        '--label', KEY + '=' + token, '--memory=1g', '--memory-swap=1g',
        '--cpus=2', '--pids-limit=128', '--network=bridge',
        '--publish', '127.0.0.1::5432', '--read-only',
        '--tmpfs', '/var/lib/postgresql/data:rw,size=640m',
        '--tmpfs', '/var/run/postgresql:rw,size=16m',
        '--tmpfs', '/tmp:rw,size=16m', '--shm-size=64m',
        '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'POSTGRES_DB=' + db,
        '-e', 'POSTGRES_USER=' + user, IMAGE,
        '-c', 'shared_buffers=32MB', '-c', 'max_connections=30',
        '-c', 'max_wal_size=128MB', '-c', 'min_wal_size=32MB',
        '-c', 'log_statement=none'])
    if not re.fullmatch(r'[a-f0-9]{64}', ident):
        raise RuntimeError('Unexpected Docker ID; inspect manually')
    with STATE.open('x') as out:
        os.chmod(STATE, 0o600)
        json.dump({'id': ident, 'owner': token, 'database': db, 'user': user, 'image': IMAGE}, out, indent=2)
    # On failure keep the receipt and first failure; operator can clean the exact ID.
    for _ in range(60):
        result = subprocess.run(DOCKER + ['exec', ident, 'pg_isready', '-U', user, '-d', db], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            break
        time.sleep(0.5)
    else:
        raise RuntimeError('Fresh container not ready after 30s; receipt retained')
    port = call(['port', ident, '5432/tcp'])
    if not re.fullmatch(r'127\.0\.0\.1:[0-9]+', port):
        raise RuntimeError('Unexpected published endpoint; receipt retained')
    url = 'postgresql://' + port + '/' + db + '?user=' + user
    (ROOT / 'synthetic-db-url.txt').write_text(url + '\n')
    print(json.dumps({'status': 'READY', 'id': ident, 'database': db, 'endpoint': port, 'url_file': str(ROOT / 'synthetic-db-url.txt')}))

check_context()
command = sys.argv[1] if len(sys.argv) == 2 else ''
if command == 'start':
    start()
elif command == 'status':
    state, info = owned()
    print(json.dumps({'id': state['id'], 'database': state['database'], 'status': info['State']['Status'], 'image': info['Image'], 'mount_types': [m['Type'] for m in info['Mounts']]}))
elif command == 'cleanup':
    state, info = owned()
    call(['rm', '--force', state['id']])
    STATE.rename(ROOT / ('removed-' + state['owner'] + '.json'))
    (ROOT / 'synthetic-db-url.txt').unlink(missing_ok=True)
    print('Removed only the captured C4-owned container ID; tmpfs data discarded')
else:
    raise SystemExit('usage: isolated_pg.py start|status|cleanup')
