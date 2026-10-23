#!/usr/bin/env python3
"""C8 bounded final-artifact runner; public synthetic TLS keys stay in memory."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

p = argparse.ArgumentParser()
p.add_argument('--binary', required=True)
p.add_argument('--commit', required=True)
p.add_argument('--output', required=True)
p.add_argument('--tls', action='store_true')
p.add_argument('test_args', nargs=argparse.REMAINDER)
a = p.parse_args()
out = Path(a.output)
out.mkdir(parents=True, exist_ok=True)
binary = Path(a.binary).resolve(strict=True)
args = a.test_args
if args and args[0] == '--':
    args = args[1:]
free = os.statvfs(out).f_bavail * os.statvfs(out).f_frsize
if free < 4 * 1024**3 + 128 * 1024**2:
    raise SystemExit('RESOURCE_STOP: 4GiB plus bounded test growth required')
env = os.environ.copy()
fds = ()
read_fd = write_fd = None
if a.tls:
    native = out.parents[1] / 'native'
    sys.path.insert(0, str(native / 'source'))
    from synthetic_tls_material import leaf_pem_for_anonymous_pipe
    public = native / 'synthetic-tls-public'
    read_fd, write_fd = os.pipe()
    fds = (read_fd,)
    env.update(PUSHGO_C6_CERT_PEM=str(public / 'leaf.pem'),
               PUSHGO_C6_CA_PEM=str(public / 'ca.pem'),
               PUSHGO_C6_KEY_PEM='/dev/fd/' + str(read_fd))
command = [str(binary)] + args
start = time.monotonic()
receipt = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'command': command, 'source_commit': a.commit,
           'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
           'free_before_bytes': free, 'tls': a.tls,
           'key_storage': 'anonymous pipe only' if a.tls else None}
with (out / 'stdout.log').open('w') as log:
    child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                             env=env, pass_fds=fds)
    if a.tls:
        os.close(read_fd)
        read_fd = None
        material = leaf_pem_for_anonymous_pipe()
        os.write(write_fd, material)
        del material
        os.close(write_fd)
        write_fd = None
    try:
        rc = child.wait(timeout=240)
    except subprocess.TimeoutExpired:
        child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
        rc = 'TIMEOUT'
receipt.update(exit_code=rc, elapsed_s=time.monotonic()-start,
               free_after_bytes=os.statvfs(out).f_bavail * os.statvfs(out).f_frsize)
(out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(receipt))
raise SystemExit(0 if rc == 0 else 1)
