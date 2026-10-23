#!/usr/bin/env python3
"""Replay explicit synthetic SQL steps using native sqlite3 trace_v2/profile.
Never open a live ledger: caller supplies a disposable copy and JSON step list.
Each step: {path,label,sql,binds:[...]}; finite labels allocated from input only.
This engine is independent of SQLx; reports its exact sqlite version/library.
"""
import argparse, ctypes as C, ctypes.util, json, time
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--database', required=True)
p.add_argument('--steps', required=True)
p.add_argument('--library', default=ctypes.util.find_library('sqlite3'))
a = p.parse_args()
steps = json.loads(Path(a.steps).read_text())
assert isinstance(steps, list) and 0 < len(steps) <= 100000
keys = {(s['path'], s['label']) for s in steps}
assert len(keys) <= 128, 'bounded statement labels required'
lib = C.CDLL(a.library)
void = C.c_void_p

def api(name, restype, args):
    fn = getattr(lib, name); fn.restype = restype; fn.argtypes = args; return fn
open_db = api('sqlite3_open_v2', C.c_int, [C.c_char_p, C.POINTER(void), C.c_int, C.c_char_p])
close_db = api('sqlite3_close', C.c_int, [void])
prepare = api('sqlite3_prepare_v2', C.c_int, [void, C.c_char_p, C.c_int, C.POINTER(void), C.POINTER(C.c_char_p)])
step = api('sqlite3_step', C.c_int, [void])
finalize = api('sqlite3_finalize', C.c_int, [void])
errmsg = api('sqlite3_errmsg', C.c_char_p, [void])
version = api('sqlite3_libversion', C.c_char_p, [])
column_count = api('sqlite3_column_count', C.c_int, [void])
column_text = api('sqlite3_column_text', C.c_char_p, [void, C.c_int])
stmt_status = api('sqlite3_stmt_status', C.c_int, [void, C.c_int, C.c_int])
bind_null = api('sqlite3_bind_null', C.c_int, [void, C.c_int])
bind_int = api('sqlite3_bind_int64', C.c_int, [void, C.c_int, C.c_longlong])
bind_text = api('sqlite3_bind_text', C.c_int, [void, C.c_int, C.c_char_p, C.c_int, void])
callback_t = C.CFUNCTYPE(C.c_int, C.c_uint, void, void, void)
trace = api('sqlite3_trace_v2', C.c_int, [void, C.c_uint, callback_t, void])
TRANSIENT = void(-1)
db = void(); rc = open_db(str(Path(a.database).resolve()).encode(), C.byref(db), 2, None)
if rc: raise RuntimeError('open failed')
records = {key: dict(calls=0, profile_ns=0, step_wall_ns=0, trace_stmt_events=0, trigger_events=0, vm_steps=0, fullscan_steps=0, sorts=0, autoindexes=0, rows=0) for key in keys}
current = None
@callback_t
def callback(kind, context, stmt, data):
    if current is None: return 0
    rec = records[current]
    if kind == 1:
        rec['trace_stmt_events'] += 1
        if data and C.string_at(data).startswith(b'--'):
            rec['trigger_events'] += 1
    elif kind == 2:
        rec['profile_ns'] += C.cast(data, C.POINTER(C.c_ulonglong)).contents.value
    return 0
trace(db, 3, callback, None)
try:
    for item in steps:
        current = (item['path'], item['label']); rec = records[current]
        stmt = void(); tail = C.c_char_p()
        rc = prepare(db, item['sql'].encode(), -1, C.byref(stmt), C.byref(tail))
        if rc: raise RuntimeError(errmsg(db).decode())
        assert not (tail.value or b'').strip(), 'one SQL statement per step'
        try:
            for index, value in enumerate(item.get('binds', []), 1):
                if value is None: rc = bind_null(stmt, index)
                elif isinstance(value, int): rc = bind_int(stmt, index, value)
                elif isinstance(value, str):
                    data = value.encode(); rc = bind_text(stmt, index, data, len(data), TRANSIENT)
                else: raise TypeError('only null, integer, text binds')
                if rc: raise RuntimeError(errmsg(db).decode())
            started = time.perf_counter_ns(); rc = step(stmt)
            while rc == 100:
                rec['rows'] += 1
                if item.get('capture_rows'):
                    captured = rec.setdefault('captured_rows', [])
                    if len(captured) < 300:
                        captured.append([(column_text(stmt, c) or b'').decode() for c in range(column_count(stmt))])
                rc = step(stmt)
            rec['step_wall_ns'] += time.perf_counter_ns() - started
            if rc != 101: raise RuntimeError(errmsg(db).decode())
            rec['calls'] += 1
            for key, opcode in [('fullscan_steps', 1), ('sorts', 2), ('autoindexes', 3), ('vm_steps', 4)]:
                rec[key] += stmt_status(stmt, opcode, 0)
        finally: finalize(stmt)
finally:
    current = None
    close_db(db)
print(json.dumps({'library': a.library, 'sqlite_version': version().decode(), 'semantics': 'PROFILE outer statement duration includes trigger programs; trace trigger events are counts, not trigger-exclusive durations; PROFILE has approximate millisecond resolution; step wall time excludes prepare/bind and includes Python callback overhead; separate engine is not SQLx timing evidence', 'statements': [{'path': k[0], 'label': k[1], **records[k]} for k in sorted(records)]}, indent=2))
