"""C6 synthetic-only, separate read-only native SQLite/PG/MySQL observation.
URL files are supplied by the environment owner; this helper provisions nothing.
Only observer placeholders change between DB-API drivers, never product SQL.
"""
import fcntl,json,os,pathlib,re,sqlite3,ssl,sys,urllib.parse
C6=pathlib.Path(__file__).resolve().parents[2]
class NativeStoreObserver:
 def __init__(self):
  self.backend=os.environ['C6_DB_BACKEND']
  if self.backend=='sqlite':
   self.path=pathlib.Path(os.environ['C6_SQLITE_PATH']).resolve()
   assert self.path.is_relative_to(C6/'provider-native'), 'SQLite path outside C6 Provider evidence'
   self.database=str(self.path);self.host=None;self.port=None
   self.url='sqlite://'+str(self.path)+'?mode=rwc'
   return
  assert self.backend in ('postgres','mysql')
  allowed=pathlib.Path(os.environ['C6_DB_ENV_ROOT']).resolve()
  assert allowed.is_relative_to(C6/'env'), 'environment owner outside C6 env'
  path=pathlib.Path(os.environ['C6_DB_URL_FILE']).resolve()
  assert path.is_relative_to(allowed), 'URL file outside selected C6 environment'
  assert path.stat().st_mode & 0o077 == 0, 'URL file must be private'
  self.url=path.read_text().strip();u=urllib.parse.urlsplit(self.url)
  assert u.scheme in (('postgres','postgresql') if self.backend=='postgres' else ('mysql',))
  assert u.hostname in ('127.0.0.1','localhost') and re.fullmatch(r'c6_[a-z0-9_]+',u.path[1:]), 'not owned synthetic C6 database'
  self.database=u.path[1:];self.host=u.hostname;self.port=u.port
  # The provisioning owner creates the lock; no observer-created lock/state files.
  with (allowed/'cases.lock').open('r') as lock:
   fcntl.flock(lock,fcntl.LOCK_SH)
   state=json.loads((allowed/('pg-owned.json' if self.backend=='postgres' else 'mysql-owned.json')).read_text())
  assert state['cases'].get(self.database,{}).get('url_file')==str(path), 'not a captured case URL'
  assert state['endpoint']==f'{u.hostname}:{u.port}', 'owned endpoint mismatch'
  vendor=pathlib.Path(os.environ['C6_OBSERVER_DEPENDENCIES']).resolve()
  sys.path.insert(0,str(vendor))
  self.kw=dict(host=u.hostname,port=u.port,user=urllib.parse.unquote(u.username or ''),password=urllib.parse.unquote(u.password or ''),database=self.database)
 def query(self,sql,args=()):
  assert sql.lstrip().upper().startswith('SELECT ') and ';' not in sql, 'read-only observer only'
  if self.backend=='sqlite':
   conn=sqlite3.connect(self.path.as_uri()+'?mode=ro',uri=True,timeout=5)
   conn.row_factory=sqlite3.Row
   try:
    conn.execute('PRAGMA query_only=ON')
    return [dict(row) for row in conn.execute(sql,tuple(args))]
   finally:conn.close()
  if self.backend=='postgres':
   import pg8000.dbapi
   conn=pg8000.dbapi.connect(**self.kw,timeout=5)
  else:
   import pymysql
   context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
   conn=pymysql.connect(**self.kw,connect_timeout=5,read_timeout=5,write_timeout=5,ssl=context)
  try:
   cur=conn.cursor();cur.execute('SET TRANSACTION READ ONLY')
   if self.backend=='postgres':cur.execute('SET LOCAL search_path TO pushgo_c,pg_catalog')
   cur.execute(sql.replace('?','%s'),tuple(args));names=[v[0] for v in cur.description]
   return [dict(zip(names,row)) for row in cur.fetchall()]
  finally:conn.rollback();conn.close()
 def metadata(self):return dict(backend=self.backend,database=self.database,host=self.host,port=self.port,namespace='pushgo_c' if self.backend=='postgres' else self.database,access='read-only separate native connection')
