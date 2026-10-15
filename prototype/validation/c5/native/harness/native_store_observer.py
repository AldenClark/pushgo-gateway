"""Read-only native PG/MySQL observer; never creates or mutates Gateway data.
C5_DB_URL_FILE is issued by the isolated environment owner for one c5_* DB.
The only SQL rewrite is observer positional ? -> DB-API %s; product SQL is untouched.
"""
import os,pathlib,sys,urllib.parse,re,ssl,json,fcntl
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'vendor'))
class NativeStoreObserver:
 def __init__(self):
  path=pathlib.Path(os.environ['C5_DB_URL_FILE']).resolve()
  allowed=ROOT.parent/'env'
  assert path.is_relative_to(allowed), 'URL file outside owned C5 env'
  assert path.stat().st_mode & 0o077 == 0, 'URL file must be private'
  self.url=path.read_text().strip();u=urllib.parse.urlsplit(self.url)
  self.backend='postgres' if u.scheme in ('postgres','postgresql') else 'mysql' if u.scheme=='mysql' else None
  assert self.backend and self.backend==os.environ['C5_DB_BACKEND']
  assert u.hostname in ('127.0.0.1','localhost') and re.fullmatch(r'c5_[a-z0-9_]+',u.path[1:]), 'not owned synthetic c5 database'
  self.database=u.path[1:];self.host=u.hostname;self.port=u.port
  with (allowed/'cases.lock').open('a') as lock:
   fcntl.flock(lock,fcntl.LOCK_SH)
   state=json.loads((allowed/('pg-owned.json' if self.backend=='postgres' else 'mysql-owned.json')).read_text())
  assert state['cases'].get(self.database,{}).get('url_file')==str(path), 'not a captured fresh case URL'
  assert state['endpoint']==f'{u.hostname}:{u.port}', 'owned container endpoint mismatch'
  self.kw=dict(host=u.hostname,port=u.port,user=urllib.parse.unquote(u.username or ''),password=urllib.parse.unquote(u.password or ''),database=self.database)
 def query(self,sql,args=()):
  assert sql.lstrip().upper().startswith('SELECT ') and ';' not in sql, 'read-only observer only'
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
   cur.execute(sql.replace('?','%s'),tuple(args))
   names=[v[0] for v in cur.description]
   return [dict(zip(names,row)) for row in cur.fetchall()]
  finally:conn.rollback();conn.close()
 def metadata(self):return dict(backend=self.backend,database=self.database,host=self.host,port=self.port,namespace='pushgo_c' if self.backend=='postgres' else self.database,access='read-only separate native DB-API connection')
