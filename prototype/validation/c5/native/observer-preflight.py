import pathlib,subprocess,os,sys,json,traceback,hashlib
ROOT=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT/'harness'))
helper=ROOT.parent/'env/isolated_db.py';rows=[]
for engine in ['pg','mysql']:
 case=json.loads(subprocess.check_output([sys.executable,str(helper),'create',engine,'native_observer'],text=True));os.environ.update(C5_DB_URL_FILE=case['url_file'],C5_DB_BACKEND='postgres' if engine=='pg' else engine)
 from native_store_observer import NativeStoreObserver
 try:
  observer=NativeStoreObserver()
  selected=observer.query('SELECT CAST(? AS '+('BIGINT' if engine=='pg' else 'SIGNED')+') AS exact_integer, ? AS exact_text, NULL AS null_value',(37,'c5 synthetic bound text'))
  assert selected==[{'exact_integer':37,'exact_text':'c5 synthetic bound text','null_value':None}],selected
  assert observer.query('SELECT ? AS intended WHERE ?=?',('right-source','right-source','wrong-source'))==[]
  rejected=False
  try:observer.query('DELETE FROM messages')
  except AssertionError:rejected=True
  assert rejected,'mutation guard inactive'
  version=observer.query('SELECT version() AS engine_version')
  read_only=False
  try:observer.query('SELECT 1; DELETE FROM messages')
  except AssertionError:read_only=True
  assert read_only
  rows.append({'status':'PASSED','engine':engine,'storage':observer.metadata(),'selected':selected,'wrong_source_empty':True,'mutation_and_multi_statement_rejected':True,'engine_version':version,'no_app_gateway_emulator_started':True})
 except BaseException as error:
  path=ROOT/f'observer-{engine}-first-failure.json'
  if not path.exists():path.write_text(json.dumps({'error':repr(error),'traceback':traceback.format_exc()},indent=2)+'\n')
  raise
 finally:
  subprocess.run([sys.executable,str(helper),'drop',engine,case['database']],check=True)
(ROOT/'observer-preflight.json').write_text(json.dumps({'status':'PASSED','runs':rows},indent=2)+'\n')
print(json.dumps({'status':'PASSED','backends':[r['engine'] for r in rows],'checks':'bound int/text/null + wrong-source empty + mutation/multi-statement denied'}))
