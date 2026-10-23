#!/usr/bin/env python3
"""Offline identity partitioning only; unchanged C8 strict reducer owns each cutoff oracle."""
import argparse,hashlib,json,pathlib,struct
import reduce_commits
RECORD=struct.Struct('<QQQ32s32sB7x')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):
 with p.open() as f:
  for line in f:yield json.loads(line)
def partition_and_reduce(run,out):
 assert not out.exists();out.mkdir(parents=True)
 meta=json.loads((run/'telemetry.json').read_text());expected=list(read(run/'expected-targets.jsonl'));by_identity={};groups={}
 for row in expected:
  groups.setdefault(row['cycle'],[]).append(row)
  if row['delivery_id'] is not None:
   identity=(row['delivery_id'],row['device_key']);assert identity not in by_identity;by_identity[identity]=row['cycle']
 streams={label:(out/(label+'-commits.bin')).open('xb') for label in groups};counts={label:0 for label in groups};seen=0;warmup=0
 try:
  with (run/'commits.bin').open('rb') as f:
   while raw:=f.read(RECORD.size):
    assert len(raw)==RECORD.size,'partialoriginalstreamrecord'
    tick,attempt,sequence,delivery,device,state=RECORD.unpack(raw);seen+=1;delivery=delivery.decode();device=device.decode()
    if delivery in meta['excluded_acknowledged_warmup_ids']:warmup+=1;continue
    identity=(delivery,device);assert identity in by_identity,'originalcallbackhasnoexpectedofferedidentity; preserveoriginalfailure'
    label=by_identity[identity];streams[label].write(raw);counts[label]+=1
 finally:
  for stream in streams.values():stream.close()
 assert seen==meta['emitted'],'globaloriginalstreamcountmismatch'
 summaries={}
 for label,rows in groups.items():
  deadlines={row['absolute_deadline_mach_ticks'] for row in rows};assert len(deadlines)==1;cutoff=deadlines.pop()
  expected_path=out/(label+'-expected.jsonl')
  with expected_path.open('x') as f:
   for row in rows:f.write(json.dumps(row)+'\n')
  view={**meta,'expected_targets':len(rows),'emitted':counts[label],'measurement_cutoff_mach_ticks':cutoff,'excluded_acknowledged_warmup_ids':[],
        'derived_view_only':True,'global_writer_receipt_and_stream_semantics_unchanged':True,'original_global_emitted':seen,'original_global_warmup_events':warmup,
        'original_stream_sha256':sha(run/'commits.bin'),'original_telemetry_sha256':sha(run/'telemetry.json')}
  meta_path=out/(label+'-telemetry.json');meta_path.write_text(json.dumps(view,indent=2)+'\n')
  summary=reduce_commits.reduce(expected_path,out/(label+'-commits.bin'),meta_path,out/(label+'-scratch.sqlite'))
  summaries[label]=summary
  (out/(label+'-summary.json')).write_text(json.dumps(summary,indent=2)+'\n')
 (out/'summary.json').write_text(json.dumps({'scope':'offlineper-cycleidentityviewsfromoneunchangedglobalstream;globalwriterdropsinvalidatesall;unchangedC8strictreducer','global_stream_sha256':sha(run/'commits.bin'),'global_emitted':seen,'warmup_excluded':warmup,'cycles':summaries},indent=2)+'\n')
 return summaries
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('run',type=pathlib.Path);p.add_argument('out',type=pathlib.Path);a=p.parse_args();print(json.dumps(partition_and_reduce(a.run,a.out),indent=2))
