#!/usr/bin/env python3
"""C9 A profile, explicitly source-bound; baseline reducer and output stay unchanged."""
import importlib.util,json,pathlib,sys
base=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('profile',base/'summarize_c9_profile.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
p=pathlib.Path(sys.argv[1]);r=m.summarize(p);plan=json.loads((p/'plan.json').read_text());assert plan['source_commit']=='1b9836a3a1c98d0c6a8e7a7559ea9676c0027c9a'
r['semantics']='SQLx caller wall timers; candidate A Usage is 3-SQL bundle, baseline is 4-SQL. Samples count bundle invocations, never engine statement count. COMMIT includes worker scheduling; nested phases overlap and must not sum. Histogram quantiles bucket upper bounds, not exact. MySQL pool_acquire includes owner check.'
r['source_bound_annotation']={'candidate_commit':plan['source_commit'],'candidate_binary_sha256':plan['binary_sha256'],'Usage_SQL_calls_per_bundle':3,'baseline_Usage_SQL_calls_per_bundle':4,'actual_engine_total_from_profile':'NOT_IDENTIFIED','baseline_outputs_modified':False};out=p/'profile-interior-summary.json';assert not out.exists();out.write_text(json.dumps(r,indent=2)+'\n')
