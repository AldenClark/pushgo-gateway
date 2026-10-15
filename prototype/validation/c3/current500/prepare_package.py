#!/usr/bin/env python3
"""Materialize the diagnostic fixture package against an explicit frozen mainline checkout.
Does not build, execute a service, copy production source, or modify the checkout.
"""
import argparse,json,pathlib,shutil,subprocess
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--mainline-source',required=True,type=pathlib.Path)
p.add_argument('--out',required=True,type=pathlib.Path)
a=p.parse_args();source=a.mainline_source.resolve();out=a.out.resolve()
expected='dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6'
actual=subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()
assert actual==expected,'Use the exact historical mainline checkout; later product source needs new evidence'
assert not subprocess.check_output(['git','status','--porcelain'],cwd=source,text=True).strip(),'Historical mainline source must be clean'
out.mkdir(parents=True,exist_ok=False);here=pathlib.Path(__file__).resolve().parent
text=(here/'Cargo.toml.template').read_text().replace('"__MAINLINE_GATEWAY_SOURCE__"',json.dumps(str(source)))
(out/'Cargo.toml').write_text(text)
for name in ['Cargo.lock','fixture.rs']:shutil.copyfile(here/name,out/name)
print(json.dumps({'package':str(out),'source_commit':actual,'execution':'NOT RUN; build separately with an approved runtime window'}))
