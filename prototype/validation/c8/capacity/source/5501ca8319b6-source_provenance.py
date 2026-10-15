#!/usr/bin/env python3
"""Read-only immutable Git+overlay identity checks; never builds or runs Gateway."""
import hashlib,pathlib,subprocess
def sha(data):return hashlib.sha256(data).hexdigest()
def verify(identity,root):
    if identity.get('verification_mode')!='git-objects-and-frozen-overlay':
        assert pathlib.Path(identity['source_root']).resolve()==root.resolve()
        for rel,expected in identity['source_sha256'].items():
            assert sha((root/rel).read_bytes())==expected,('source identity changed',rel)
        return {'mode':'frozen live source bytes','files':len(identity['source_sha256'])}
    commit=identity['source_commit'];original=identity['original_source_sha256']
    observed_tree=subprocess.check_output(['git','rev-parse',commit+'^{tree}'],cwd=root,text=True).strip()
    assert observed_tree==identity['source_tree'],'Git tree differs'
    paths=sorted(original)
    request=''.join(commit+':'+name+'\n' for name in paths).encode()
    process=subprocess.run(['git','cat-file','--batch'],input=request,capture_output=True,cwd=root)
    assert process.returncode==0,'Git blob read failed'
    raw=process.stdout;position=0
    for name in paths:
        end=raw.index(b'\n',position);header=raw[position:end].split();assert len(header)==3 and header[1]==b'blob',('not a blob',name)
        size=int(header[2]);position=end+1;content=raw[position:position+size]
        assert sha(content)==original[name],('immutable source bytes differ',name)
        position+=size;assert raw[position:position+1]==b'\n';position+=1
    assert position==len(raw),'unexpected Git output tail'
    overlay=pathlib.Path(identity['frozen_overlay_root']);combined=dict(original)
    for rel,expected in identity['frozen_overlay_sha256'].items():
        assert sha((overlay/rel).read_bytes())==expected,('frozen overlay changed',rel)
        combined[rel]=expected
    assert combined==identity['source_sha256'],'Git + overlay do not reproduce recorded build inputs'
    return {'mode':'immutable Git objects + frozen observer overlay','files':len(combined),'tree':observed_tree}
