"""Test a native installed layout, generate invented reports, and archive controlled files."""
from pathlib import Path
import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
sys.dont_write_bytecode=True
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('stage',type=Path);parser.add_argument('target',choices=['linux-x64','windows-x64','macos-arm64']);parser.add_argument('--version',required=True);parser.add_argument('--go',default='go');args=parser.parse_args()
source=Path(__file__).resolve().parents[1];stage=args.stage.resolve();binary=stage/'bin'/('framelens.exe' if os.name=='nt' else 'framelens')
def run(*arguments,code=0):
    result=subprocess.run([binary,*map(str,arguments)],capture_output=True,text=True,encoding='utf-8',timeout=30)
    assert result.returncode==code,result.stdout+result.stderr
    return result.stdout
assert run('--version').strip()=='framelens '+args.version
for name in ['README.md','LICENSE','SECURITY.md','CONTRIBUTING.md']:shutil.copyfile(source/name,stage/name)
for name in ['docs','assets','examples']:shutil.copytree(source/name,stage/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
goroot=Path(subprocess.check_output([args.go,'env','GOROOT'],text=True).strip());(stage/'licenses').mkdir()
for name in ['LICENSE','PATENTS']:shutil.copyfile(goroot/name,stage/'licenses'/('GO-'+name))
spec=importlib.util.spec_from_file_location('synthetic',source/'examples/make_capture.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
capture=stage/'examples/synthetic';expected=fixture.create(capture)
inspection=json.loads(run('inspect',capture/'pipeline.http','--format','json'))
comparison=json.loads(run('compare',capture/'fixed.http',capture/'chunked.http','--format','json','--fail-on','changed'))
assert inspection['complete'] and inspection['summary']['messages']==2 and inspection['summary']['validatedBytes']==expected['pipelineBytes']
assert comparison['comparable'] and comparison['projectionEqual'] and comparison['wireOnly']==1
(capture/'inspection.json').write_text(json.dumps(inspection,indent=2)+'\n',encoding='utf-8');(capture/'comparison.json').write_text(json.dumps(comparison,indent=2)+'\n',encoding='utf-8')
run('inspect',capture/'pipeline.http','--format','html','--output',capture/'inspection.html')
run('compare',capture/'fixed.http',capture/'chunked.http','--format','html','--output',capture/'comparison.html')
destination=source/'dist';destination.mkdir(exist_ok=True);archive=destination/('framelens-'+args.version+'-'+args.target+('.zip' if args.target=='windows-x64' else '.tar.gz'));assert not archive.exists(),'Refusing to replace an existing package'
files=sorted(p for p in stage.rglob('*') if '__pycache__' not in p.parts and p.suffix!='.pyc');assert all(not p.is_symlink() for p in files)
if archive.suffix=='.zip':
    with zipfile.ZipFile(archive,'x',compression=zipfile.ZIP_DEFLATED) as output:
        for file in files:output.write(file,file.relative_to(stage).as_posix())
else:
    with tarfile.open(archive,'x:gz') as output:
        for file in files:output.add(file,arcname=file.relative_to(stage).as_posix(),recursive=False)
print('Installed example oracles passed; created',archive.name)
