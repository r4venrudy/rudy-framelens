"""Black-box installed-command and independent byte/digest contract tests."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
sys.dont_write_bytecode=True
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('binary',type=Path);parser.add_argument('root',type=Path);args=parser.parse_args()
binary=args.binary.resolve();root=args.root.resolve();checks=0
def check(value,message):
    global checks
    checks+=1
    assert value,message
def run(*arguments,code=0):
    result=subprocess.run([binary,*map(str,arguments)],capture_output=True,text=True,encoding='utf-8',timeout=20)
    check(result.returncode==code,str(arguments)+'\n'+result.stdout+result.stderr)
    return result
def report(*arguments,code=0):return json.loads(run(*arguments,'--format','json',code=code).stdout)
spec=importlib.util.spec_from_file_location('synthetic',root/'examples/make_capture.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
with tempfile.TemporaryDirectory(prefix='framelens-contract-') as temp_name:
    temp=Path(temp_name);capture=temp/'captur\u00e9 \u0130';expected=fixture.create(capture)
    fixed,chunked,pipeline=[capture/name for name in ['fixed.http','chunked.http','pipeline.http']]
    original=fixed.read_bytes();j=report('inspect',fixed);m=j['messages'][0]
    check(j['complete'] and j['sourceRechecked'],'Full source parse and stability')
    check(j['sha256']==expected['sha256']['fixed.http'] and j['bytes']==len(original),'Independent source bytes and SHA-256')
    check(m['headerEnd']==expected['fixedHeaderEnd'] and m['end']==len(original),'Independent fixed body boundary')
    check(m['bodySha256']==expected['bodySha256'] and m['decodedBodyBytes']==expected['bodyBytes'],'Independent body identity')
    check(m['wireSha256']==hashlib.sha256(original).hexdigest(),'Wire digest covers all frame bytes')
    c=report('inspect',chunked);check(c['messages'][0]['bodySha256']==m['bodySha256'] and c['messages'][0]['chunkCount']==3,'Chunked body identity and count')
    for trace in c['messages'][0]['chunks']:
        wire=chunked.read_bytes();size_line=wire[trace['lineStart']:trace['dataStart']-2]
        check(int(size_line,16)==trace['bytes'],'Chunk line points to independently decoded size')
        check(wire[trace['wireEnd']-2:trace['wireEnd']]==b'\r\n','Chunk wire boundary')
    comp=report('compare',fixed,chunked,'--fail-on','changed')
    check(comp['comparable'] and comp['projectionEqual'] and comp['wireOnly']==1,'Reframing preserves documented projection')
    changed=report('compare',fixed,capture/'changed.http','--fail-on','changed',code=1)
    check(changed['modified']==1 and not changed['projectionEqual'],'Body changes reach the gate')
    p=report('inspect',pipeline,'--rows',1)
    check(p['summary']['messages']==2 and p['omittedMessages']==1 and len(p['messages'])==1,'Display truncation preserves full summary')
    incomplete=report('inspect',capture/'incomplete.http',code=2)
    check(not incomplete['complete'] and incomplete['summary']['validatedBytes']==expected['firstMessageEnd'],'Incomplete suffix preserves exact validated prefix')
    unknown=report('compare',fixed,capture/'incomplete.http','--fail-on','changed',code=2)
    check(not unknown['comparable'] and unknown['projectionEqual'] is None,'Unavailable comparison is not equal')
    conflict=report('inspect',capture/'conflict.http',code=2)
    check(conflict['problem']['code']=='te-cl-conflict' and conflict['summary']['messages']==0,'Conservative framing conflict policy')
    tr=report('inspect',capture/'trailers.http')
    check(tr['messages'][0]['trailerFields']==1 and tr['messages'][0]['trailerNames']==['x-demo-checksum'],'Trailers remain separate')
    for file in [fixed,chunked,pipeline,capture/'trailers.http']:
        html=run('inspect',file,'--format','html').stdout
        for private in ['demo.invalid','source=synthetic','hello from Rudy','application/octet-stream','invented']:
            check(private not in html,'Raw field, target, extension or body value leaked')
        check('<script' not in html and 'Content-Security-Policy' in html and 'Rudy FrameLens' in html,'Offline escaped report')
    destination=temp/'evidence \u00e9.html';run('inspect',fixed,'--format','html','--output',destination);saved=destination.read_bytes()
    run('inspect',fixed,'--output',destination,code=2);check(destination.read_bytes()==saved,'Existing reports preserved')
    alias=temp/'source-alias.http';os.link(fixed,alias);run('inspect',fixed,'--output',alias,code=2);check(fixed.read_bytes()==original,'Hard-link source preserved')
    if os.name!='nt':
        check(destination.stat().st_mode&0o777==0o600,'Private POSIX output mode')
        link=temp/'source-symlink.http';link.symlink_to(fixed);run('inspect',link,code=2)
        fifo=temp/'pipe';os.mkfifo(fifo);run('inspect',fifo,code=2)
    for extra in [['--rows','0'],['--rows','1001'],['--rows','1','--rows','2'],['--format','xml'],['--max-body-mib','-1'],['--max-input-mib','2049'],['--max-messages','0'],['--max-chunks','0'],['--fail-on','changed'],['--unknown','x'],['--format']]:run('inspect',fixed,*extra,code=2)
    for extra in [('compare',fixed),('compare',fixed,chunked,'--fail-on','wire'),('inspect',temp/'missing.http')]:run(*extra,code=2)
    budget=report('inspect',fixed,'--max-body-mib',0,code=2);check(budget['problem']['code']=='body-budget','Body budget fails before payload application')
    report('inspect',pipeline,'--max-messages',1,code=2);report('inspect',chunked,'--max-chunks',1,code=2)
    empty=temp/'empty.http';empty.write_bytes(b'');check(report('inspect',empty)['summary']['messages']==0,'Empty request stream is explicitly empty')
    huge=temp/'huge.http';huge.write_bytes(b'x'*(1024*1024+1));check(run('inspect',huge,'--max-input-mib',1,code=2).stdout=='','Input budget fails before report creation')
    many=temp/'many-fields.http';many.write_bytes(b'GET / HTTP/1.1\r\nHost: x\r\n'+b''.join(f'X-{i}: v\r\n'.encode() for i in range(40))+b'\r\n')
    names=report('inspect',many)['messages'][0];check(names['headerFields']==41 and len(names['headerNames'])==32 and names['omittedHeaderNames']==9,'Field-name omissions are explicit')
    check(run('--version').stdout.strip()=='framelens 0.1.0-preview','Version contract');run('--help')
    for path in [root/'README.md',*sorted((root/'docs').glob('*.md'))]:
        if path.exists():
            for target in re.findall(r'\]\(([^)#]+)(?:#[^)]*)?\)',path.read_text(encoding='utf-8')):
                if '://' not in target:check((path.parent/target).exists(),'Documentation target '+target)
print(f'FrameLens independent CLI checks passed: {checks}; digest/boundary oracles, projection gates, limits, privacy and output contracts.')
