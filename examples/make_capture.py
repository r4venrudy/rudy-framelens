"""Invent request streams for offline tests. No requests are sent."""
from pathlib import Path
import argparse
import hashlib
import json

def create(destination):
    destination=Path(destination);destination.mkdir(parents=True,exist_ok=False)
    body=b'hello from Rudy\n'
    headers=b'POST /demo?source=synthetic HTTP/1.1\r\nHost: demo.invalid\r\nContent-Type: application/octet-stream\r\n'
    fixed=headers+b'Content-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
    chunks=b''.join(f'{len(part):x}\r\n'.encode()+part+b'\r\n' for part in [body[:3],body[3:10],body[10:]])
    chunked=headers+b'Transfer-Encoding: chunked\r\n\r\n'+chunks+b'0\r\n\r\n'
    second=b'GET /second HTTP/1.1\r\nHost: demo.invalid\r\n\r\n'
    streams={'fixed.http':fixed,'chunked.http':chunked,'pipeline.http':fixed+second,'changed.http':fixed[:-1]+b'!',
             'incomplete.http':fixed+second[:-1],
             'conflict.http':b'POST /demo HTTP/1.1\r\nHost: demo.invalid\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n',
             'trailers.http':headers+b'Transfer-Encoding: chunked\r\nTrailer: X-Demo-Checksum\r\n\r\n'+chunks+b'0\r\nX-Demo-Checksum: invented\r\n\r\n'}
    for name,data in streams.items():(destination/name).write_bytes(data)
    expected={'schema':'rudy-framelens/synthetic-v1','sha256':{name:hashlib.sha256(data).hexdigest() for name,data in streams.items()},'bodySha256':hashlib.sha256(body).hexdigest(),'bodyBytes':len(body),'fixedHeaderEnd':fixed.index(b'\r\n\r\n')+4,'firstMessageEnd':len(fixed),'pipelineBytes':len(fixed+second)}
    (destination/'expected.json').write_text(json.dumps(expected,indent=2)+'\n',encoding='utf-8')
    return expected

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('new_directory',type=Path);args=parser.parse_args();create(args.new_directory)
    print('Created seven invented request captures and independent expected byte identities.')
