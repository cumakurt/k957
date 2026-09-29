#!/usr/bin/env python3
"""Independent end-to-end package/hash verification; only Python stdlib needed."""
from test_support import default_binary
import hashlib,json,pathlib,subprocess,tempfile,zipfile,sys
exe=str(pathlib.Path(sys.argv[1] if len(sys.argv)>1 else default_binary()).resolve())
with tempfile.TemporaryDirectory() as work:
 p=pathlib.Path(work);root=p/'source';root.mkdir()
 (root/'auth.log').write_text('2026-09-27T14:00:00+03:00 failed password\n',encoding='utf-8')
 (root/'binary.dat').write_bytes(bytes(range(256))*10)
 def run(*args,ok=True):
  r=subprocess.run([exe,*map(str,args)],capture_output=True,text=True, encoding="utf-8")
  assert (r.returncode==0)==ok,(args,r.returncode,r.stderr)
  return r
 run('keygen','--out',p/'sign');run('encryption-key','--out',p/'transport.key')
 package=p/'case.k957'
 run('collect','--root',root,'--out',package,'--case','INTEGRATION','--operator','Test','--scope','Synthetic only','--sign-key',p/'sign.key')
 with zipfile.ZipFile(package) as z:
  m=json.loads(z.read('manifest.json'));assert m['status']=='complete'
  assert len(m['items'])==2
  for i in m['items']:
   data=z.read(i['object']);assert len(data)==i['size'];assert hashlib.sha256(data).hexdigest()==i['sha256']
   assert data==pathlib.Path(i['source']).read_bytes()
 run('verify','--in',package,'--trusted-key',p/'sign.pub')
 run('seal','--in',package,'--out',p/'sealed','--key',p/'transport.key')
 run('unseal','--in',p/'sealed','--out',p/'restored','--key',p/'transport.key')
 assert package.read_bytes()==(p/'restored').read_bytes()
 run('analyze','--in',p/'restored','--trusted-key',p/'sign.pub','--out',p/'report','--rules','examples/rules.json')
 a=json.loads((p/'report'/'analysis.json').read_text(encoding="utf-8"));assert len(a['findings'])==1
 event=next(e for e in a['timeline'] if e['type']=='log_timestamp');assert event['time']=='2026-09-27T11:00:00Z'
 bad=p/'bad.k957'
 with zipfile.ZipFile(package) as zin,zipfile.ZipFile(bad,'w') as zout:
  for i in zin.infolist():
   data=zin.read(i.filename)
   if i.filename.startswith('objects/'):data=b'X'+data[1:]
   zout.writestr(i.filename,data)
 run('verify','--in',bad,ok=False)
 run('collect','--root',root,'--out',p/'small.k957','--case','T','--operator','T','--scope','T','--max-file','1',ok=False)
 result=json.loads(run('verify','--in',p/'small.k957').stdout);assert result['collection_status']=='partial'
 print('PASS: native CLI, independent ZIP hashes, signature, encryption roundtrip, log timezone, tamper rejection, partial status')
