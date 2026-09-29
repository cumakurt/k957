#!/usr/bin/env python3
"""Forced process termination/restart plus independent AES-GCM verification of encrypted staging.
Optional dependency: Python cryptography. Run with the native platform binary.
"""
from test_support import default_binary
import pathlib,json,subprocess,tempfile,time,hashlib,hmac,zipfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
base=pathlib.Path(__file__).resolve().parents[1];exe=str(default_binary())
with tempfile.TemporaryDirectory() as d:
 p=pathlib.Path(d);root=p/'source';root.mkdir();marker=b'K957_PRIVATE_SYNTHETIC_MARKER_050';source=root/'sensitive.bin'
 with source.open('wb') as f:
  for i in range(192):f.write(marker+bytes([i%256])*((1<<20)-len(marker)))
 key=p/'transport.key';work=p/'work';out=p/'case.k957.enc'
 def run(*args,ok=True):
  r=subprocess.run([exe,*map(str,args)],capture_output=True,text=True, encoding="utf-8");assert (r.returncode==0)==ok,(args,r.stderr);return r
 run('encryption-key','--out',key);run('encryption-key','--out',p/'wrong.key')
 master=bytes.fromhex(key.read_text(encoding="utf-8"))
 aes=AESGCM(hmac.new(master,b'k957/stage/aead/v1',hashlib.sha256).digest())
 name_key=hmac.new(master,b'k957/stage/name/v1',hashlib.sha256).digest()
 def decrypt_blob(path,purpose):
  b=path.read_bytes();assert b[:8]==b'K957STG1'
  return aes.decrypt(b[8:20],b[20:],b'aes256-gcm-stage/1:'+purpose.encode())
 args=['collect','--root',root,'--work',work,'--out',out,'--case','ENCRYPTED','--operator','Test','--scope','Synthetic encrypted collection','--encryption-key',key]
 proc=subprocess.Popen([exe,*map(str,args)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 killed=False;deadline=time.monotonic()+25
 try:
  while time.monotonic()<deadline:
   if proc.poll() is not None:break
   try:
    s=json.loads(decrypt_blob(work/'state.enc','state'))
    if s['files'][0]['item'].get('parts') and not s['files'][0]['complete']:
     proc.kill();proc.wait(timeout=10);killed=True;break
   except FileNotFoundError:pass
   time.sleep(.005)
 finally:
  if proc.poll() is None:proc.kill();proc.wait()
 stderr=proc.stderr.read().decode('utf-8',errors='replace');proc.stderr.close()
 assert killed,f'did not interrupt after encrypted checkpoint (exit {proc.returncode}): {stderr}'
 assert not (work/'state.json').exists();assert (work/'active.lock').exists()
 preflight_args=['preflight','--resume','--root',root,'--out',out,'--work',work,'--reserve','0','--encryption-key',key]
 blocked=json.loads(run(*preflight_args,ok=False).stdout)
 assert any(c['code']=='WORK_LOCK_PRESENT' for c in blocked['checks'])
 run(*args,'--resume',ok=False)
 # Only after waiting for our own child process to exit is its stale lock removed.
 (work/'active.lock').unlink()
 before=(work/'state.enc').read_bytes()
 bad=args.copy();bad[-1]=p/'wrong.key';run(*bad,'--resume',ok=False)
 bad_plan=preflight_args.copy();bad_plan[-1]=p/'wrong.key';run(*bad_plan,ok=False)
 assert before==(work/'state.enc').read_bytes()
 budget=json.loads(run(*preflight_args).stdout)
 saved=sum(part['size'] for part in json.loads(decrypt_blob(work/'state.enc','state'))['files'][0]['item']['parts'])
 assert budget['resume'] and budget['encrypted'] and budget['acquired_bytes']==saved
 assert budget['remaining_bytes']==source.stat().st_size-saved and budget['estimated_output_bytes']>=source.stat().st_size
 assert before==(work/'state.enc').read_bytes()
 result=json.loads(run(*args,'--resume','--check-space','--reserve','0').stdout);assert result['encrypted'] and isinstance(result['items'],int) and 'case' not in result
 status=json.loads(run('work-status','--work',work,'--verify-parts','--encryption-key',key).stdout);assert status['encrypted'] and status['completed_files']==1
 s=json.loads(decrypt_blob(work/'state.enc','state'));assert len(s['manifest']['epochs'])==2
 for part in s['files'][0]['item']['parts']:
  name=hmac.new(name_key,part['sha256'].encode(),hashlib.sha256).hexdigest();assert name!=part['sha256']
  data=decrypt_blob(work/'chunks'/name,'chunk:'+part['sha256']);assert hashlib.sha256(data).hexdigest()==part['sha256']
 for path in work.rglob('*'):
  if path.is_file():assert marker not in path.read_bytes() and str(root).encode() not in path.read_bytes()
 assert out.read_bytes().startswith(b'K957ENC1') and marker not in out.read_bytes()
 run('unseal','--in',out,'--out',p/'plain.k957','--key',key);run('verify','--in',p/'plain.k957')
 with zipfile.ZipFile(p/'plain.k957') as z:
  m=json.loads(z.read('manifest.json'));item=m['items'][0]
  digest=hashlib.sha256()
  with z.open(item['object']) as acquired,source.open('rb') as original:
   while True:
    block=acquired.read(8<<20)
    if not block:break
    assert block==original.read(len(block));digest.update(block)
  assert digest.hexdigest()==item['sha256']
 print('PASS: encrypted forced process termination/restart, authenticated remaining-space preflight, gated recovery, wrong-key refusal, independent state/chunk AES-GCM and HMAC verification, no fixture plaintext in work/output, 192 MiB final source equality')
