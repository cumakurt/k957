#!/usr/bin/env python3
"""Native process-termination/restart test with independently checked parts."""
from test_support import default_binary
import hashlib,json,pathlib,subprocess,tempfile,time,zipfile
base=pathlib.Path(__file__).resolve().parents[1]
exe=str(default_binary())
with tempfile.TemporaryDirectory() as d:
 p=pathlib.Path(d);root=p/'source';root.mkdir();source=root/'large.bin'
 with source.open('wb') as f:
  for i in range(192):f.write(bytes([i%256])*(1<<20))
 package=p/'case.k957';work=p/'work'
 args=[exe,'collect','--root',str(root),'--out',str(package),'--work',str(work),'--case','RESTART','--operator','Test','--scope','Synthetic interruption test']
 proc=subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 deadline=time.monotonic()+20;interrupted=False
 try:
  while time.monotonic()<deadline:
   if proc.poll() is not None:break
   try:
    state=json.loads((work/'state.json').read_text(encoding="utf-8"))
    if state['files'][0]['item'].get('parts') and not state['files'][0]['complete']:
     proc.kill();proc.wait(timeout=10);interrupted=True;break
   except (FileNotFoundError,json.JSONDecodeError,IndexError):pass
   time.sleep(.005)
 finally:
  if proc.poll() is None:proc.kill();proc.wait()
 stderr=proc.stderr.read().decode('utf-8',errors='replace');proc.stderr.close()
 assert interrupted,f'did not hit a saved mid-file checkpoint (exit {proc.returncode}): {stderr}'
 assert (work/'active.lock').exists(),'expected stale lock after forced process termination'
 checkpoint=(work/'state.json').read_bytes()
 plan_args=[exe,'preflight','--resume','--root',str(root),'--out',str(package),'--work',str(work),'--reserve','0']
 plan=subprocess.run(plan_args,capture_output=True,text=True,encoding='utf-8')
 assert plan.returncode!=0 and any(c['code']=='WORK_LOCK_PRESENT' for c in json.loads(plan.stdout)['checks'])
 assert (work/'state.json').read_bytes()==checkpoint
 locked=subprocess.run(args+['--resume'],capture_output=True,text=True, encoding="utf-8")
 assert locked.returncode!=0 and 'locked' in locked.stderr
 # We own this test process and have waited for its exit; manual stale-lock
 # recovery is safe here. Never remove a lock from a possibly active collector.
 (work/'active.lock').unlink()
 plan=subprocess.run(plan_args,check=True,capture_output=True,text=True,encoding='utf-8')
 budget=json.loads(plan.stdout)
 saved=sum(part['size'] for part in json.loads(checkpoint)['files'][0]['item']['parts'])
 assert budget['resume'] and budget['acquired_bytes']==saved
 assert budget['remaining_bytes']==source.stat().st_size-saved and budget['estimated_output_bytes']>=source.stat().st_size
 assert (work/'state.json').read_bytes()==checkpoint
 result=subprocess.run(args+['--resume','--check-space','--reserve','0'],capture_output=True,text=True, encoding="utf-8")
 assert result.returncode==0,result.stderr
 subprocess.run([exe,'verify','--in',str(package)],check=True,capture_output=True)
 with zipfile.ZipFile(package) as z:
  m=json.loads(z.read('manifest.json'));assert m['schema']=='k957-evidence/2'
  assert len(m['epochs'])==2 and 'interrupted' in m['epochs'][0]['outcome']
  item=m['items'][0];assert len(set(part['epoch'] for part in item['parts']))==2
  full=hashlib.sha256()
  with z.open(item['object']) as f,source.open('rb') as original:
   for part in item['parts']:
    data=f.read(part['size']);assert data==original.read(part['size'])
    assert hashlib.sha256(data).hexdigest()==part['sha256'];full.update(data)
   assert not f.read(1)
  assert full.hexdigest()==item['sha256']
 subprocess.run([exe,'analyze','--in',str(package),'--out',str(p/'report')],check=True,capture_output=True)
 report=(p/'report'/'report.html').read_text(encoding="utf-8");assert 'Edinim dönemleri' in report
 print('PASS: forced process termination after checkpoint, stale lock preflight rejection, read-only remaining-space plan, gated recovery, source-prefix validation, independent 192 MiB/24-part hashes, two epochs, report')
