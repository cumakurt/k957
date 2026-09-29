#!/usr/bin/env python3
"""CLI review lifecycle: signed revisions, exact basis, rejected tampering."""
from test_support import default_binary
import hashlib,json,pathlib,subprocess,tempfile
base=pathlib.Path(__file__).resolve().parents[1];exe=str(default_binary())
with tempfile.TemporaryDirectory() as d:
 p=pathlib.Path(d);source=p/'source';source.mkdir();(source/'log').write_text('2026-09-27T00:00:00Z failed password\n', encoding="utf-8")
 def run(*args,ok=True):
  r=subprocess.run([exe,*map(str,args)],capture_output=True,text=True, encoding="utf-8");assert (r.returncode==0)==ok,(args,r.stderr);return r
 package=p/'evidence';rules=base/'examples/rules.json'
 run('collect','--root',source,'--out',package,'--case','REVIEW','--operator','Test','--scope','Synthetic review')
 before=hashlib.sha256(package.read_bytes()).hexdigest()
 run('analyze','--in',package,'--rules',rules,'--out',p/'first')
 analysis=p/'first'/'analysis.json';a=json.loads(analysis.read_text(encoding="utf-8"));finding=a['findings'][0]['id']
 run('keygen','--out',p/'sign')
 run('review','--analysis',analysis,'--finding',finding,'--decision','needs-review','--analyst','Alice','--note','Initial review','--sign-key',p/'sign.key','--out',p/'v1.json')
 v1=(p/'v1.json').read_bytes()
 run('review','--analysis',analysis,'--previous',p/'v1.json','--previous-key',p/'sign.pub','--finding',finding,'--decision','rejected','--analyst','Bob','--note','Synthetic test data','--sign-key',p/'sign.key','--out',p/'v2.json')
 run('analyze','--in',package,'--rules',rules,'--reviews',p/'v2.json','--review-key',p/'sign.pub','--out',p/'reviewed')
 b=json.loads((p/'reviewed'/'analysis.json').read_text(encoding="utf-8"));assert b['findings'][0]['review']=='rejected';assert len(b['review_history'])==2
 assert a['findings'][0]['id']==b['findings'][0]['id'];assert (p/'v1.json').read_bytes()==v1
 assert hashlib.sha256(package.read_bytes()).hexdigest()==before
 modified=json.loads((p/'v2.json').read_text(encoding="utf-8"));modified['events'][0]['note']='tampered';(p/'bad.json').write_text(json.dumps(modified), encoding="utf-8")
 run('analyze','--in',package,'--rules',rules,'--reviews',p/'bad.json','--out',p/'bad-report',ok=False);assert not (p/'bad-report').exists()
 changed=p/'changed-rules.json';changed.write_text('[{"id":"R","contains":"password"}]', encoding="utf-8")
 run('analyze','--in',package,'--rules',changed,'--reviews',p/'v2.json','--out',p/'wrong-basis',ok=False)
 print('PASS: signed two-revision CLI review, fresh reanalysis, stable IDs, evidence/old revision unchanged, tamper and changed-rule rejection')
