#!/usr/bin/env python3
"""Check structured events, source byte offsets and cross-evidence entities."""
from test_support import default_binary
import pathlib,json,subprocess,tempfile,csv,hashlib
base=pathlib.Path(__file__).resolve().parents[1];exe=str(default_binary())
with tempfile.TemporaryDirectory() as d:
 p=pathlib.Path(d);root=p/'source';root.mkdir()
 data=b'timestamp,user,host,src_ip,message\r\n\r\n2026-09-27T14:00:00+03:00,alice,HOST.,::ffff:192.0.2.1,"first\nsecond"\r\ninvalid,alice,HOST.,192.0.2.1,bad time\r\n'
 (root/'a.csv').write_bytes(data)
 records=[{'timestamp':'2026-09-27T11:01:00Z','username':'alice','hostname':'host','destination_ip':'192.0.2.1','message':'second source'}, {'timestamp':'2026-09-27T11:02:00Z','user':'Alice','src_ip':'invalid'}]
 (root/'b.jsonl').write_text('\n'.join(json.dumps(v) for v in records), encoding="utf-8")
 def run(*args):return subprocess.run([exe,*map(str,args)],check=True,capture_output=True,text=True, encoding="utf-8")
 package=p/'case.k957';run('collect','--root',root,'--out',package,'--case','STRUCTURED','--operator','Test','--scope','Synthetic')
 before=hashlib.sha256(package.read_bytes()).hexdigest()
 run('analyze','--in',package,'--out',p/'report')
 a=json.loads((p/'report'/'analysis.json').read_text(encoding="utf-8"))
 assert len(a['correlations'])==3
 for c in a['correlations']:
  assert c['sources']==2 and c['events']==2
  assert {r['evidence'] for r in c['references']}=={'E000001','E000002'}
 summaries=a['parse_summaries'];assert all(s['rows']==2 and s['parsed']==1 and s['skipped']==1 for s in summaries)
 event=next(e for e in a['timeline'] if e['type']=='log_timestamp' and e['source'].endswith('.csv'))
 assert event['line']==3 and event['time']=='2026-09-27T11:00:00Z'
 assert data[event['byte_offset']:].startswith(b'2026-09-27T14:00:00')
 assert event['source_ip']=='192.0.2.1' and event['detail']=='first\nsecond'
 with (p/'report'/'correlations.csv').open(encoding="utf-8") as f:assert len(list(csv.DictReader(f)))==3
 assert hashlib.sha256(package.read_bytes()).hexdigest()==before
 print('PASS: CSV/JSONL parsing, skipped-record counts, byte offsets, UTC conversion, 3 cross-evidence entities, CSV export, unchanged evidence')
