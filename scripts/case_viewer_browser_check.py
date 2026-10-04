#!/usr/bin/env python3
"""Exercise case viewer request ordering and navigation in headless Chromium using synthetic responses."""
import pathlib
import re
import shutil
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
chromium = shutil.which('chromium') or shutil.which('google-chrome')
if not chromium:
    raise SystemExit('Chromium is required for this explicit browser check')
source = (root / 'cmd/k957/case_access.go').read_text(encoding='utf-8')
script = re.search(r'const caseViewerScript = `(.*?)`', source, re.S).group(1)
fields = ['kind','text','host','digest','evidence','native-parser','native-record','usn-file-id','after','before']
html = '<!doctype html><form id="search">' + ''.join(f'<input id="{f}">' for f in fields) + '</form>'
html += '<p id="status"></p><button id="next"></button><button id="prev"></button><table><tbody id="rows"></tbody></table><pre id="detail"></pre><output id="result">PENDING</output>'
html += '<script>const pending=[];window.fetch=(url,options)=>new Promise(resolve=>pending.push({url,options,resolve}));</script>'
html += '<script>' + script + '</script>'
html += '''<script>
(async()=>{
 const check=(value,message)=>{if(!value)throw new Error(message)};
 const tick=()=>new Promise(resolve=>setTimeout(resolve,0));
 const row={kind:'event',collection_digest:'a'.repeat(64),evidence:'E1',source:'fixture',payload:{usn:{file_id_le_hex:'abcdef0123456789'}}};
 const finish=(i,rows,more=false,offset=0)=>pending[i].resolve({ok:true,json:async()=>({rows,more,offset})});
 try {
  document.getElementById('text').value='submitted';search();
  check(pending[0].options.signal.aborted,'previous request not cancelled');
  finish(1,[row],true);await tick();finish(0,[],false);await tick();
  check(document.getElementById('rows').children.length===1,'stale response replaced rows');
  document.getElementById('text').value='unsubmitted';document.getElementById('next').click();
  let q=new URL(pending[2].url,'http://localhost').searchParams;
  check(q.get('text')==='submitted'&&q.get('offset')==='100','pagination changed submitted filters');
  finish(2,[row],false,100);await tick();
  document.querySelectorAll('#rows button')[1].click();
  q=new URL(pending[3].url,'http://localhost').searchParams;
  check(q.get('digest')===row.collection_digest&&q.get('evidence')==='E1'&&q.get('usn-file-id')==='abcdef0123456789'&&!q.has('text')&&q.get('offset')==='0','related records lost scope');
  finish(3,[row]);await tick();document.getElementById('result').textContent='PASS';
 }catch(error){document.getElementById('result').textContent='FAIL '+error.message}
})();
</script>'''
with tempfile.TemporaryDirectory(prefix='k957-viewer-browser-') as tmp:
    work = pathlib.Path(tmp)
    page = work / 'fixture.html'
    page.write_text(html)
    result = subprocess.run([chromium,'--headless','--no-sandbox','--disable-gpu','--disable-background-networking',
                             '--no-first-run',f'--user-data-dir={work / "profile"}','--virtual-time-budget=3000',
                             '--dump-dom',page.as_uri()], capture_output=True,text=True,timeout=30)
    assert result.returncode == 0 and '<output id="result">PASS</output>' in result.stdout, result.stdout + result.stderr
print('PASS: Chromium synthetic viewer check: stale responses, cancellation, submitted pagination and scoped related records')
