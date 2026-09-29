#!/usr/bin/env python3
"""Optional independent cryptography verification; requires Python cryptography."""
from test_support import default_binary
import pathlib,subprocess,tempfile,struct,zipfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
exe=str(default_binary())
with tempfile.TemporaryDirectory() as d:
 p=pathlib.Path(d)
 def run(*args):subprocess.run([exe,*map(str,args)],check=True,capture_output=True)
 run('encryption-key','--out',p/'key');run('keygen','--out',p/'sign')
 source=p/'source';source.mkdir();(source/'payload').write_bytes(b'fixture\x00'*200000)
 run('collect','--root',source,'--out',p/'data','--case','T','--operator','T','--scope','T','--sign-key',p/'sign.key')
 with zipfile.ZipFile(p/'data') as z:
  Ed25519PublicKey.from_public_bytes(bytes.fromhex((p/'sign.pub').read_text(encoding="utf-8"))).verify(z.read('manifest.sig'),z.read('manifest.json'))
 run('seal','--in',p/'data','--out',p/'sealed','--key',p/'key')
 blob=(p/'sealed').read_bytes();header=blob[:16];assert header[:8]==b'K957ENC1';pos=16;index=0;plain=b''
 aes=AESGCM(bytes.fromhex((p/'key').read_text(encoding="utf-8")))
 while True:
  n=struct.unpack('>I',blob[pos:pos+4])[0];pos+=4
  block=aes.decrypt(header[8:]+struct.pack('>I',index),blob[pos:pos+n],header);pos+=n;index+=1
  if not block:assert pos==len(blob);break
  plain+=block
 assert plain==(p/'data').read_bytes()
 print('PASS: Ed25519 signature and AES-GCM envelope verified independently with Python cryptography')
