#!/usr/bin/env python3
from __future__ import annotations
import argparse,base64,hashlib,json,re,ssl,subprocess,urllib.error,urllib.request
from pathlib import Path
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
PUBLISH_DOMAIN=b'JaroslavZemanESP|firmware-publish-v1|'; Z2M_PUBLISH_DOMAIN=b'JaroslavZemanESP|z2m-publish-v1|'
def b64url(d): return base64.urlsafe_b64encode(d).decode().rstrip('=')
def sha256(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def detected_version(project,build):
 d=build/'project_description.json'
 if d.is_file():
  try:
   v=str(json.loads(d.read_text()).get('project_version') or '').strip()
   if v:return v
  except Exception:pass
 try:return subprocess.check_output(['git','-C',str(project),'describe','--tags','--always','--dirty'],text=True,stderr=subprocess.DEVNULL,timeout=5).strip()
 except Exception:return 'unknown'
def post(req,ctx,label):
 try:
  with urllib.request.urlopen(req,timeout=120,context=ctx) as r:return json.loads(r.read())
 except urllib.error.HTTPError as e:raise SystemExit(f'{label} rejected HTTP {e.code}: {e.read().decode(errors="replace")}')
 except Exception as e:raise SystemExit(f'{label} failed: {e}')
def publish_z2m(url,name,build,version,cert,key,ctx):
 p=build/'zigbee2mqtt'/f'{name}.mjs'
 if not p.is_file():raise SystemExit(f'Generated Zigbee2MQTT converter missing: {p}')
 data=p.read_bytes(); m=re.search(rb'^// JarZem firmware build: (.+)$',data,re.M); cv=m.group(1).decode().strip() if m else 'missing'
 if cv!=version:raise SystemExit(f'Converter/firmware build mismatch: converter={cv} firmware={version}')
 digest=hashlib.sha256(p.name.encode()+b'\0'+data+b'\0').hexdigest(); canonical=Z2M_PUBLISH_DOMAIN+name.encode()+b'|'+digest.encode(); sig=key.sign(canonical,ec.ECDSA(hashes.SHA256()))
 body=json.dumps({'schema':2,'project':name,'firmware_version':version,'files':{p.name:base64.b64encode(data).decode()},'certificate':b64url(cert.read_bytes()),'signature':b64url(sig)},separators=(',',':')).encode()
 result=post(urllib.request.Request(url+'/api/zigbee2mqtt/publish',data=body,headers={'Content-Type':'application/json'},method='POST'),ctx,'Zigbee2MQTT converter publish')
 if result.get('status')!='PUBLISHED':raise SystemExit(f'Zigbee2MQTT converter publish rejected: {result}')
 print(f'JarZem OTA Zigbee2MQTT converter published: project={name} build={version} changed={int(bool(result.get("changed")))}')
def main():
 a=argparse.ArgumentParser();a.add_argument('--project',type=Path,required=True);a.add_argument('--build',type=Path,required=True);a.add_argument('--project-name',required=True);x=a.parse_args();project=x.project.resolve();build=x.build.resolve();cp=project/'.jarzem_ota'/'project.json'
 if not cp.is_file():raise SystemExit('JarZem OTA project manifest is missing; build output will not be published.')
 c=json.loads(cp.read_text());binp=build/f'{x.project_name}.bin'; creds=project/'device_credentials';keyp=creds/'device_private.pem';cert=creds/'device_cert.pem';ca=creds/'root_ca_cert.pem'
 for p in (binp,keyp,cert,ca):
  if not p.is_file():raise SystemExit(f'Required publish file missing: {p}')
 meta=dict(c.get('firmware') or {});meta['firmware_version']=detected_version(project,build);required=('ota_ecosystem','device_model','product_role','firmware_product','hardware_revision','chip_family','flash_size','firmware_channel','firmware_version');missing=[k for k in required if not str(meta.get(k) or '').strip()]
 if missing:raise SystemExit('Firmware publish metadata missing: '+', '.join(missing))
 meta.setdefault('secure_version',0);meta.setdefault('active',True);fn=str(c.get('firmware_filename') or f"{meta['firmware_product']}.bin");digest=sha256(binp);mb=b64url(json.dumps(meta,separators=(',',':'),sort_keys=True).encode());canonical=PUBLISH_DOMAIN+fn.encode()+b'|'+digest.encode()+b'|'+mb.encode();key=serialization.load_pem_private_key(keyp.read_bytes(),password=None)
 if not isinstance(key,ec.EllipticCurvePrivateKey):raise SystemExit('Installed device private key is not EC.')
 sig=key.sign(canonical,ec.ECDSA(hashes.SHA256()));url=str(c.get('publish_url') or '').rstrip('/');ctx=ssl.create_default_context(cafile=str(ca));headers={'Content-Type':'application/octet-stream','X-Firmware-Filename':fn,'X-Firmware-SHA256':digest,'X-Firmware-Metadata':mb,'X-Publisher-Certificate':b64url(cert.read_bytes()),'X-Publisher-Signature':b64url(sig)};result=post(urllib.request.Request(url+'/api/firmware/publish',data=binp.read_bytes(),headers=headers,method='POST'),ctx,'Firmware publish')
 if result.get('status')!='PUBLISHED':raise SystemExit(f'Firmware publish rejected: {result}')
 print(f'JarZem OTA firmware published: {fn} version={meta["firmware_version"]} sha256={digest[:12]}');publish_z2m(url,x.project_name,build,meta['firmware_version'],cert,key,ctx)
if __name__=='__main__':main()
