from __future__ import annotations
import base64,hashlib,json,os,re,tempfile,urllib.request
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from firmware_publish import _b64url_decode,_send_json,_validated_publisher
MAX_BODY_BYTES=512*1024; PUBLISH_DOMAIN=b'JaroslavZemanESP|z2m-publish-v1|'; ADDON_CONFIGS_ROOT=Path('/addon_configs'); _PROJECT_RE=re.compile(r'^[A-Za-z0-9_.-]{1,96}$')
def _find_zigbee2mqtt_config_dir():
 c=[p for p in ADDON_CONFIGS_ROOT.iterdir() if p.is_dir() and (p.name.lower()=='zigbee2mqtt' or p.name.lower().endswith('_zigbee2mqtt') or 'zigbee2mqtt' in p.name.lower())] if ADDON_CONFIGS_ROOT.is_dir() else []
 if len(c)!=1:raise ValueError('zigbee2mqtt_addon_config_not_found_or_ambiguous')
 return c[0]
def _restart_zigbee2mqtt():
 token=os.environ.get('SUPERVISOR_TOKEN','')
 if not token:raise ValueError('supervisor_token_missing_for_zigbee2mqtt_restart')
 with urllib.request.urlopen(urllib.request.Request('http://supervisor/addons',headers={'Authorization':f'Bearer {token}'}),timeout=10) as r:p=json.loads(r.read())
 a=p.get('data',{}).get('addons',[]);m=[str(x.get('slug') or '') for x in a if str(x.get('slug') or '')=='zigbee2mqtt' or str(x.get('slug') or '').endswith('_zigbee2mqtt') or str(x.get('name') or '').lower()=='zigbee2mqtt']
 if len(m)!=1:raise ValueError('zigbee2mqtt_supervisor_addon_not_found_or_ambiguous')
 with urllib.request.urlopen(urllib.request.Request(f'http://supervisor/addons/{m[0]}/restart',data=b'',headers={'Authorization':f'Bearer {token}'},method='POST'),timeout=30) as r:r.read()
def _write_verified(target,data):
 old=target.read_bytes() if target.is_file() else None;fd,tmp=tempfile.mkstemp(prefix='.'+target.name+'.',dir=target.parent)
 try:
  with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
  os.replace(tmp,target)
 except Exception:
  try:os.unlink(tmp)
  except OSError:pass
  raise
 if target.read_bytes()!=data:raise ValueError('zigbee2mqtt_deploy_verify_failed')
 return old!=data,hashlib.sha256(data).hexdigest()
def handle_zigbee2mqtt_publish(handler):
 try:
  length=int(handler.headers.get('Content-Length','0'))
  if length<=0 or length>MAX_BODY_BYTES:raise ValueError('invalid_zigbee2mqtt_bundle_size')
  req=json.loads(handler.rfile.read(length));project=str(req.get('project') or '')
  if not _PROJECT_RE.fullmatch(project):raise ValueError('invalid_project_name')
  if int(req.get('schema') or 0)!=2:raise ValueError('unsupported_zigbee2mqtt_publish_schema')
  version=str(req.get('firmware_version') or '').strip();files=req.get('files');expected=f'{project}.mjs'
  if not version or not isinstance(files,dict) or set(files)!={expected}:raise ValueError('invalid_single_converter_file_set')
  data=base64.b64decode(str(files[expected]),validate=True)
  if len(data)>256*1024:raise ValueError('zigbee2mqtt_file_too_large')
  marker=re.search(rb'^// JarZem firmware build: (.+)$',data,re.M)
  if not marker or marker.group(1).decode().strip()!=version:raise ValueError('zigbee2mqtt_firmware_build_marker_mismatch')
  digest=hashlib.sha256(expected.encode()+b'\0'+data+b'\0').hexdigest();cert,publisher,_=_validated_publisher(str(req.get('certificate') or ''));sig=_b64url_decode(str(req.get('signature') or ''));cert.public_key().verify(sig,PUBLISH_DOMAIN+project.encode()+b'|'+digest.encode(),ec.ECDSA(hashes.SHA256()))
  target_dir=_find_zigbee2mqtt_config_dir()/'external_converters';target_dir.mkdir(parents=True,exist_ok=True);target=target_dir/expected;changed,file_sha=_write_verified(target,data)
  removed=[]
  for legacy in (target_dir/f'{project}.project.mjs',target_dir/f'{project}.ota.mjs'):
   if legacy.exists():legacy.unlink();removed.append(legacy.name);changed=True
  if target.read_bytes()!=data:raise ValueError('zigbee2mqtt_deploy_verify_failed')
  print(f'Zigbee2MQTT converter deployed file={expected} build={version} changed={int(changed)} sha256={file_sha[:12]} bytes={len(data)} removed={removed}',flush=True)
  if changed:_restart_zigbee2mqtt()
  _send_json(handler,201,{'status':'PUBLISHED','project':project,'firmware_version':version,'changed':changed,'directory':str(target_dir),'files':{expected:file_sha},'removed':removed})
 except Exception as exc:
  print(f'Zigbee2MQTT converter publish rejected: {exc}',flush=True);_send_json(handler,400,{'status':'ERROR','error':str(exc)})
