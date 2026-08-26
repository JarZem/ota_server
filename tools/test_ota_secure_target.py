#!/usr/bin/env python3
"""Generate ESP->OTA MQTT test vectors so the ESP can be completely bypassed.

hello: signs H with the device private key and prints the MQTT action topic/payload.
response: verifies an A frame from OTA, signs R with the device key, prints MQTT action topic/payload.
"""
import argparse, base64
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def b64d(s): return base64.urlsafe_b64decode(s+"="*((-len(s))%4))
def rawsig(der):
    r,s=decode_dss_signature(der); return r.to_bytes(32,"big")+s.to_bytes(32,"big")
def dersig(raw): return encode_dss_signature(int.from_bytes(raw[:32],"big"),int.from_bytes(raw[32:],"big"))
def load_key(p): return serialization.load_pem_private_key(Path(p).read_bytes(),password=None)
def load_cert(p): return x509.load_pem_x509_certificate(Path(p).read_bytes())
def canon_a(device,counter,rnd): return f"A|{device}|{counter}|".encode()+rnd
def canon_r(device,counter,rnd): return f"R|{device}|{counter}|".encode()+rnd+b"|OK"
def show(device,wire):
    print("TOPIC:",f"zigbee2mqtt/0x{device.replace(':','')}/action")
    print("PAYLOAD:",wire)
    print("WIRE_BYTES:",len(wire.encode()))

def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd",required=True)
    h=sub.add_parser("hello"); h.add_argument("--device-id",required=True); h.add_argument("--counter",type=int,required=True); h.add_argument("--device-key",required=True)
    r=sub.add_parser("response"); r.add_argument("--device-id",required=True); r.add_argument("--counter",type=int,required=True); r.add_argument("--device-key",required=True); r.add_argument("--ota-cert",required=True); r.add_argument("--challenge",required=True)
    a=p.parse_args(); key=load_key(a.device_key)
    if a.cmd=="hello":
        canonical=f"H|{a.device_id}|{a.counter}".encode(); sig=rawsig(key.sign(canonical,ec.ECDSA(hashes.SHA256())))
        show(a.device_id,f"H|{a.counter}|{b64u(sig)}"); return
    parts=a.challenge.split("|")
    if len(parts)!=3 or parts[0]!="A": raise SystemExit("invalid A frame")
    rnd=b64d(parts[1]); sig=b64d(parts[2])
    if len(rnd)!=8 or len(sig)!=64: raise SystemExit("invalid A lengths")
    ota=load_cert(a.ota_cert)
    ota.public_key().verify(dersig(sig),canon_a(a.device_id,a.counter,rnd),ec.ECDSA(hashes.SHA256()))
    print("A_VERIFY: OK")
    rsig=rawsig(key.sign(canon_r(a.device_id,a.counter,rnd),ec.ECDSA(hashes.SHA256())))
    show(a.device_id,f"R|{b64u(rsig)}")
if __name__=="__main__": main()
