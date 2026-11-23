#!/usr/bin/env python3
"""Agente de alertas del IDS (R3, G05): sigue eve.json de Suricata y avisa a identity.

Por cada alerta envía el origen (IP y MAC, del metadato Ethernet de EVE), la firma
y el instante del paquete que la disparó. identity identifica la sesión 802.1X del
atacante y lo bloquea en la tabla 2 de R-SW1 (y en cuarentena si reincide).
Agrupa alertas del mismo origen y firma durante unos segundos para no saturar.
Las firmas de trazabilidad de R2 (sid 2000000-2999999) van al mismo endpoint:
identity las registra como intentos denegados y no bloquea.
"""
import json
import os
import time
import urllib.request
from datetime import datetime

EVE = os.getenv('EVE', '/var/log/suricata/eve.json')
IDENTITY = os.getenv('IDENTITY_URL', 'http://192.168.0.16:5001/identity/alert')
HOLD = float(os.getenv('HOLD', '5'))       # s entre avisos del mismo origen y firma
recent = {}


def post(body):
    req = urllib.request.Request(IDENTITY, data=json.dumps(body).encode(),
                                 headers={'Content-Type': 'application/json'}, method='POST')
    try:
        urllib.request.urlopen(req, timeout=3).read()
        return True
    except OSError as e:
        print(f'no se pudo avisar a identity: {e}', flush=True)
        return False


def follow(path):
    while not os.path.exists(path):
        time.sleep(1)
    f = open(path)
    f.seek(0, os.SEEK_END)
    ino = os.fstat(f.fileno()).st_ino
    while True:
        line = f.readline()
        if line:
            yield line
            continue
        time.sleep(0.1)
        try:                                   # rotación del archivo
            if os.stat(path).st_ino != ino:
                f = open(path)
                ino = os.fstat(f.fileno()).st_ino
        except OSError:
            pass


def main():
    for line in follow(EVE):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get('event_type') != 'alert':
            continue
        a = e['alert']
        src_mac = (e.get('ether') or {}).get('src_mac')
        sid = a.get('signature_id') or 0
        # R2 (sid 2xxxxxx): un aviso por origen, firma y destino; R3: por origen y firma.
        key = (e.get('src_ip'), sid, e.get('dest_ip') if 2000000 <= sid < 3000000 else None)
        now = time.time()
        if now - recent.get(key, 0) < HOLD:
            continue
        recent[key] = now
        try:
            ts = datetime.strptime(e['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
        except (KeyError, ValueError):
            ts = now
        body = {'src_ip': e.get('src_ip'), 'src_mac': src_mac, 'dest_ip': e.get('dest_ip'),
                'dest_port': e.get('dest_port'), 'proto': e.get('proto'),
                'firma': a.get('signature'), 'sid': a.get('signature_id'),
                'severidad': a.get('severity'), 'ts': ts,
                'retardo_agente_ms': int((time.time() - ts) * 1000)}   # mismo reloj (IDS)
        ok = post(body)
        print(json.dumps({**body, 'enviado': ok}, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
