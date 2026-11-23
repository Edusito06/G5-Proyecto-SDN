#!/usr/bin/env python3
"""Agente de eventos AAA (G05): sigue el log del ONOS local y los envía a identity.

En el clúster, la app AAA procesa el EAPOL en el nodo master del switch y solo ese
nodo escribe los eventos en su log. Este agente corre en cada nodo ONOS y reenvía
a identity los eventos que la REST de AAA no refleja (por ejemplo el EAPOL-Logoff,
que solo aparece como "AUTHORIZED -> IDLE").

  STARTED / APPROVED / DENIED / UNAUTHORIZED / TIMEOUT  -> con dispositivo y puerto
  FAILURE (Send EAP failure ... MacAddress X)           -> con dispositivo, puerto y MAC
  IDLE    (Moving from AUTHORIZED state to IDLE state)  -> sin puerto (logoff)
"""
import json
import os
import re
import subprocess
import time
import urllib.request

IDENTITY = os.getenv('IDENTITY_URL', 'http://192.168.0.16:5001/identity/aaa')
NODE = os.uname().nodename
ANSI = re.compile(r'\x1b\[[0-9;]*m')
PATTERNS = [
    (re.compile(r'Auth event (STARTED|APPROVED|DENIED|UNAUTHORIZED|TIMEOUT) for (of:\w+)/(\d+)'),
     lambda m: {'ev': m.group(1), 'dev': m.group(2), 'port': m.group(3)}),
    (re.compile(r'Send EAP failure message to supplicant on dev/port: (of:\w+)/(\d+) with MacAddress ([0-9A-Fa-f:]{17})'),
     lambda m: {'ev': 'FAILURE', 'dev': m.group(1), 'port': m.group(2), 'mac': m.group(3).lower()}),
    (re.compile(r'Moving from AUTHORIZED state to IDLE state'),
     lambda m: {'ev': 'IDLE'}),
]


def send(event):
    event.update({'nodo': NODE, 'ts': time.time()})
    req = urllib.request.Request(IDENTITY, data=json.dumps(event).encode(),
                                 headers={'Content-Type': 'application/json'}, method='POST')
    try:
        urllib.request.urlopen(req, timeout=3).read()
    except OSError as e:
        print(f'no se pudo avisar a identity: {e}', flush=True)


def main():
    while True:
        p = subprocess.Popen(['docker', 'logs', '-f', '--since', '1s', 'onos'],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        for raw in p.stdout:
            line = ANSI.sub('', raw)
            for rx, build in PATTERNS:
                m = rx.search(line)
                if m:
                    send(build(m))
                    break
        print('log de ONOS cerrado; reintento en 3 s', flush=True)
        time.sleep(3)


if __name__ == '__main__':
    main()
