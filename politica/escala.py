#!/usr/bin/env python3
"""Escalabilidad de R2 (G05): sesiones sintéticas sobre el mismo camino que usa identity.

Se ejecuta en ONOS-1, en /opt/g05/politica, con identity DETENIDO (si no, su worker
retiraría las reglas sintéticas en su próxima reconciliación):

  python3 escala.py nivel <n>          base real + n sesiones sintéticas; mide la
                                       reconciliación y el tiempo hasta ADDED
  python3 escala.py tasa <n> <k>       desde base + n, agrega k sesiones de a una
                                       (como identity con cada login) y mide cada paso
  python3 escala.py rafaga <n> <k>     desde base + n, agrega k sesiones de golpe
  python3 escala.py base               vuelve a las sesiones reales
  python3 escala.py fijar <n>          base + n sintéticas, solo la llamada REST (sin esperar):
                                       el orquestador mide en OVS cuándo están las reglas

Las sesiones sintéticas usan MAC 02:aa:00:00:xx:xx (no existen en la red: no generan
tráfico), roles 1-5 en rotación e IPs fuera del pool de Kea (.2-.99 de cada subred).
"""
import json
import os
import sys
import time

os.environ['R2_LOCAL'] = '1'
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import r2ctl  # noqa: E402

STATE = os.getenv('R2_SESSIONS', '/var/lib/r2/sessions.json')
pol, topo = r2ctl.load()
DPID = topo['switches']['r-sw1']['dpid']


def base():
    try:
        return [s for s in json.load(open(STATE)) if s.get('ip')]
    except (OSError, ValueError):
        return []


def sinteticas(desde, n):
    out = []
    for i in range(desde, desde + n):
        rol = (1, 2, 3, 4, 5)[i % 5]
        out.append({'nombre': f'sint{i:03d}', 'usuario': f'sint{i:03d}',
                    'mac': f'02:aa:00:00:{i // 256:02x}:{i % 256:02x}',
                    'switch': 'r-sw1', 'puerto': 4, 'rol': rol,
                    'ip': f'10.{rol * 10}.0.{2 + i // 5}', 'estado': 'VINCULADO',
                    'inicio': time.time(), 'expira': time.time() + 3600})
    return out


def flujos():
    fl = [f for f in r2ctl.installed() if f['deviceId'] == DPID]
    return len(fl), sum(1 for f in fl if f['state'] == 'ADDED')


def aplicar(snap):
    """Reconciliación (lo que hace identity) + espera hasta que el switch confirme."""
    t0 = time.time()
    add, rem, _ = r2ctl.reconcile(pol, topo, snap)
    t1 = time.time()
    want = len(r2ctl.diff(pol, topo, sessions=snap)[1])
    added = 0
    for _ in range(300):
        tot, added = flujos()
        if added >= want and tot == want:
            break
        time.sleep(0.1)
    t2 = time.time()
    return {'agregadas': add, 'retiradas': rem, 'reglas': want, 'added': added,
            'rest_ms': int((t1 - t0) * 1000), 'hasta_added_ms': int((t2 - t0) * 1000)}


def main():
    cmd = sys.argv[1]
    b = base()
    if cmd == 'fijar':
        n = int(sys.argv[2])
        snap = b + sinteticas(0, n)
        t0 = time.time()
        add, rem, _ = r2ctl.reconcile(pol, topo, snap)
        print(json.dumps({'sesiones': len(snap), 'agregadas': add, 'retiradas': rem,
                          'rest_ms': int((time.time() - t0) * 1000),
                          'reglas': len(r2ctl.diff(pol, topo, sessions=snap)[1])}))
        return
    if cmd == 'base':
        print(json.dumps({'sesiones': len(b), **aplicar(b)}))
    elif cmd == 'nivel':
        n = int(sys.argv[2])
        print(json.dumps({'sesiones': len(b) + n, **aplicar(b + sinteticas(0, n))}))
    elif cmd in ('tasa', 'rafaga'):
        n, k = int(sys.argv[2]), int(sys.argv[3])
        snap = b + sinteticas(0, n)
        aplicar(snap)
        if cmd == 'rafaga':
            r = aplicar(snap + sinteticas(n, k))
            print(json.dumps({'desde': len(snap), 'nuevas': k, **r}))
            return
        pasos = []
        for j in range(k):
            snap = snap + sinteticas(n + j, 1)
            pasos.append(aplicar(snap))
        ms = sorted(p['hasta_added_ms'] for p in pasos)
        print(json.dumps({'desde': len(b) + n, 'nuevas': k,
                          'mediana_ms': ms[len(ms) // 2], 'max_ms': ms[-1],
                          'reglas_por_sesion': pasos[-1]['reglas'] - pasos[-2]['reglas'] if k > 1 else None,
                          'pasos_ms': [p['hasta_added_ms'] for p in pasos]}))


if __name__ == '__main__':
    main()
