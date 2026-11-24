#!/bin/bash
# Pruebas de R4 (G05): DDoS por consumo de ancho de banda, identificación de la fuente y
# mitigación con meter sin afectar el tráfico legítimo. Desde el Mac con los canales
# ~/.ssh/ctl-<puerto> (5806 ONOS-1, 5811 Recursos, 5813 Alumno).
#
#  víctima:   Mesa de ayuda (10.100.1.150, VM Recursos, interfaz ens4)
#  testigo:   invitado en u-inv (descarga HTTP de la víctima durante todo el ataque)
#  atacantes: alu01 (802.1X, u-alu) e invitados en u-doc y u-net
#  ataque:    inundación TCP ACK con 1200 B de carga hacia :80 (hping3). No tiene firma
#             en R3 (no es SYN ni HTTP): solo se ve por volumen.
#
# Ritmo del ataque acotado (~100 Mbit/s en total): el espejo de R3 copia el tráfico de
# usuarios por la red de gestión, que también lleva la sincronización del clúster.
exec python3 - "$@" <<'PY'
import json, os, statistics, subprocess, sys, threading, time
GW = '10.20.12.7'
VICTIMA = '10.100.1.150'
ATK = ('u-alu', '02:05:00:00:00:02')
INVITADOS = {'u-inv': '02:05:00:00:00:01', 'u-doc': '02:05:00:00:00:03', 'u-net': '02:05:00:00:00:05'}
TESTIGO = 'u-inv'

def ssh(port, cmd, timeout=300):
    return subprocess.run(['ssh', '-S', os.path.expanduser(f'~/.ssh/ctl-{port}'), f'x@{GW}', cmd],
                          capture_output=True, text=True, timeout=timeout).stdout.strip()
alumno = lambda c, **k: ssh(5813, c, **k)
onos1 = lambda c: ssh(5806, c)
idn = lambda m, p: onos1(f"curl -s -X {m} http://127.0.0.1:5001/identity/{p}")

def trafico():
    return json.loads(idn('GET', 'trafico'))

def limitados():
    return set(trafico()['limitados'])

def testigo(mb=20, n=5):
    """Velocidad de descarga (Mbit/s) y tiempo de conexión TCP (ms, mediana de n)."""
    out = alumno(f'sudo ip netns exec {TESTIGO} curl -s -o /dev/null -m 30 -w "%{{speed_download}}" '
                 f'"http://{VICTIMA}/descarga?mb={mb}"; echo; for i in $(seq {n}); do '
                 f'sudo ip netns exec {TESTIGO} curl -s -o /dev/null -m 3 -w "%{{time_connect}}\\n" http://{VICTIMA}/; done')
    l = out.split()
    vel = float(l[0]) * 8 / 1e6 if l and l[0] != '0.000' else 0.0
    con = [float(x) * 1000 for x in l[1:] if float(x) > 0]
    return round(vel), (round(statistics.median(con), 1) if con else None), len(con), n

def servidor(seg=4):
    """Lo que recibe la víctima (Mbit/s, paquetes/s) en `seg` segundos."""
    out = ssh(5811, f'r() {{ cat /sys/class/net/ens4/statistics/rx_bytes /sys/class/net/ens4/statistics/rx_packets; }}; '
                    f'a=$(r); sleep {seg}; b=$(r); echo $a $b')
    b0, p0, b1, p1 = map(int, out.split())
    return round((b1 - b0) * 8 / seg / 1e6, 1), round((p1 - p0) / seg)

def atacar(ns, pps, dur):
    alumno(f'sudo ip netns exec {ns} nohup timeout {dur} hping3 -q -A -p 80 -d 1200 -i u{int(1e6 / pps)} '
           f'{VICTIMA} >/dev/null 2>&1 &')

def preparar():
    print('== Preparación: alu01 (802.1X) e invitados con IP')
    alumno('for ns in u-inv u-alu u-doc u-adm u-net u-cic; do sudo g05-r1 logout $ns >/dev/null; '
           'sudo ip netns exec $ns ip -4 addr flush dev $ns; done; sudo pkill hping3; true')
    for m in [ATK[1], *INVITADOS.values()]:
        idn('DELETE', f'limit/{m}'); idn('DELETE', f'block/{m}'); idn('DELETE', f'sessions/{m}')
    time.sleep(3)
    alumno(f'sudo g05-r1 login {ATK[0]} alu01 >/dev/null; sleep 2; sudo g05-r1 dhcp {ATK[0]} >/dev/null')
    for ns, m in INVITADOS.items():
        idn('POST', f'guest/{m}')
    time.sleep(3)
    for ns in INVITADOS:
        alumno(f'sudo g05-r1 dhcp {ns} >/dev/null')
    time.sleep(3)
    for ns in [ATK[0], *INVITADOS]:
        ok = alumno(f'sudo ip netns exec {ns} timeout 3 nc -z -w2 {VICTIMA} 80 && echo sí || echo no')
        ip = alumno(f"sudo ip netns exec {ns} ip -4 -o addr show dev {ns} | awk '{{print $4}}'")
        print(f'  {ns:<6} {ip:<16} -> Mesa de ayuda: {ok}')

def esperar(cond, tmax):
    t0 = time.time()
    while time.time() - t0 < tmax:
        if cond():
            return round(time.time() - t0, 1)
        time.sleep(0.5)
    return None

def fase(titulo, fuentes, pps, dur=100):
    print(f'\n=== {titulo}')
    base = testigo()
    srv0 = servidor()
    print(f'  antes:   testigo {base[0]} Mbit/s, conexión {base[1]} ms ({base[2]}/{base[3]}); servidor recibe {srv0[0]} Mbit/s')
    macs = {INVITADOS.get(ns, ATK[1]) for ns in fuentes}
    t0 = time.time()
    for ns in fuentes:
        atacar(ns, pps, dur)
    time.sleep(3)
    srv_atk = servidor(3)
    tr = trafico()
    ofrec = {m: tr['usuarios'].get(m, {}).get('bps', 0) for m in macs}
    print(f'  ataque:  {len(fuentes)} fuente(s) x {pps} pps; servidor recibe {srv_atk[0]} Mbit/s, {srv_atk[1]} pps '
          f'(monitor: {", ".join(f"{m[-2:]}={v/1e6:.0f} Mbit/s" for m, v in sorted(ofrec.items()))})')
    t_det = esperar(lambda: macs <= limitados(), 60)
    t_det = round(time.time() - t0, 1) if t_det is not None else None
    lim = limitados()
    print(f'  fuentes limitadas a los {t_det} s del inicio: {sorted(m[-2:] for m in lim & macs)} de {sorted(m[-2:] for m in macs)}; '
          f'otras limitadas: {sorted(m[-2:] for m in lim - macs) or "ninguna"}')
    time.sleep(11)                                  # dos lecturas de ONOS ya con el meter
    srv1 = servidor()
    dur_t = testigo()
    tr = trafico()
    print(f'  con límite: servidor recibe {srv1[0]} Mbit/s, {srv1[1]} pps')
    # Lo que pasa el meter se mide en el servidor: OVS atribuye los contadores a todas las
    # reglas que recorre el paquete antes de que el meter lo descarte en el datapath.
    for m in sorted(macs):
        o = tr['ofrecido'].get(m, {}).get('bps', 0) / 1e6
        print(f'    fuente {m[-2:]}: sigue ofreciendo {o:.0f} Mbit/s (meter {tr["limitados"].get(m, {}).get("meter")})')
    print(f'  testigo durante el ataque: {dur_t[0]} Mbit/s, conexión {dur_t[1]} ms ({dur_t[2]}/{dur_t[3]}); '
          f'limitado: {"sí" if INVITADOS[TESTIGO] in lim else "no"}')
    resto = dur - (time.time() - t0)
    if resto > 0:
        time.sleep(resto)
    t_fin = time.time()
    t_lev = esperar(lambda: not (macs & limitados()), 120)
    print(f'  fin del ataque: límites levantados {t_lev} s después')
    return {'det': t_det, 'base': base, 'dur': dur_t, 'srv_atk': srv_atk, 'srv_lim': srv1, 'lev': t_lev}

preparar()
print('\n=== Falsos positivos: 60 s de descargas legítimas a toda velocidad (testigo y alu01)')
desde = int(onos1('date +%s'))
picos, fin = {}, [False]
def muestrear():
    while not fin[0]:
        for m, v in trafico()['usuarios'].items():
            if v['bps'] > picos.get(m, {'bps': 0})['bps']:
                picos[m] = v
        time.sleep(2)
hilo = threading.Thread(target=muestrear, daemon=True); hilo.start()
for _ in range(4):
    for ns in (TESTIGO, ATK[0]):
        alumno(f'sudo ip netns exec {ns} curl -s -o /dev/null -m 30 "http://{VICTIMA}/descarga?mb=200"')
    time.sleep(3)
time.sleep(10); fin[0] = True
det = [r for r in json.loads(onos1(f"curl -s 'http://127.0.0.1:5001/identity/incidents?desde={desde}'"))
       if r['ev'] == 'DDOS_DETECTADO']
print(f'  detecciones durante el tráfico legítimo: {len(det)}; subida máxima vista (ACK de la descarga): '
      + ', '.join(f"{m[-2:]} {v['bps']/1e6:.0f} Mbit/s / {v['pps']} pps" for m, v in sorted(picos.items())))

r1 = fase('Una fuente volumétrica: alu01 a ~10 000 pps (~100 Mbit/s)', [ATK[0]], 10000)
r2 = fase('Ataque distribuido: alu01 + 2 invitados a ~5 000 pps cada uno (bajo el umbral individual)',
          [ATK[0], 'u-doc', 'u-net'], 5000)

print('\n== Registro (DDOS_DETECTADO / LIMITE_LEVANTADO)')
for r in json.loads(onos1(f"curl -s 'http://127.0.0.1:5001/identity/incidents?desde={desde}'")):
    if r['ev'] in ('DDOS_DETECTADO', 'MITIGACION_APLICADA', 'LIMITE_LEVANTADO'):
        print('  ' + json.dumps({k: r[k] for k in r if k not in ('ts', 't')}, ensure_ascii=False)[:230])
alumno('sudo pkill hping3; true')
for m in [ATK[1], *INVITADOS.values()]:
    idn('DELETE', f'limit/{m}')
PY
