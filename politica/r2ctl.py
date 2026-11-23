#!/usr/bin/env python3
"""r2ctl: despliegue predefinido de R2 (G05, LLSD §5.7) sobre ONOS.

    r2ctl validate        valida policy.yaml y topology.yaml
    r2ctl plan            compara las reglas deseadas con las instaladas
    r2ctl apply           instala lo que falta y retira lo que sobra
    r2ctl verify [--roles all]
                          corre la matriz de pruebas desde los hosts
    r2ctl stats           contadores por regla y ocupación de tablas
    r2ctl rol <host> <n>  cambia el rol de un host (simula a identity/R1)
    r2ctl clear           retira todas las reglas y meters de r2ctl

Pipeline (6 tablas): 0 ingreso, 1 anti-spoofing, 2 mitigación R3, 3 identidad,
4 política R2, 5 reenvío. El rol viaja como VLAN id (rol x 100) dentro del
switch y se retira antes de salir (plan B del LLSD §6.1, V1/V2: el REST de
ONOS no soporta write_metadata). Las reglas las programa ONOS por REST con
appId edu.pucp.r2ctl; Ansible solo hace el bootstrap.

Se ejecuta desde el Mac reutilizando los canales SSH ControlMaster que abre el
usuario (ctl-<puerto>); ONOS se consulta con curl -n (~/.netrc del controller).
"""
import argparse
import ipaddress
import json
import os
import subprocess
import sys
import time
from collections import Counter, defaultdict

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
POLICY = os.path.join(HERE, 'policy.yaml')
TOPO = os.path.join(HERE, 'topology.yaml')
GW = os.getenv('VNRT_GW', 'ubuntu@10.20.12.7')
# Slice final: ONOS-1 (REST del clúster) y la VM Alumno (namespaces de prueba).
PORTS = {'controller': 5806, 'alumno': 5813}
APP = 'edu.pucp.r2ctl'
BCAST = 'FF:FF:FF:FF:FF:FF'
M_SAMPLE, M_CRIT = 'muestreo-5pps', 'critico-10pps'     # nombres de los meters
METERS = {M_SAMPLE: 5, M_CRIT: 10}


# ----------------------------------------------------------------- transporte
def ssh(node, cmd, stdin=None, timeout=120):
    sock = os.path.expanduser(f'~/.ssh/ctl-{PORTS[node]}')
    if not os.path.exists(sock):
        sys.exit(f'No hay canal SSH abierto para {node} ({sock}). Reábrelo.')
    r = subprocess.run(['ssh', '-S', sock, '-p', str(PORTS[node]), '-o',
                        'BatchMode=yes', GW, cmd], input=stdin, text=True,
                       capture_output=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


LOCAL = bool(os.getenv('R2_LOCAL'))       # 1 = corre en el controller (identity)
SESSIONS_FILE = os.getenv('R2_SESSIONS', '/var/lib/r2/sessions.json')
IDENTITY = 'http://127.0.0.1:5001'


def onos(method, path, body=None):
    """Llama a la REST de ONOS en el controller; devuelve (código, JSON|texto)."""
    hdr = "-H 'Content-Type: application/json' " if body is not None else ''
    cmd = (f"curl -sn -X {method} {hdr}"
           f"-w '\\n%{{http_code}}' 'http://127.0.0.1:8181/onos/v1{path}'"
           + (" -d @-" if body is not None else ''))
    stdin = json.dumps(body) if body is not None else None
    if LOCAL:                                   # sin SSH: curl local (~/.netrc)
        r = subprocess.run(cmd, shell=True, input=stdin, text=True,
                           capture_output=True, timeout=60)
        out = r.stdout
    else:
        _, out, err = ssh('controller', cmd, stdin=stdin)
    text, _, code = out.rpartition('\n')
    try:
        data = json.loads(text) if text.strip() else {}
    except ValueError:
        data = text
    return int(code or 0), data


# ------------------------------------------------------------------- modelos
def load():
    return yaml.safe_load(open(POLICY)), yaml.safe_load(open(TOPO))


def identity_call(method, path, body=None):
    """Llama a la API REST del servicio identity (en el controller)."""
    cmd = (f"curl -s -X {method} -H 'Content-Type: application/json' "
           f"-w '\\n%{{http_code}}' '{IDENTITY}{path}'"
           + (" -d @-" if body is not None else ''))
    stdin = json.dumps(body) if body is not None else None
    if LOCAL:
        out = subprocess.run(cmd, shell=True, input=stdin, text=True,
                             capture_output=True, timeout=30).stdout
    else:
        _, out, _ = ssh('controller', cmd, stdin=stdin)
    text, _, code = out.rpartition('\n')
    try:
        return int(code or 0), (json.loads(text) if text.strip() else {})
    except ValueError:
        return int(code or 0), text


def bindings(topo, sessions=None):
    """Vinculaciones puerto-MAC-IP-rol que alimentan las tablas 1 y 3.

    Modo estático (Fase 1): salen de `usuarios` en topology.yaml.
    Modo dinámico (R1): salen de las sesiones que mantiene el servicio identity
    (autenticadas por 802.1X; la IP llega por DHCP).
    """
    if sessions is not None:
        return sessions
    if topo.get('modo') == 'dinamico':
        if LOCAL:
            try:
                return json.load(open(SESSIONS_FILE))
            except (OSError, ValueError):
                return []
        _, data = identity_call('GET', '/identity/sessions')
        return data if isinstance(data, list) else []
    return [{'nombre': h, 'mac': u['mac'], 'switch': u['switch'],
             'puerto': u['puerto'], 'ip': u['ip'], 'rol': u['rol'],
             'estado': 'VINCULADO'} for h, u in topo['usuarios'].items()]


def save_topo(topo):
    """Reescribe solo la sección `usuarios`, conservando los comentarios."""
    text = open(TOPO).read()
    head = text.split('\nusuarios:')[0]
    rest = text.split('\nservidor:', 1)[1]
    users = yaml.safe_dump({'usuarios': topo['usuarios']}, sort_keys=False,
                           default_flow_style=None)
    with open(TOPO, 'w') as f:
        f.write(head + '\n' + users + '\n# Los servidores están detrás de Core-1 (no cuelgan de R-SW1).\n'
                'servidor:' + rest)


def net(p):
    return ipaddress.ip_network(p)


def parse_svc(s):
    proto, port = s.split('/')
    return proto, int(port)


def vid(rol):
    return int(rol) * 100


# ----------------------------------------------------------- reglas (helpers)
def rule(dev, table, prio, crit, ins, tag):
    return {'deviceId': dev, 'tableId': table, 'priority': prio,
            'timeout': 0, 'isPermanent': True,
            'selector': {'criteria': crit}, 'treatment': {'instructions': ins},
            '_tag': tag}


def c_eth(t): return {'type': 'ETH_TYPE', 'ethType': f'0x{t:04x}'}
def c_in(p): return {'type': 'IN_PORT', 'port': p}
def c_vlan(v): return {'type': 'VLAN_VID', 'vlanId': v}
def c_dst(ip): return {'type': 'IPV4_DST', 'ip': ip}
def c_mac(kind, m): return {'type': kind, 'mac': m.upper()}
def i_tbl(t): return {'type': 'TABLE', 'tableId': t}
def i_out(p): return {'type': 'OUTPUT', 'port': p}
def i_pop(): return {'type': 'L2MODIFICATION', 'subtype': 'VLAN_POP'}
def i_meter(m): return {'type': 'METER', 'meterId': m}


def i_push(v):
    return [{'type': 'L2MODIFICATION', 'subtype': 'VLAN_PUSH',
             'ethernetType': '0x8100'},
            {'type': 'L2MODIFICATION', 'subtype': 'VLAN_ID', 'vlanId': v}]


# -------------------------------------------------------------- compilador
def tabla4(dev, pol, roles_present, meters, pop=True):
    """Tabla 4 (LLSD §5.3): 53 reglas con los 6 roles del inventario.

    Con pop=False (topología enrutada) el tráfico permitido conserva la VLAN de su
    rol, que es la que lleva a Core-1 hasta el gateway de ese rol."""
    R = []
    ok = [i_pop(), i_tbl(5)] if pop else [i_tbl(5)]
    crit = pol['bloque_critico']
    for rol, r in pol['roles'].items():
        v = vid(rol)
        nombre = r['nombre']
        # OVS exige match de VLAN para hacer pop_vlan: el ARP lleva una regla
        # por rol (6) en vez de una sola (LLSD §5.3 decía 1).
        R.append(rule(dev, 4, 29800, [c_vlan(v), c_eth(0x0806)],
                      ok,
                      f'T4 ARP {nombre} (inundación validada; sin proxy ARP)'))
        if r['permite'] == 'todo':
            R.append(rule(dev, 4, 29900, [c_vlan(v)], ok,
                          f'T4 permiso total {nombre}'))
            continue
        for g in r['permite']:
            rec = pol['recursos'][g]
            svcs = rec.get('servicios')
            base = [c_vlan(v), c_eth(0x0800), c_dst(rec['prefijo'])]
            if not svcs:
                R.append(rule(dev, 4, 25000, base, ok,
                              f'T4 permite {nombre} -> {g} {rec["nombre"]}'))
            for s in svcs or []:
                proto, port = parse_svc(s)
                pc = ([{'type': 'IP_PROTO', 'protocol': 6},
                       {'type': 'TCP_DST', 'tcpPort': port}] if proto == 'tcp'
                      else [{'type': 'IP_PROTO', 'protocol': 17},
                            {'type': 'UDP_DST', 'udpPort': port}])
                R.append(rule(dev, 4, 25000, base + pc, ok,
                              f'T4 permite {nombre} -> {g} {rec["nombre"]} {s}'))
        R.append(rule(dev, 4, 23000,
                      [c_vlan(v), c_eth(0x0800), c_dst(crit)],
                      [i_meter(meters[M_CRIT]), i_out('CONTROLLER')],
                      f'T4 bloqueo crítico {nombre} (cuenta y muestrea)'))
        if r.get('internet'):
            for p in pol['bloques_privados']:
                R.append(rule(dev, 4, 22000,
                              [c_vlan(v), c_eth(0x0800), c_dst(p)], [],
                              f'T4 bloqueo intranet {nombre} {p}'))
            R.append(rule(dev, 4, 21000, [c_vlan(v)], ok,
                          f'T4 salida a Internet {nombre}'))
    R.append(rule(dev, 4, 0, [], [], 'T4 table-miss descarta'))
    return R


def next_port(topo, sw, destino):
    """Puerto de `sw` hacia el switch `destino` (árbol: búsqueda en anchura)."""
    if sw == destino:
        return None
    sws = topo['switches']
    seen, cola = {sw}, [(sw, None)]
    while cola:
        cur, first = cola.pop(0)
        for p, info in sws[cur]['puertos'].items():
            nb = info['a']
            if nb in sws and nb not in seen:
                f = first if first is not None else p
                if nb == destino:
                    return f
                seen.add(nb)
                cola.append((nb, f))
    raise ValueError(f'sin camino {sw} -> {destino}')


def tabla5_enrutada(dev, info, users):
    """Tabla 5 en la topología enrutada (slice final).

    - Lo que sale de un usuario ya pasó la política (T4) y lleva la VLAN de su rol:
      se entrega tal cual al puerto `salida` (Core-1, gateway de cada rol).
    - Lo que vuelve de la red llega etiquetado con la VLAN del rol: se quita la
      etiqueta y se entrega al usuario por su MAC (o a todos los de ese rol en su
      puerto si es broadcast, p. ej. el ARP del gateway).
    """
    R = []
    salida = info['salida']
    uplinks = [p for p, i in info['puertos'].items() if i.get('uplink')]
    por_puerto_rol = defaultdict(set)
    for h, u in users.items():
        v = vid(u['rol'])
        por_puerto_rol[v].add(u['puerto'])
        for up in uplinks:
            R.append(rule(dev, 5, 10100, [c_in(up), c_vlan(v), c_mac('ETH_DST', u['mac'])],
                          [i_pop(), i_out(u['puerto'])],
                          f'T5 hacia {h} (VLAN {v}) por puerto {u["puerto"]}'))
    for v, ports in por_puerto_rol.items():
        for up in uplinks:
            R.append(rule(dev, 5, 10050, [c_in(up), c_vlan(v), c_mac('ETH_DST', BCAST)],
                          [i_pop()] + [i_out(p) for p in sorted(ports)],
                          f'T5 broadcast de la VLAN {v} hacia sus usuarios'))
    for p in sorted({u['puerto'] for u in users.values()}):
        R.append(rule(dev, 5, 10000, [c_in(p)], [i_out(salida)],
                      f'T5 usuario (puerto {p}) -> Core-1 por puerto {salida}'))
    R.append(rule(dev, 5, 0, [], [], 'T5 table-miss descarta'))
    return R


def compile_all(pol, topo, meters_by_dev, sessions=None):
    out = defaultdict(list)
    binds = bindings(topo, sessions)
    macs = {}                       # mac -> switch donde cuelga
    for h, u in topo['usuarios'].items():
        macs[u['mac']] = (h, u['switch'], u['puerto'])
    for h, s in topo['servidor'].items():
        macs[s['mac']] = (h, s['switch'], s['puerto'])
    for sw, info in topo['switches'].items():
        dev = info['dpid']
        meters = meters_by_dev.get(dev, {M_SAMPLE: 0, M_CRIT: 0})
        puertos = info['puertos']
        links = [p for p, i in puertos.items() if i.get('uplink')]
        servers = [s['puerto'] for s in topo['servidor'].values()
                   if s['switch'] == sw]
        mine = [b for b in binds if b['switch'] == sw]
        users = {b['nombre'] if 'nombre' in b else b['mac']: b for b in mine
                 if b.get('estado') in ('VINCULADO', 'CUARENTENA') and b.get('ip')}
        sin_ip = [b for b in mine if b.get('estado') == 'SIN_IP' or not b.get('ip')]
        R = out[dev]
        R.append(rule(dev, 0, 65000, [c_eth(0x88CC)], [i_out('CONTROLLER')],
                      'T0 LLDP al controlador (descubrimiento)'))
        R.append(rule(dev, 0, 65000, [c_eth(0x8942)], [i_out('CONTROLLER')],
                      'T0 BDDP al controlador (descubrimiento)'))
        if info['funcion'] == 'acceso':
            R.append(rule(dev, 0, 65000, [c_eth(0x888E)], [i_out('CONTROLLER')],
                          'T0 EAPOL al controlador (R1)'))
            # Una regla por puerto de usuario solo para tener contadores por puerto:
            # identity detecta el EAPOL-Logoff (AAA no deja rastro del puerto).
            for p, i in puertos.items():
                if not i.get('uplink') and not i.get('monitor') and p not in servers:
                    R.append(rule(dev, 0, 65100, [c_in(p), c_eth(0x888E)],
                                  [i_out('CONTROLLER')],
                                  f'T0 EAPOL puerto {p} (contador por puerto)'))
            for p in links + servers:
                R.append(rule(dev, 0, 61000, [c_in(p)], [i_tbl(5)],
                              f'T0 tráfico de la red/servidor (puerto {p}) -> T5'))
            R.append(rule(dev, 0, 60000, [c_eth(0x0800)], [i_tbl(1)],
                          'T0 IPv4 de usuario -> T1'))
            R.append(rule(dev, 0, 60000, [c_eth(0x0806)], [i_tbl(1)],
                          'T0 ARP de usuario -> T1'))
            R.append(rule(dev, 0, 0, [],
                          [i_meter(meters[M_SAMPLE]), i_out('CONTROLLER')],
                          'T0 table-miss: descarta y muestrea (5 pps)'))
            # Ventana DHCP (LLSD §4.5): puerto autenticado que aún no tiene IP. En la
            # topología enrutada el DHCP sale con la VLAN del rol (Core-1 elige la
            # subred por la interfaz del relay) y se mantiene para las renovaciones.
            ventana = (sin_ip + list(users.values())) if topo.get('enrutado') else sin_ip
            for b in ventana:
                acc = (i_push(vid(b['rol'])) + [i_tbl(5)]) if topo.get('enrutado') else [i_tbl(5)]
                R.append(rule(dev, 0, 64000,
                              [c_in(b['puerto']), c_mac('ETH_SRC', b['mac']),
                               c_eth(0x0800), {'type': 'IP_PROTO', 'protocol': 17},
                               {'type': 'UDP_SRC', 'udpPort': 68},
                               {'type': 'UDP_DST', 'udpPort': 67}],
                              acc,
                              f'T0 ventana DHCP {b.get("usuario", b["mac"])} (rol {b["rol"]})'))
            for h, u in users.items():
                p, m = u['puerto'], u['mac']
                R.append(rule(dev, 1, 50000,
                              [c_in(p), c_mac('ETH_SRC', m), c_eth(0x0800),
                               {'type': 'IPV4_SRC', 'ip': u['ip'] + '/32'}],
                              [i_tbl(2)], f'T1 anti-spoofing IPv4 {h}'))
                # El REST de ONOS 2.7 no tiene el criterio ARP_SPA: el ARP se
                # valida por puerto y MAC (limitación a declarar en el LLSD).
                R.append(rule(dev, 1, 50000,
                              [c_in(p), c_mac('ETH_SRC', m), c_eth(0x0806)],
                              [i_tbl(2)], f'T1 anti-spoofing ARP {h} (puerto+MAC)'))
                R.append(rule(dev, 3, 35000, [c_in(p), c_mac('ETH_SRC', m)],
                              i_push(vid(u['rol'])) + [i_tbl(4)],
                              f'T3 identidad {h}: rol {u["rol"]} -> VLAN {vid(u["rol"])}'))
            R.append(rule(dev, 1, 0, [], [], 'T1 table-miss descarta'))
            R.append(rule(dev, 2, 1, [], [i_tbl(3)], 'T2 paso (ajuste A3)'))
            R.append(rule(dev, 2, 0, [], [], 'T2 table-miss descarta'))
            R.append(rule(dev, 3, 0, [], [], 'T3 table-miss descarta'))
            R.extend(tabla4(dev, pol, None, meters, pop=not topo.get('enrutado')))
        else:                                   # core: solo tránsito
            # Debe superar la prioridad 40000 de las reglas propias de ONOS
            # (ARP/BDDP al controlador), o el ARP no se reenvía en el core.
            R.append(rule(dev, 0, 60000, [], [i_tbl(5)], 'T0 core: todo a T5'))
        if topo.get('enrutado') and info['funcion'] == 'acceso':
            activos = dict(users)
            activos.update({b.get('nombre', b['mac']): b for b in sin_ip if b.get('rol')})
            R.extend(tabla5_enrutada(dev, info, activos))
            continue
        # tabla 5: reenvío proactivo por MAC destino + inundación de broadcast
        for m, (h, sw_h, p_h) in macs.items():
            port = p_h if sw_h == sw else next_port(topo, sw, sw_h)
            R.append(rule(dev, 5, 10100, [c_mac('ETH_DST', m)], [i_out(port)],
                          f'T5 reenvío a {h} por puerto {port}'))
        for p in puertos:
            R.append(rule(dev, 5, 10000,
                          [c_in(p), c_mac('ETH_DST', BCAST)],
                          [i_out(q) for q in puertos if q != p],
                          f'T5 broadcast desde puerto {p}'))
        R.append(rule(dev, 5, 0, [], [], 'T5 table-miss descarta'))
    return out


# ------------------------------------------------- normalización y comparación
def _n(v):
    if isinstance(v, str):
        try:
            return int(v, 0)
        except ValueError:
            return v.lower()
    return v


def norm_item(d):
    return tuple(sorted((k, _n(v)) for k, v in d.items()))


def key(r):
    crit = tuple(sorted(norm_item(c) for c in r['selector']['criteria']))
    raw = [i for i in r['treatment'].get('instructions', [])
           if i.get('type') != 'NOACTION']             # ONOS: descartar = NOACTION
    # ONOS mueve el METER después de las acciones; en OpenFlow el meter es una
    # instrucción aparte, así que su posición no cambia el resultado.
    ins = (tuple(norm_item(i) for i in raw if i['type'] != 'METER'),
           tuple(sorted(norm_item(i) for i in raw if i['type'] == 'METER')))
    return (r['deviceId'], r['tableId'], r['priority'], crit, ins)


# ------------------------------------------------------------------ validate
def validate(pol, topo, quiet=False):
    err = []
    rec = pol['recursos']
    crit_net = net(pol['bloque_critico'])
    items = list(rec.items())
    for i, (g, a) in enumerate(items):
        for h, b in items[i + 1:]:
            if net(a['prefijo']).overlaps(net(b['prefijo'])):
                err.append(f'prefijos solapados: {g} {a["prefijo"]} y {h} {b["prefijo"]}')
    for g, a in items:
        inside = net(a['prefijo']).subnet_of(crit_net)
        if a['nivel'] == 'critico' and not inside:
            err.append(f'{g} es crítico y está fuera de {crit_net}')
        if a['nivel'] != 'critico' and inside:
            err.append(f'{g} no es crítico pero cae dentro de {crit_net}')
        if a['nivel'] != 'critico' and 'servicios' not in a and a['nivel'] == 'intermedio':
            err.append(f'{g} es intermedio y no declara servicios')
        if not ipaddress.ip_address(a['ip']) in net(a['prefijo']):
            err.append(f'{g}: la ip {a["ip"]} no está en {a["prefijo"]}')
        for s in a.get('servicios', []):
            parse_svc(s)
    for rol, r in pol['roles'].items():
        if r['permite'] != 'todo':
            for g in r['permite']:
                if g not in rec:
                    err.append(f'rol {rol} ({r["nombre"]}): grupo {g} no existe')
    for h, u in topo['usuarios'].items():
        if u['rol'] not in pol['roles']:
            err.append(f'{h}: rol {u["rol"]} no existe')
        if u['switch'] not in topo['switches']:
            err.append(f'{h}: switch {u["switch"]} no existe')
    if pol.get('defecto') != 'denegar':
        err.append('la política por defecto debe ser denegar')
    meters = {i['dpid']: {M_SAMPLE: 1, M_CRIT: 2} for i in topo['switches'].values()}
    comp = compile_all(pol, topo, meters)
    n4 = {d: sum(1 for r in rs if r['tableId'] == 4) for d, rs in comp.items()
          if any(r['tableId'] == 4 for r in rs)}
    if not quiet:
        print('Validación de policy.yaml y topology.yaml')
        print(f'  recursos: {len(rec)}  roles: {len(pol["roles"])}  usuarios: '
              f'{len(topo["usuarios"])}  switches: {len(topo["switches"])}')
        for d, n in n4.items():
            print(f'  tabla 4 en {d}: {n} reglas')
        total = {d: len(rs) for d, rs in comp.items()}
        print(f'  reglas totales por switch: {total}')
        for e in err:
            print('  ERROR:', e)
        print('  RESULTADO:', 'OK' if not err else f'{len(err)} errores')
    return not err


# -------------------------------------------------------------------- meters
def _mid(m):
    """Los ids de meter de ONOS son hexadecimales ("1f")."""
    return int(str(m['id']), 16)


def list_meters(dev):
    """Meters de r2ctl en un switch. ONOS guarda los creados por REST con
    appId org.onosproject.rest, no con el nuestro, así que se reconocen por tasa."""
    _, data = onos('GET', f'/meters/{dev}')
    out = []
    for m in data.get('meters', []) if isinstance(data, dict) else []:
        if m.get('appId') in (APP, 'org.onosproject.rest') and m.get('bands'):
            out.append(m)
    return out


def ensure_meters(topo, create=True):
    """Devuelve {deviceId: {nombre: id}}, creando solo los meters que falten."""
    res = {}
    for sw, info in topo['switches'].items():
        if info['funcion'] != 'acceso':
            continue
        dev = info['dpid']

        def have():
            by = {}
            for m in list_meters(dev):
                r = m['bands'][0]['rate']
                if r in METERS.values() and (r not in by or _mid(m) < by[r]):
                    by[r] = _mid(m)
            return by

        cur = have()
        missing = [r for r in METERS.values() if r not in cur]
        if create and missing:
            for rate in missing:
                code, _ = onos('POST', f'/meters/{dev}', {
                    'deviceId': dev, 'appId': APP, 'unit': 'PKTS_PER_SEC',
                    'burst': True,
                    'bands': [{'type': 'DROP', 'rate': rate, 'burstSize': rate}]})
                if code not in (200, 201):
                    sys.exit(f'No se pudo crear el meter de {rate} pps en {dev}: HTTP {code}')
            for _ in range(10):
                cur = have()
                if all(r in cur for r in METERS.values()):
                    break
                time.sleep(1)
        res[dev] = {n: cur[r] for n, r in METERS.items() if r in cur}
    return res


def prune_meters(topo):
    """Borra los meters duplicados que dejó el error anterior (conserva el menor id por tasa)."""
    borrados = 0
    for info in topo['switches'].values():
        if info['funcion'] != 'acceso':
            continue
        dev = info['dpid']
        keep = {}
        ms = sorted(list_meters(dev), key=_mid)
        for m in ms:
            keep.setdefault(m['bands'][0]['rate'], _mid(m))
        for m in ms:
            if keep[m['bands'][0]['rate']] != _mid(m):
                onos('DELETE', f'/meters/{dev}/{_mid(m)}')   # el DELETE usa el id en decimal
                borrados += 1
    print(f'prune: {borrados} meters duplicados borrados')


def installed():
    code, data = onos('GET', f'/flows/application/{APP}')
    return data.get('flows', []) if code == 200 else []


def diff(pol, topo, create_meters=False, sessions=None):
    meters = ensure_meters(topo, create=create_meters)
    for sw, info in topo['switches'].items():
        if info['funcion'] == 'acceso' and not meters.get(info['dpid'], {}).get(M_CRIT):
            meters[info['dpid']] = {M_SAMPLE: 1, M_CRIT: 2}      # solo para planear
    want = compile_all(pol, topo, meters, sessions)
    desired = {key(r): r for rs in want.values() for r in rs}
    cur = {}
    for f in installed():
        r = {'deviceId': f['deviceId'], 'tableId': int(f['tableId']),
             'priority': f['priority'],
             'selector': f['selector'], 'treatment': f['treatment']}
        r['treatment'] = {'instructions': f['treatment'].get('instructions', [])}
        cur[key(r)] = f
    add = [desired[k] for k in desired if k not in cur]
    rem = [cur[k] for k in cur if k not in desired]
    return want, desired, cur, add, rem


def cmd_plan(pol, topo):
    if not validate(pol, topo, quiet=True):
        sys.exit('La política no valida. Corre `r2ctl validate`.')
    _, desired, cur, add, rem = diff(pol, topo)
    by = lambda rs, f: Counter(f(r) for r in rs)
    print(f'Reglas deseadas: {len(desired)}   instaladas: {len(cur)}')
    print(f'  por agregar: {len(add)}   por retirar: {len(rem)}')
    for dev, n in sorted(by(add, lambda r: r['deviceId']).items()):
        print(f'  + {dev}: {n}')
    for dev, n in sorted(by(rem, lambda f: f['deviceId']).items()):
        print(f'  - {dev}: {n}')
    return add, rem


def reconcile(pol, topo, sessions=None, wait=False):
    """Instala lo que falta y retira lo que sobra. Devuelve (agregadas, retiradas, ok)."""
    want, desired, cur, add, rem = diff(pol, topo, create_meters=True,
                                        sessions=sessions)
    for f in rem:
        onos('DELETE', f'/flows/{f["deviceId"]}/{f["id"]}')
    bydev = defaultdict(list)
    for r in add:
        bydev[r['deviceId']].append({k: v for k, v in r.items() if k != '_tag'})
    for dev, flows in bydev.items():
        for i in range(0, len(flows), 40):
            code, data = onos('POST', f'/flows?appId={APP}', {'flows': flows[i:i + 40]})
            if code not in (200, 201):
                raise RuntimeError(f'ONOS rechazó las reglas de {dev}: HTTP {code} {data}')
    ok = None
    if wait:
        for _ in range(15):
            ok = sum(1 for f in installed() if f['state'] == 'ADDED')
            if ok >= len(desired):
                break
            time.sleep(1)
        ok = (ok, len(desired))
    return len(add), len(rem), ok


def cmd_apply(pol, topo):
    if not validate(pol, topo, quiet=True):
        sys.exit('La política no valida. Corre `r2ctl validate`.')
    t0 = time.time()
    try:
        add, rem, ok = reconcile(pol, topo, wait=True)
    except RuntimeError as e:
        sys.exit(str(e))
    print(f'apply: +{add} reglas, -{rem} reglas en {time.time() - t0:.1f} s')
    print(f'  instaladas en el switch (ADDED): {ok[0]} de {ok[1]}')
    return ok[0] >= ok[1]


def cmd_clear(topo):
    code, _ = onos('DELETE', f'/flows/application/{APP}')
    n = 0
    for info in topo['switches'].values():
        _, data = onos('GET', f'/meters/{info["dpid"]}')
        for m in data.get('meters', []):
            if m['appId'] == APP:
                onos('DELETE', f'/meters/{info["dpid"]}/{m["id"]}')
                n += 1
    print(f'clear: reglas retiradas (HTTP {code}), meters retirados: {n}')


# --------------------------------------------------------------------- stats
def cmd_stats(pol, topo):
    fl = installed()
    meters = {i['dpid']: {M_SAMPLE: 1, M_CRIT: 2} for i in topo['switches'].values()}
    desc = {key(r): r['_tag'] for rs in compile_all(pol, topo, meters).values()
            for r in rs}
    print('Ocupación de tablas (reglas de r2ctl):')
    occ = defaultdict(Counter)
    for f in fl:
        occ[f['deviceId']][int(f['tableId'])] += 1
    for dev, c in sorted(occ.items()):
        print(f'  {dev}: ' + '  '.join(f'T{t}={n}' for t, n in sorted(c.items()))
              + f'   total={sum(c.values())}')
    print('\nContadores de la tabla 4 con tráfico (paquetes > 0):')
    rows = []
    for f in fl:
        if int(f['tableId']) == 4 and f.get('packets', 0) > 0:
            r = {'deviceId': f['deviceId'], 'tableId': 4, 'priority': f['priority'],
                 'selector': f['selector'],
                 'treatment': {'instructions': f['treatment'].get('instructions', [])}}
            rows.append((f['deviceId'], f['packets'], f['bytes'],
                         desc.get(key(r), f'prio {f["priority"]}')))
    for dev, p, b, d in sorted(rows):
        print(f'  {dev[-2:]}  {p:>6} pkts {b:>8} B  {d}')
    if not rows:
        print('  (sin tráfico todavía)')


# -------------------------------------------------------------------- verify
def allowed(pol, rol, ip, proto, port):
    """Oráculo: decide desde la política, sin mirar las reglas compiladas."""
    r = pol['roles'][rol]
    if r['permite'] == 'todo':
        return True
    a = ipaddress.ip_address(ip)
    for g, rec in pol['recursos'].items():
        if a in net(rec['prefijo']):
            if g not in r['permite']:
                return False
            svcs = rec.get('servicios')
            return (not svcs) or f'{proto}/{port}' in svcs
    if any(a in net(p) for p in pol['bloques_privados']):
        return False
    return bool(r.get('internet'))


def targets(pol, topo):
    t = []
    fuera = set(topo.get('fuera_de_prueba', []))
    for g, rec in pol['recursos'].items():
        if g in fuera:
            continue
        for port in (22, 80, 443):
            t.append((g, rec['nombre'], rec['ip'], 'tcp', port))
    t.append(('G11', 'dns', pol['recursos']['G11']['ip'], 'udp', 53))
    for port in (80, 443):
        t.append(('NET', 'internet', topo['internet_ip'], 'tcp', port))
    return t


def in_host(topo, h, script, timeout=180):
    """Ejecuta un script en el host de prueba (dentro de su namespace si lo tiene)."""
    u = topo['usuarios'][h]
    if u.get('ns'):
        return ssh(u['nodo'], f"sudo ip netns exec {u['ns']} bash -s", stdin=script, timeout=timeout)
    return ssh(h, script, timeout=timeout)


def probe(topo, host, tg):
    lines = []
    for g, name, ip, proto, port in tg:
        if proto == 'tcp':
            c = f'nc -z -w2 {ip} {port}'
        else:
            c = f'printf x | nc -u -w2 {ip} {port} | grep -q SRV'
        lines.append(f'({c} && echo "{ip} {proto} {port} 1" || '
                     f'echo "{ip} {proto} {port} 0") &')
    _, out, _ = in_host(topo, host, '\n'.join(lines) + '\nwait\n')
    res = {}
    for l in out.split('\n'):
        p = l.split()
        if len(p) == 4:
            res[(p[0], p[1], int(p[2]))] = p[3] == '1'
    return res


def find_session(topo, h):
    mac = topo['usuarios'][h]['mac'].lower()
    for b in bindings(topo):
        if b['mac'].lower() == mac:
            return b
    return None


def rol_of(topo, h):
    if topo.get('modo') != 'dinamico':
        return topo['usuarios'][h]['rol']
    b = find_session(topo, h)
    return b['rol'] if b and b.get('estado') in ('VINCULADO', 'CUARENTENA') else None


def run_verify(pol, topo, hosts):
    tg = targets(pol, topo)
    tot = Counter()
    errores = []
    for h in hosts:
        rol = rol_of(topo, h)
        if rol is None:
            print(f'  {h}: sin sesión vinculada, se omite')
            continue
        res = probe(topo, h, tg)
        for g, name, ip, proto, port in tg:
            exp = allowed(pol, rol, ip, proto, port)
            got = res.get((ip, proto, port))
            tot['pruebas'] += 1
            tot['no_autorizadas'] += (not exp)
            if got is None:
                errores.append((h, rol, name, proto, port, 'sin dato'))
            elif got != exp:
                errores.append((h, rol, name, proto, port,
                                'pasó y debía bloquearse' if got else
                                'se bloqueó y debía pasar'))
            elif not exp:
                tot['bloqueadas_ok'] += 1
        # matriz resumida del documento (§5.7)
        cols = [('Matrícula', 'G04', 443), ('Notas', 'G06', 443),
                ('Portal', 'G10', 443), ('Ayuda', 'G12', 443)]
        cells = []
        for lab, g, port in cols:
            ip = pol['recursos'][g]['ip']
            cells.append(f'{lab}:{"sí" if res.get((ip, "tcp", port)) else "no"}')
        cells.append(f'DNS:{"sí" if res.get((pol["recursos"]["G11"]["ip"], "udp", 53)) else "no"}')
        cells.append(f'Internet:{"sí" if res.get((topo["internet_ip"], "tcp", 443)) else "no"}')
        print(f'  {h} rol {rol} {pol["roles"][rol]["nombre"]:<15} ' + '  '.join(cells))
    return tot, errores


def set_rol(pol, topo, host, rol):
    if rol not in pol['roles']:
        sys.exit(f'Rol {rol} no existe en la política')
    u = topo['usuarios'][host]
    u['rol'] = rol
    u['ip'] = f'10.{rol * 10}.0.{u.get("octeto", 10)}'
    save_topo(topo)
    if u.get('ns'):          # namespace con su macvlan: IP del rol y su gateway
        cmd = (f'ip addr flush dev {u["ns"]} && ip addr add {u["ip"]}/{u["mascara"]} dev {u["ns"]} && '
               f'ip route replace default via 10.{rol * 10}.0.1 dev {u["ns"]}')
        code, _, err = ssh(u['nodo'], f"sudo ip netns exec {u['ns']} bash -s", stdin=cmd)
    else:
        cmd = (f'sudo ip addr flush dev ens4 && sudo ip addr add {u["ip"]}/{u["mascara"]} '
               'dev ens4 && sudo ip route replace 10.0.0.0/8 dev ens4 scope link && '
               'sudo ip route replace 203.0.113.0/24 dev ens4 scope link')
        code, _, err = ssh(host, cmd)
    if code:
        sys.exit(f'No se pudo cambiar la IP de {host}: {err}')
    return u


LOGIN_USER = {5: 'admin01', 4: 'adm01', 3: 'doc01', 2: 'alu01'}


def wait_sync(timeout=30):
    """Espera a que identity termine de instalar las reglas pendientes."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        _, d = identity_call('GET', '/identity/sync')
        if isinstance(d, dict) and not d.get('pendiente', True):
            return True
        time.sleep(1)
    return False


def wait_session(topo, h, rol=None, timeout=60):
    t0 = time.time()
    while time.time() - t0 < timeout:
        b = find_session(topo, h)
        if (b and b.get('estado') in ('VINCULADO', 'CUARENTENA') and b.get('ip')
                and (rol is None or b['rol'] == rol)):
            wait_sync()
            return b
        time.sleep(1.5)
    return None


def host_login(topo, h, rol):
    """Lleva a un host al rol pedido usando 802.1X, invitado o cuarentena."""
    u = topo['usuarios'][h]
    mac = u['mac'].lower()
    ns = u['ns']

    def sh(cmd):
        return ssh(u['nodo'], cmd, timeout=120)
    sh(f'sudo g05-r1 logout {ns}')
    identity_call('DELETE', f'/identity/sessions/{mac}')
    if rol == 1:
        identity_call('POST', f'/identity/guest/{mac}')
        wait_sync()
        sh(f'sudo g05-r1 dhcp {ns}')
    elif rol == 9:
        host_login(topo, h, 2)
        identity_call('POST', f'/identity/quarantine/{mac}',
                      {'motivo': 'prueba de verify', 'ttl': 600})
        wait_sync()
        sh(f'sudo g05-r1 dhcp {ns}')
    else:
        identity_call('DELETE', f'/identity/quarantine/{mac}')
        sh(f'sudo g05-r1 login {ns} {LOGIN_USER[rol]}')
        wait_sync()
        sh(f'sudo g05-r1 dhcp {ns}')
    b = wait_session(topo, h, rol)
    if not b:
        print(f'  AVISO: {h} no llegó al rol {rol}')
    return b


def cmd_verify(pol, topo, roles_all):
    dyn = topo.get('modo') == 'dinamico'
    if not roles_all:
        print('Matriz de pruebas (rol actual de cada host):')
        hosts = [h for h in topo['usuarios'] if rol_of(topo, h) is not None]
        tot, err = run_verify(pol, topo, hosts)
    elif dyn:
        host = topo.get('host_ciclo', 'h4')
        print(f'Matriz de pruebas recorriendo todos los roles con {host} (802.1X real):')
        tot, err = Counter(), []
        for rol in (5, 4, 3, 2, 1, 9):
            if not host_login(topo, host, rol):
                err.append((host, rol, '-', '-', 0, 'no se alcanzó el rol'))
                continue
            t, e = run_verify(pol, topo, [host])
            tot.update(t)
            err += e
        identity_call('DELETE', f'/identity/quarantine/{topo["usuarios"][host]["mac"].lower()}')
        host_login(topo, host, 3)           # h4 vuelve a docente (doc01)
    else:
        orig = {h: topo['usuarios'][h]['rol'] for h in topo['usuarios']}
        host = topo.get('host_ciclo', 'h4')
        print(f'Matriz de pruebas recorriendo todos los roles con {host}:')
        tot, err = Counter(), []
        for rol in pol['roles']:
            set_rol(pol, topo, host, rol)
            cmd_apply_quiet(pol, topo)
            t, e = run_verify(pol, topo, [host])
            tot.update(t)
            err += e
        set_rol(pol, topo, host, orig[host])
        cmd_apply_quiet(pol, topo)
    n = tot['pruebas']
    print(f'\nPruebas: {n}   discrepancias: {len(err)}')
    if tot['no_autorizadas']:
        print(f'Precisión en la restricción: {tot["bloqueadas_ok"]}/{tot["no_autorizadas"]} '
              f'intentos no autorizados bloqueados '
              f'({100 * tot["bloqueadas_ok"] / tot["no_autorizadas"]:.1f} %)')
    for e in err:
        print('  DISCREPANCIA:', *e)
    return not err


def cmd_apply_quiet(pol, topo):
    so = sys.stdout
    sys.stdout = open(os.devnull, 'w')
    try:
        cmd_apply(pol, topo)
    finally:
        sys.stdout = so


def main():
    ap = argparse.ArgumentParser(prog='r2ctl', description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('cmd', choices=['validate', 'plan', 'apply', 'verify',
                                    'stats', 'rol', 'clear', 'sesiones', 'prune'])
    ap.add_argument('args', nargs='*')
    ap.add_argument('--roles', choices=['all'])
    a = ap.parse_args()
    pol, topo = load()
    if a.cmd == 'validate':
        sys.exit(0 if validate(pol, topo) else 1)
    elif a.cmd == 'plan':
        cmd_plan(pol, topo)
    elif a.cmd == 'apply':
        sys.exit(0 if cmd_apply(pol, topo) else 1)
    elif a.cmd == 'verify':
        sys.exit(0 if cmd_verify(pol, topo, a.roles == 'all') else 1)
    elif a.cmd == 'stats':
        cmd_stats(pol, topo)
    elif a.cmd == 'clear':
        cmd_clear(topo)
    elif a.cmd == 'prune':
        prune_meters(topo)
    elif a.cmd == 'sesiones':
        for b in bindings(topo):
            print(f"  {b['switch']}/{b['puerto']}  {b['mac']}  {b.get('usuario','-'):<8} "
                  f"rol={b['rol']} {b.get('estado','-'):<10} ip={b.get('ip') or '-'}")
    elif a.cmd == 'rol':
        host, rol = a.args[0], int(a.args[1])
        u = set_rol(pol, topo, host, rol)
        print(f'{host}: rol {rol} ({pol["roles"][rol]["nombre"]}), IP {u["ip"]}')
        cmd_apply(pol, topo)


if __name__ == '__main__':
    main()
