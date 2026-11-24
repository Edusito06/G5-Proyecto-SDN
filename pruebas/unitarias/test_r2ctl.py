"""Pruebas unitarias de r2ctl (R2): la política compilada implementa la declarada.

Un simulador recorre las reglas compiladas para R-SW1 tabla por tabla, como OVS
(OpenFlow 1.3: gana la prioridad más alta; acciones en orden; goto a otra tabla), y su
veredicto se compara con el oráculo `allowed()`, que decide solo desde policy.yaml.
"""
import ipaddress

import pytest

SW = 'r-sw1'
PUERTO_USUARIO = 4
GW_MAC = '02:00:00:00:00:fe'


# ------------------------------------------------------------------ simulador
def _coincide(c, p):
    t = c['type']
    if t == 'IN_PORT':
        return p['in_port'] == c['port']
    if t == 'ETH_TYPE':
        return p['eth_type'] == int(c['ethType'], 16)
    if t in ('ETH_SRC', 'ETH_DST'):
        return p[t.lower()].lower() == c['mac'].lower()
    if t == 'VLAN_VID':
        return p.get('vlan') == c['vlanId']
    if t in ('IPV4_SRC', 'IPV4_DST'):
        ip = p.get('ip_src' if t == 'IPV4_SRC' else 'ip_dst')
        return ip is not None and ipaddress.ip_address(ip) in ipaddress.ip_network(c['ip'], strict=False)
    if t == 'IP_PROTO':
        return p.get('ip_proto') == c['protocol']
    if t == 'TCP_DST':
        return p.get('ip_proto') == 6 and p.get('dport') == c['tcpPort']
    if t == 'UDP_DST':
        return p.get('ip_proto') == 17 and p.get('dport') == c['udpPort']
    if t == 'UDP_SRC':
        return p.get('ip_proto') == 17 and p.get('sport') == c['udpPort']
    raise AssertionError(f'criterio no soportado por el simulador: {t}')


def simular(reglas, paquete):
    """Devuelve ([(puerto, vlan)], [etiquetas de las reglas usadas])."""
    p, salidas, traza, tabla = dict(paquete), [], [], 0
    while tabla is not None:
        cand = [r for r in reglas if r['tableId'] == tabla
                and all(_coincide(c, p) for c in r['selector']['criteria'])]
        if not cand:
            break                                   # sin regla: se descarta
        r = max(cand, key=lambda x: x['priority'])
        traza.append(r['_tag'])
        tabla = None
        for i in r['treatment']['instructions']:
            if i['type'] == 'OUTPUT':
                salidas.append((i['port'], p.get('vlan')))
            elif i['type'] == 'TABLE':
                tabla = i['tableId']
            elif i['type'] == 'L2MODIFICATION':
                if i['subtype'] == 'VLAN_PUSH':
                    p['vlan'] = 0
                elif i['subtype'] == 'VLAN_ID':
                    p['vlan'] = i['vlanId']
                elif i['subtype'] == 'VLAN_POP':
                    p['vlan'] = None
    return salidas, traza


def sesion(nombre, rol, mac, ip, estado='VINCULADO', **extra):
    return {'nombre': nombre, 'usuario': nombre, 'mac': mac, 'switch': SW,
            'puerto': PUERTO_USUARIO, 'ip': ip, 'rol': rol, 'estado': estado, **extra}


def reglas_rsw1(r2ctl, pol, topo, sesiones):
    dev = topo['switches'][SW]['dpid']
    return r2ctl.compile_all(pol, topo, {}, sesiones)[dev]


def ipv4(src_mac, ip_src, ip_dst, proto, dport, in_port=PUERTO_USUARIO):
    return {'in_port': in_port, 'eth_src': src_mac, 'eth_dst': GW_MAC, 'eth_type': 0x0800,
            'ip_src': ip_src, 'ip_dst': ip_dst,
            'ip_proto': 6 if proto == 'tcp' else 17, 'dport': dport, 'sport': 40000}


def llega_a_core1(salidas, topo, rol, r2ctl):
    return (topo['switches'][SW]['salida'], r2ctl.vid(rol)) in salidas


# ------------------------------------------------------------------- pruebas
def test_politica_valida(r2ctl, politica):
    pol, topo = politica
    assert r2ctl.validate(pol, topo, quiet=True)


def test_matriz_compilada_igual_al_oraculo(r2ctl, politica):
    """Las 216 combinaciones de `verify` (6 roles x 36 destinos), sin red."""
    pol, topo = politica
    casos = errores = 0
    for rol in pol['roles']:
        mac, ip = '02:05:00:00:00:aa', f'10.{rol * 10}.0.150'
        reglas = reglas_rsw1(r2ctl, pol, topo, [sesion('u', rol, mac, ip)])
        for g, nombre, dst, proto, port in r2ctl.targets(pol, topo):
            esperado = r2ctl.allowed(pol, rol, dst, proto, port)
            salidas, traza = simular(reglas, ipv4(mac, ip, dst, proto, port))
            obtenido = llega_a_core1(salidas, topo, rol, r2ctl)
            casos += 1
            if obtenido != esperado:
                errores += 1
                print(f'rol {rol} -> {g} {proto}/{port}: esperado {esperado}, simulado {obtenido}; {traza}')
    assert casos == 216
    assert errores == 0


@pytest.mark.parametrize('rol', [1, 2, 3, 4, 5, 9])
def test_bloque_critico_y_gestion_nunca_salen(r2ctl, politica, rol):
    """Matrícula y Planillas (bloque crítico) solo para admin; la gestión, para nadie."""
    pol, topo = politica
    mac, ip = '02:05:00:00:00:aa', f'10.{rol * 10}.0.150'
    reglas = reglas_rsw1(r2ctl, pol, topo, [sesion('u', rol, mac, ip)])
    for dst in ('10.100.0.50', '10.100.0.66'):
        sal, _ = simular(reglas, ipv4(mac, ip, dst, 'tcp', 443))
        assert llega_a_core1(sal, topo, rol, r2ctl) == (rol == 5)
    if rol != 5:                       # admin: "todo" en el switch, lo corta Core-1 (nft)
        sal, _ = simular(reglas, ipv4(mac, ip, '192.168.0.16', 'tcp', 22))
        assert not llega_a_core1(sal, topo, rol, r2ctl)


def test_ip_de_origen_falsa_se_descarta_y_cuenta(r2ctl, politica):
    pol, topo = politica
    mac = '02:05:00:00:00:aa'
    reglas = reglas_rsw1(r2ctl, pol, topo, [sesion('alu', 2, mac, '10.20.0.150')])
    for falsa in ('10.20.0.77', '198.51.100.7', '10.50.0.150'):
        sal, traza = simular(reglas, ipv4(mac, falsa, '10.100.1.10', 'tcp', 443))
        assert sal == []
        assert any('R3 spoofing detectado' in t for t in traza)   # contador del sensor


def test_mac_desconocida_no_pasa(r2ctl, politica):
    pol, topo = politica
    reglas = reglas_rsw1(r2ctl, pol, topo, [sesion('alu', 2, '02:05:00:00:00:aa', '10.20.0.150')])
    sal, traza = simular(reglas, ipv4('02:99:99:99:99:99', '10.20.0.150', '10.100.1.10', 'tcp', 443))
    assert sal == [] and traza[-1] == 'T1 table-miss descarta'


def test_bloqueo_r3_corta_incluso_lo_permitido(r2ctl, politica):
    pol, topo = politica
    mac, ip = '02:05:00:00:00:aa', '10.20.0.150'
    libre = reglas_rsw1(r2ctl, pol, topo, [sesion('alu', 2, mac, ip)])
    bloq = reglas_rsw1(r2ctl, pol, topo, [sesion('alu', 2, mac, ip, bloqueado=True, motivo_bloqueo='sid 1')])
    pkt = ipv4(mac, ip, '10.100.1.10', 'tcp', 443)
    assert llega_a_core1(simular(libre, pkt)[0], topo, 2, r2ctl)
    sal, traza = simular(bloq, pkt)
    assert sal == [] and any(t.startswith('T2 R3 bloqueo') for t in traza)


def test_cuarentena_solo_dns_y_mesa_de_ayuda(r2ctl, politica):
    pol, topo = politica
    mac, ip = '02:05:00:00:00:aa', '10.90.0.150'
    reglas = reglas_rsw1(r2ctl, pol, topo, [sesion('alu', 9, mac, ip, estado='CUARENTENA')])
    ok = lambda d, pr, pt: llega_a_core1(simular(reglas, ipv4(mac, ip, d, pr, pt))[0], topo, 9, r2ctl)
    assert ok('10.100.1.130', 'udp', 53)
    assert ok('10.100.1.150', 'tcp', 80)
    assert not ok('10.100.1.10', 'tcp', 443)        # Portal
    assert not ok(topo['internet_ip'], 'tcp', 443)  # sin Internet


def test_ventana_dhcp_sin_ip(r2ctl, politica):
    """Autenticado sin IP: solo el DHCP sale, con la VLAN de su rol (relay de Core-1)."""
    pol, topo = politica
    mac = '02:05:00:00:00:aa'
    reglas = reglas_rsw1(r2ctl, pol, topo, [sesion('doc', 3, mac, None, estado='SIN_IP')])
    dhcp = {'in_port': PUERTO_USUARIO, 'eth_src': mac, 'eth_dst': 'ff:ff:ff:ff:ff:ff',
            'eth_type': 0x0800, 'ip_src': '0.0.0.0', 'ip_dst': '255.255.255.255',
            'ip_proto': 17, 'sport': 68, 'dport': 67}
    assert (topo['switches'][SW]['salida'], 300) in simular(reglas, dhcp)[0]
    assert simular(reglas, ipv4(mac, '10.30.0.150', '10.100.1.10', 'tcp', 443))[0] == []


def test_retorno_desde_core1_se_entrega_sin_etiqueta(r2ctl, politica):
    pol, topo = politica
    mac = '02:05:00:00:00:aa'
    reglas = reglas_rsw1(r2ctl, pol, topo, [sesion('alu', 2, mac, '10.20.0.150')])
    vuelta = {'in_port': topo['switches'][SW]['salida'], 'eth_src': GW_MAC, 'eth_dst': mac,
              'eth_type': 0x0800, 'vlan': 200, 'ip_src': '10.100.1.10', 'ip_dst': '10.20.0.150',
              'ip_proto': 6, 'dport': 40000, 'sport': 443}
    assert simular(reglas, vuelta)[0] == [(PUERTO_USUARIO, None)]
    vuelta['vlan'] = 300                            # otra VLAN: no es para este usuario
    assert simular(reglas, vuelta)[0] == []


def test_eapol_va_al_controlador(r2ctl, politica):
    pol, topo = politica
    reglas = reglas_rsw1(r2ctl, pol, topo, [])
    eapol = {'in_port': PUERTO_USUARIO, 'eth_src': '02:05:00:00:00:aa',
             'eth_dst': 'ff:ff:ff:ff:ff:ff', 'eth_type': 0x888E}
    assert simular(reglas, eapol)[0] == [('CONTROLLER', None)]


def test_siete_reglas_por_sesion(r2ctl, politica):
    """Coste por usuario: 7 reglas (las de broadcast por VLAN se comparten)."""
    pol, topo = politica
    s = [sesion(f'u{i}', 2, f'02:05:00:00:01:{i:02x}', f'10.20.0.{10 + i}') for i in range(3)]
    n = [len(reglas_rsw1(r2ctl, pol, topo, s[:k])) for k in range(4)]
    assert n[2] - n[1] == 7 and n[3] - n[2] == 7


def test_firmas_ids_desde_la_politica(r2ctl, politica):
    """Trazabilidad de R2: cada recurso no permitido de cada rol tiene su firma."""
    pol, _ = politica
    txt = r2ctl.ids_reglas(pol)
    firmas = [l for l in txt.splitlines() if l.startswith('alert ')]
    sids = [int(l.split('sid:')[1].split(';')[0]) for l in firmas]
    assert len(sids) == len(set(sids))
    assert all(2000000 <= s < 3000000 for s in sids)
    for rol, r in pol['roles'].items():
        n = r['nombre']
        gw = f'10.{rol * 10}.0.1'
        mias = [l for l in firmas if f'denegado: {n} ->' in l]
        assert all(f',!{gw}]' in l for l in mias), 'el router del rol no debe contar como usuario'
        if r['permite'] == 'todo':
            assert not any('no ofrecido' in l for l in mias)
            continue
        for g, rec in pol['recursos'].items():
            if g not in r['permite']:
                assert any(f'-> {rec["prefijo"]} any' in l and f'{n} -> {g} ' in l for l in mias), (rol, g)
        assert any('-> Internet' in l for l in mias) == (not r.get('internet'))
