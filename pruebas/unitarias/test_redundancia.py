"""Pruebas unitarias de g05-redundancia: el plan de respaldo del control in-band.

Se genera el plan de los 6 switches (reglas y grupos Fast Failover) y un simulador
sigue el tráfico OpenFlow (TCP/6653) de cada switch hacia ONOS-1 y ONOS-2, y la
respuesta de vuelta, por la topología de FABRIC. Un grupo FF usa el primer puerto
vivo, como hace OVS con la vida que reporta BFD. Se prueba sin fallas, con cada
enlace entre switches caído y con Core-1 caído entero.
"""
import itertools
import re

import pytest

from conftest import FILES, cargar

red = cargar('g05_redundancia', FILES / 'g05-redundancia.py')
SWITCHES = list(red.IP)
CONTROL = {'onos-1': red.ONOS, 'onos-2': red.ONOS2}


def ofport(nic):
    return int(nic[3:]) - 3                       # ens4 -> 1, ens5 -> 2, ...


@pytest.fixture(scope='module')
def planes():
    red.ofport = ofport
    out = {}
    for h in SWITCHES:
        grupos, reglas = red.plan(h)
        parsed = []
        for f in reglas:
            m = re.search(r'priority=(\d+),in_port=(\w+),.*?,(arp|tcp),(.*) actions=(.*)', f)
            prio, inp, proto, match, act = m.groups()
            campos = dict(kv.split('=') for kv in match.split(','))
            parsed.append({'prio': int(prio), 'in': inp, 'proto': proto, 'm': campos, 'act': act})
        out[h] = (grupos, parsed)
    return out


ENLACES = sorted({tuple(sorted((a, b))) for a, v in red.FABRIC.items() for b in v
                  if b in red.FABRIC})


def vecino(host, puerto):
    """(vecino, puerto de entrada en el vecino) del puerto `puerto` de `host`."""
    for peer, nic in red.FABRIC[host].items():
        if ofport(nic) == puerto:
            if peer in CONTROL:
                return peer, None
            return peer, ofport(red.FABRIC[peer][host])
    raise AssertionError(f'{host}: puerto {puerto} sin vecino')


def caido(a, b, fallas):
    return tuple(sorted((a, b))) in fallas or a in fallas or b in fallas


def recorrer(planes, origen, src, dst, sube, fallas, inicio=None):
    """Sigue un paquete TCP/6653 desde `origen` (LOCAL) o desde un controlador.
    Devuelve el nodo donde se entrega o None si se pierde (o hay un bucle)."""
    tp = ('tp_dst', '6653') if sube else ('tp_src', '6653')
    host, inp = (origen, 'LOCAL') if inicio is None else inicio
    for _ in range(20):
        if host in fallas:
            return None
        grupos, reglas = planes[host]
        cand = [r for r in reglas if r['proto'] == 'tcp' and r['in'] == str(inp)
                and r['m'].get('nw_src') == src and r['m'].get('nw_dst') == dst
                and r['m'].get(tp[0]) == tp[1]]
        if not cand:
            return None
        act = max(cand, key=lambda r: r['prio'])['act']
        if act == 'LOCAL':
            return host if red.IP[host] == dst else None
        if act.startswith('group:'):
            vivos = [p for p in grupos[int(act[6:])] if not caido(host, vecino(host, p)[0], fallas)]
            if not vivos:
                return None
            puerto = vivos[0]
        else:
            puerto = int(act.split(':')[1])
        nb, nb_in = vecino(host, puerto)
        if caido(host, nb, fallas):
            return None
        if nb in CONTROL:
            return nb if CONTROL[nb] == dst else None
        host, inp = nb, nb_in
    return None


def entrada_desde(control):
    """(switch, puerto) por donde entra al fabric lo que envía un controlador."""
    for sw, v in red.FABRIC.items():
        if control in v:
            return sw, ofport(v[control])


def alcanza(planes, sw, control, fallas=frozenset()):
    """Ida y vuelta entre `sw` y `control`. Un switch conectado directo a su
    controlador (DC-DIST a ONOS-1) usa la regla del bootstrap: un solo enlace,
    sin respaldo posible, así que no hay nada que proteger."""
    me, ip_c = red.IP[sw], CONTROL[control]
    directo = control in red.FABRIC[sw]
    propia = any(r['in'] == 'LOCAL' and r['m'].get('nw_dst') == ip_c for r in planes[sw][1])
    if directo and not propia:
        return True
    ida = recorrer(planes, sw, me, ip_c, True, fallas) == control
    vuelta = recorrer(planes, None, ip_c, me, False, fallas, inicio=entrada_desde(control)) == sw
    return ida and vuelta


@pytest.mark.parametrize('control', ['onos-1', 'onos-2'])
def test_sin_fallas_todos_llegan_a_los_dos_controladores(planes, control):
    assert [sw for sw in SWITCHES if not alcanza(planes, sw, control)] == []


@pytest.mark.parametrize('enlace', ENLACES, ids=lambda e: f'{e[0]}--{e[1]}')
@pytest.mark.parametrize('control', ['onos-1', 'onos-2'])
def test_un_enlace_caido_no_aisla_a_nadie(planes, enlace, control):
    fallas = {enlace}
    afectados = [sw for sw in SWITCHES if not alcanza(planes, sw, control, fallas)]
    assert afectados == [], f'sin control por {control} con {enlace} caído: {afectados}'


@pytest.mark.parametrize('control', ['onos-1', 'onos-2'])
def test_core1_caido_los_demas_siguen_por_core2(planes, control):
    fallas = {'core-1'}
    vivos = [sw for sw in SWITCHES if sw != 'core-1']
    assert [sw for sw in vivos if not alcanza(planes, sw, control, fallas)] == []


def test_grupos_fast_failover_tienen_respaldo(planes):
    for h, (grupos, _) in planes.items():
        for gid, puertos in grupos.items():
            assert len(puertos) == 2 and puertos[0] != puertos[1], (h, gid)
            assert gid in red.GRANGE


def test_bfd_solo_entre_switches():
    """Los puertos hacia las VMs de control no llevan BFD (no hablan BFD)."""
    for h, v in red.FABRIC.items():
        for peer in v:
            assert (peer in red.CONTROLLER_PEERS) == (peer not in red.FABRIC)


def test_reglas_por_encima_del_bootstrap(planes):
    for _, (_, reglas) in planes.items():
        for r in reglas:
            assert r['prio'] in (red.P_LOCAL, red.P_TRANSIT)
    assert red.P_LOCAL > 64500 and red.P_TRANSIT > 62500
