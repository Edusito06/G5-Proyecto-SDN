"""Pruebas unitarias de R4: detector de DDoS (ddos.py) y regla de límite en T2 (r2ctl).

El detector recibe contadores acumulados como los de ONOS (bytes, paquetes, instante de
lectura cada 5 s) y devuelve qué fuentes limitar y cuándo levantar el límite.
"""
import pytest

import ddos
from test_r2ctl import llega_a_core1, reglas_rsw1, sesion, simular, ipv4

ATK, ATK2, LEGIT = '02:05:00:00:00:02', '02:05:00:00:00:06', '02:05:00:00:00:01'
MBIT = 1e6 / 8                       # bytes por segundo de 1 Mbit/s


def cfg(**k):
    base = dict(user_bps=50e6, user_pps=15000, srv_bps=80e6, srv_pps=20000,
                share_bps=10e6, share_pps=2000, sostener=2, enfriar=30)
    return ddos.Detector(**{**base, **k})


class Red:
    """Contadores acumulados que avanzan a la tasa indicada (Mbit/s y paquetes/s)."""
    def __init__(self):
        self.t, self.c = 0.0, {}

    def paso(self, dt, tasas):
        self.t += dt
        for k, (mbps, pps) in tasas.items():
            b, p, _ = self.c.get(k, (0, 0, 0))
            self.c[k] = (b + mbps * MBIT * dt, p + pps * dt, self.t)
        return {k: v for k, v in self.c.items()}


def correr(det, pasos, limitados=()):
    """pasos: [{clave: (Mbit/s, pps)}]; claves ('u'|'i'|'o', mac) y ('r', g)."""
    red, acciones, lim = Red(), [], set(limitados)
    for i, tasas in enumerate(pasos):
        c = red.paso(5, tasas)
        u = {k[1]: v for k, v in c.items() if k[0] == 'u'}
        r = {k[1]: v for k, v in c.items() if k[0] == 'r'}
        o = {k[1]: v for k, v in c.items() if k[0] == 'o'}
        i_ = {k[1]: v for k, v in c.items() if k[0] == 'i'}
        for acc, mac, det_ in det.actualizar(u, r, o, sorted(lim), red.t, i_):
            acciones.append((i, acc, mac, det_))
            (lim.add if acc == 'limitar' else lim.discard)(mac)
    return acciones


def test_trafico_normal_no_dispara():
    pasos = [{('u', LEGIT): (8, 900), ('u', ATK): (12, 1500), ('r', 'G12'): (20, 2400)}] * 12
    assert correr(cfg(), pasos) == []


def test_descarga_legitima_a_toda_velocidad_no_es_fuente():
    """Quien descarga 1,3 Gbit/s envía ~30 Mbit/s y ~55 000 ACK/s, pero recibe mucho más:
    no es una fuente, ni sola ni durante un ataque distribuido contra el mismo servidor."""
    descarga = {('u', LEGIT): (30, 55000), ('i', LEGIT): (1300, 110000)}
    assert correr(cfg(), [descarga] * 6) == []
    ataque = {**descarga, ('u', ATK): (45, 4000), ('i', ATK): (0.2, 300),
              ('u', ATK2): (45, 4000), ('i', ATK2): (0.2, 300), ('r', 'G12'): (120, 63000)}
    assert {m for _, a, m, _ in correr(cfg(), [descarga] + [ataque] * 3)} == {ATK, ATK2}


def test_un_pico_aislado_no_dispara():
    """Una descarga/subida puntual sobre el umbral no basta: se pide que se sostenga."""
    pasos = [{('u', ATK): (5, 500)}] * 3 + [{('u', ATK): (90, 8000)}] + [{('u', ATK): (5, 500)}] * 4
    assert correr(cfg(), pasos) == []


def test_fuente_volumetrica_por_bps():
    pasos = [{('u', ATK): (2, 200), ('u', LEGIT): (3, 300)}] + [{('u', ATK): (100, 9000), ('u', LEGIT): (3, 300)}] * 4
    acc = correr(cfg(), pasos)
    assert [(a, m) for _, a, m, _ in acc] == [('limitar', ATK)]
    i, _, _, d = acc[0]
    assert i == 2                                  # segunda muestra alta: ~10 s
    assert d['motivo'] == 'volumétrico' and 90e6 < d['bps'] < 110e6


def test_fuente_volumetrica_por_pps_con_paquetes_pequenos():
    """Flood de paquetes de 64 B: pocos Mbit/s pero muchos paquetes por segundo."""
    pasos = [{('u', ATK): (0.1, 10)}] + [{('u', ATK): (15, 30000)}] * 3
    acc = correr(cfg(), pasos)
    assert [(a, m) for _, a, m, _ in acc] == [('limitar', ATK)]


def test_ataque_distribuido_identifica_a_los_que_aportan():
    """Ninguna fuente supera el umbral individual, pero juntas saturan G12: se limitan
    las que aportan más de su parte; el usuario legítimo (2 Mbit/s) no se toca."""
    normal = {('u', ATK): (1, 100), ('u', ATK2): (1, 100), ('u', LEGIT): (2, 200), ('r', 'G12'): (4, 400)}
    ataque = {('u', ATK): (45, 4000), ('u', ATK2): (45, 4000), ('u', LEGIT): (2, 200), ('r', 'G12'): (92, 8200)}
    acc = correr(cfg(), [normal] + [ataque] * 3)
    limitados = {m for _, a, m, _ in acc if a == 'limitar'}
    assert limitados == {ATK, ATK2}
    assert all(d['recurso'] == 'G12' for _, a, _, d in acc)


def test_se_levanta_tras_enfriar_y_no_antes():
    """Con el límite puesto, la tasa ofrecida (antes del meter) decide cuándo levantar."""
    det = cfg(enfriar=30)
    ataque = [{('u', ATK): (2, 150), ('o', ATK): (100, 9000)}] * 3       # sigue atacando
    calma = [{('u', ATK): (1, 80), ('o', ATK): (1, 80)}] * 8             # dejó de atacar
    acc = correr(det, ataque + calma, limitados={ATK})
    lev = [(i, a) for i, a, m, _ in acc if a == 'levantar']
    assert len(lev) == 1
    assert lev[0][0] >= 3 + 6                       # >= 30 s de calma (6 muestras de 5 s)


def test_sin_muestra_nueva_de_onos_no_cambia_nada():
    """ONOS actualiza cada 5 s; leer dos veces el mismo contador no es tasa cero."""
    det = cfg()
    c = {ATK: (100 * MBIT * 5, 45000, 5.0)}
    det.actualizar({ATK: (0, 0, 0.0)}, {}, {}, [], 0)
    det.actualizar(c, {}, {}, [], 5)
    det.actualizar(c, {}, {}, [], 7.5)              # misma lectura
    assert det.tasa[('u', ATK)][0] == pytest.approx(100e6)
    assert det.racha[('u', ATK)] == 1


def test_contador_reiniciado_no_da_tasa_negativa():
    det = cfg()
    det.actualizar({ATK: (10**9, 10**6, 5.0)}, {}, {}, [], 5)
    det.actualizar({ATK: (1000, 10, 10.0)}, {}, {}, [], 10)   # regla reinstalada
    assert ('u', ATK) not in det.tasa


# ------------------------------------------------ regla de límite (simulador)
def test_regla_de_limite_pasa_por_el_meter_y_conserva_la_politica(r2ctl, politica):
    pol, topo = politica
    mac, ip = '02:05:00:00:00:aa', '10.20.0.150'
    reglas = reglas_rsw1(r2ctl, pol, topo, [sesion('alu', 2, mac, ip, limite_meter=7)])
    t2 = [r for r in reglas if r['tableId'] == 2 and r['priority'] == 39000]
    assert len(t2) == 1
    assert t2[0]['treatment']['instructions'] == [{'type': 'METER', 'meterId': 7},
                                                  {'type': 'TABLE', 'tableId': 3}]
    # limitado no es bloqueado: lo permitido sigue saliendo (dentro del meter) y lo
    # denegado sigue denegado
    assert llega_a_core1(simular(reglas, ipv4(mac, ip, '10.100.1.10', 'tcp', 443))[0], topo, 2, r2ctl)
    assert not llega_a_core1(simular(reglas, ipv4(mac, ip, '10.100.0.130', 'tcp', 443))[0], topo, 2, r2ctl)


def test_bloqueo_de_r3_gana_al_limite_de_r4(r2ctl, politica):
    pol, topo = politica
    mac, ip = '02:05:00:00:00:aa', '10.20.0.150'
    reglas = reglas_rsw1(r2ctl, pol, topo, [sesion('alu', 2, mac, ip, limite_meter=7, bloqueado=True)])
    assert not [r for r in reglas if r['tableId'] == 2 and r['priority'] == 39000]
    assert simular(reglas, ipv4(mac, ip, '10.100.1.10', 'tcp', 443))[0] == []


def test_lectura_de_contadores_de_onos():
    """identity agrupa los contadores de ONOS: T3 por usuario, T2 límite, T4 por recurso."""
    import os
    os.environ.setdefault('R2_LOCAL', '1')
    import identity
    flows = [
        {'tableId': '3', 'priority': 35000, 'bytes': 1000, 'packets': 10, 'lastSeen': 5000,
         'selector': {'criteria': [{'type': 'IN_PORT', 'port': 4}, {'type': 'ETH_SRC', 'mac': ATK.upper()}]}},
        {'tableId': '2', 'priority': 39000, 'bytes': 9000, 'packets': 90, 'lastSeen': 5000,
         'selector': {'criteria': [{'type': 'ETH_SRC', 'mac': ATK.upper()}]}},
        {'tableId': '4', 'priority': 25000, 'bytes': 300, 'packets': 3, 'lastSeen': 5000,
         'selector': {'criteria': [{'type': 'VLAN_VID', 'vlanId': 200}, {'type': 'IPV4_DST', 'ip': '10.100.1.144/28'}]}},
        {'tableId': '4', 'priority': 25000, 'bytes': 700, 'packets': 7, 'lastSeen': 6000,
         'selector': {'criteria': [{'type': 'VLAN_VID', 'vlanId': 100}, {'type': 'IPV4_DST', 'ip': '10.100.1.144/28'}]}},
    ]
    flows += [{'tableId': '5', 'priority': 10100, 'bytes': b, 'packets': 1, 'lastSeen': 5000,
               'selector': {'criteria': [{'type': 'IN_PORT', 'port': up}, {'type': 'ETH_DST', 'mac': ATK.upper()}]}}
              for up, b in ((1, 400), (2, 100))]                 # un T5 por uplink
    u, o, r, i = identity.leer_contadores(flows)
    assert u == {ATK: (1000, 10, 5.0)} and o == {ATK: (9000, 90, 5.0)}
    assert r == {'G12': (1000, 10, 6.0)} and i == {ATK: (500, 2, 5.0)}
