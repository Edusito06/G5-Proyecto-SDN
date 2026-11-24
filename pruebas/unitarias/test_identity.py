"""Pruebas unitarias de identity (R1, R2 y R3), sin ONOS ni RADIUS.

identity se importa con su estado en un directorio temporal; los eventos de AAA,
RADIUS, Kea y del IDS se le entregan llamando a sus funciones, como lo hace su API.
"""
import json
import os
import time

import pytest

DEV = 'of:0000000000000006'          # R-SW1
MAC = '02:05:00:00:00:02'


@pytest.fixture()
def idn(tmp_path, monkeypatch, r2ctl):
    os.environ['R2_SESSIONS'] = str(tmp_path / 'sessions.json')
    os.environ['G05_INCIDENTES'] = str(tmp_path / 'incidentes.jsonl')
    import identity as m
    monkeypatch.setattr(m, 'STATE', str(tmp_path / 'sessions.json'))
    monkeypatch.setattr(m, 'INCIDENTES', str(tmp_path / 'incidentes.jsonl'))
    monkeypatch.setattr(m.time, 'sleep', lambda s: None)       # sin esperas reales
    for d in (m.sessions, m.quarantine, m.blocks, m.alert_hist, m.intentos,
              m.mitigacion_pendiente, m.spoof_gracia):
        d.clear()
    m.radius_q.clear()
    return m


def eventos(m):
    try:
        return [json.loads(l) for l in open(m.INCIDENTES)]
    except OSError:
        return []


def aprobar(m, usuario, vlan, mac=MAC, puerto=4, hace=0.0):
    m.radius_q.append((time.time() - hace, usuario, str(vlan)))
    m.on_approved(DEV, puerto, mac, usuario)
    return next((s for s in m.sessions.values() if s['mac'] == mac), None)


# ----------------------------------------------------------------- R1: sesión
def test_union_radius_y_aaa_da_el_rol_de_la_vlan(idn):
    s = aprobar(idn, 'doc01', 300)
    assert s['rol'] == 3 and s['estado'] == 'SIN_IP' and s['ip'] is None
    assert s['switch'] == 'r-sw1' and s['puerto'] == 4


def test_aaa_sin_respuesta_de_radius_se_rechaza(idn):
    idn.on_approved(DEV, 4, MAC, 'alu01')
    assert idn.sessions == {}
    assert any(e['ev'] == 'SESION_RECHAZADA' for e in eventos(idn))


def test_respuesta_de_radius_de_otro_usuario_no_se_une(idn):
    idn.radius_q.append((time.time(), 'admin01', '500'))
    idn.on_approved(DEV, 4, MAC, 'alu01')
    assert idn.sessions == {}
    assert len(idn.radius_q) == 1                   # la de admin01 sigue pendiente


def test_respuesta_de_radius_vencida_no_se_une(idn):
    assert aprobar(idn, 'alu01', 200, hace=idn.JOIN_WINDOW + 5) is None


def test_vlan_de_un_rol_inexistente_se_rechaza(idn):
    assert aprobar(idn, 'alu01', 700) is None


def test_switch_sin_politica_se_rechaza(idn):
    idn.radius_q.append((time.time(), 'alu01', '200'))
    idn.on_approved('of:00000000000000ff', 4, MAC, 'alu01')
    assert idn.sessions == {}


def test_dhcp_vincula_solo_ips_de_la_subred_del_rol(idn):
    aprobar(idn, 'alu01', 200)
    assert not idn.on_dhcp('add', MAC, '10.30.0.105')          # subred de docentes
    assert idn.on_dhcp('add', MAC, '10.20.0.105')
    s = next(iter(idn.sessions.values()))
    assert s['estado'] == 'VINCULADO' and s['ip'] == '10.20.0.105'
    assert idn.on_dhcp('del', MAC, '10.20.0.105')
    assert s['ip'] is None and s['estado'] == 'SIN_IP'


def test_dhcp_sin_sesion_se_rechaza_y_registra(idn):
    assert not idn.on_dhcp('add', '02:05:00:00:00:99', '10.20.0.150')
    assert any(e['ev'] == 'DHCP_SIN_SESION' for e in eventos(idn))


def test_reautenticacion_conserva_la_ip(idn):
    aprobar(idn, 'alu01', 200)
    idn.on_dhcp('add', MAC, '10.20.0.105')
    s = aprobar(idn, 'alu01', 200)
    assert s['ip'] == '10.20.0.105' and s['estado'] == 'VINCULADO'


def test_cambio_de_rol_obliga_a_pedir_ip_nueva(idn):
    aprobar(idn, 'alu01', 200)
    idn.on_dhcp('add', MAC, '10.20.0.105')
    s = aprobar(idn, 'admin01', 500)
    assert s['rol'] == 5 and s['ip'] is None


def test_un_equipo_que_cambia_de_puerto_no_deja_sesion_vieja(idn):
    aprobar(idn, 'alu01', 200, puerto=4)
    aprobar(idn, 'alu01', 200, puerto=3)
    assert [s['puerto'] for s in idn.sessions.values()] == [3]


def test_las_sesiones_sobreviven_un_reinicio(idn):
    aprobar(idn, 'doc01', 300)
    guardadas = json.load(open(idn.STATE))
    assert [(s['usuario'], s['rol']) for s in guardadas] == [('doc01', 3)]


# ----------------------------------------------------------------- R3: alertas
def alerta(sid, ip='10.20.0.105', mac=MAC):
    return {'sid': sid, 'firma': f'firma {sid}', 'src_ip': ip, 'src_mac': mac,
            'dest_ip': '10.100.1.150', 'ts': time.time(), 'retardo_agente_ms': 30}


def test_alerta_del_ids_bloquea_la_mac_autenticada(idn):
    aprobar(idn, 'alu01', 200)
    idn.on_dhcp('add', MAC, '10.20.0.105')
    assert idn.on_alert(alerta(1000001, mac=None))             # identifica por IP
    assert MAC in idn.blocks
    evs = [e['ev'] for e in eventos(idn)]
    assert 'ALERTA_IDS' in evs and 'BLOQUEO' in evs


def test_tres_alertas_en_diez_minutos_mandan_a_cuarentena(idn):
    aprobar(idn, 'alu01', 200)
    idn.on_dhcp('add', MAC, '10.20.0.105')
    for sid in (1000001, 1000002, 1000010):
        idn.on_alert(alerta(sid))
    s = next(iter(idn.sessions.values()))
    assert idn.quarantine.get(MAC) and s['rol'] == 9 and s['rol_orig'] == 2
    assert s['ip'] is None                                     # nueva IP de la VLAN 900


def test_alerta_sin_origen_identificable_no_bloquea(idn):
    assert not idn.on_alert(alerta(1000001, ip='10.20.0.200', mac=None))
    assert idn.blocks == {}


# ------------------------------------------------------------ R2: trazabilidad
def test_intento_denegado_se_registra_sin_bloquear(idn):
    aprobar(idn, 'alu01', 200)
    idn.on_dhcp('add', MAC, '10.20.0.105')
    b = alerta(2002004) | {'firma': 'G05 R2 intento denegado: alumno -> G04 matricula',
                           'dest_ip': '10.100.0.50', 'dest_port': 443, 'proto': 'TCP'}
    assert idn.on_alert(b) and idn.on_alert(b)
    assert idn.blocks == {}
    assert idn.intentos[('alu01', 'alumno -> G04 matricula')]['n'] == 2
    reg = [e for e in eventos(idn) if e['ev'] == 'INTENTO_DENEGADO'][0]
    assert reg['usuario'] == 'alu01' and reg['rol'] == 2 and reg['dst'] == '10.100.0.50:443/TCP'
    assert 'fecha' in reg and 'ts' in reg


# ---------------------------------------------------- API: quién puede llamar
@pytest.mark.parametrize('ip,res,metodo,arg,permitido', [
    ('127.0.0.1', 'block', 'DELETE', MAC, True),               # administración local
    ('192.168.0.19', 'sessions', 'POST', None, True),           # FreeRADIUS
    ('192.168.0.19', 'block', 'POST', MAC, False),
    ('192.168.0.19', 'sessions', 'DELETE', MAC, False),
    ('192.168.0.16', 'aaa', 'POST', None, True),                # agentes AAA
    ('192.168.0.22', 'alert', 'POST', None, True),              # IDS
    ('192.168.0.22', 'sessions', 'POST', None, False),
    ('192.168.0.20', 'dhcp', 'POST', None, True),               # Kea
    ('192.168.0.20', 'alert', 'POST', None, False),
    ('10.20.0.105', 'sessions', 'POST', None, False),           # un usuario
    ('10.20.0.105', 'block', 'DELETE', MAC, False),
])
def test_cada_origen_solo_llama_lo_suyo(idn, ip, res, metodo, arg, permitido):
    h = idn.H.__new__(idn.H)
    h.client_address = (ip, 50000)
    assert h.allowed(res, metodo, arg) is permitido
