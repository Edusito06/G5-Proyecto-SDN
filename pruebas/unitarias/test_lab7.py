"""Pruebas obligatorias del Lab 7 (sin red): R1-01..03, R2-01..03 y R3-03, R3-05, R3-06.

Cada prueba lleva su código del informe previo y su caso X.Y.Z. Las que necesitan el
FreeRADIUS o el Suricata reales (R1-01, R1-02, R1-03 en vivo, multirol, R3-01, R3-02 y
R3-04) están en test_lab7_slice.py. Las funciones referenciales del informe previo se
mapean así:

  R1-01/02  validate_credentials  -> FreeRADIUS (EAP-TLS + LDAP) e identity.on_approved
  R1-03     register_failed_attempt / is_locked -> g05-bloqueo.py (funciones con el mismo nombre)
  R2-01/02  evaluate_access       -> r2ctl.evaluate_access
  R2-03     translate_policy      -> r2ctl.compile_all / tabla4 (reglas T4 de ONOS)
  R3-03     check_ip_binding      -> reglas T1 de r2ctl (puerto + MAC + IP)
  R3-05     build_block_rule      -> r2ctl.compile_all con la sesión bloqueada (T2) + identity.vencer
  R3-06     log_incident          -> identity.log (registro de seguridad incidentes.jsonl)
"""
import copy
import json
import time

import pytest

from conftest import FILES, cargar
from test_identity import DEV, MAC, aprobar, eventos, idn  # noqa: F401  (fixture idn)
from test_r2ctl import llega_a_core1, reglas_rsw1, sesion, simular, ipv4

bloqueo = cargar('g05_bloqueo', FILES / 'g05-bloqueo.py')
ADMIN, ADMINISTRATIVO, DOCENTE, ALUMNO, INVITADO = 5, 4, 3, 2, 1


# ============================================================ Módulo 1 · R1
# 1.1 Autenticación
def test_1_1_1_R1_01_usuario_valido_obtiene_identidad_y_rol(idn):
    """Tras el Access-Accept de FreeRADIUS (VLAN 300) y la aprobación de AAA, identity
    devuelve la sesión con el identificador del usuario y su rol."""
    s = aprobar(idn, 'doc01', 300)
    assert s['usuario'] == 'doc01' and s['rol'] == DOCENTE
    assert [e['ev'] for e in eventos(idn)] == []          # ningún rechazo registrado


@pytest.mark.parametrize('nombre', ["' OR '1'='1", '', '*', 'alu01)(uid=*', 'alu01\nACEPTA admin01',
                                    'x' * 65, 'alu01 ', '../../etc/passwd'])
def test_1_1_2_R1_02_entradas_maliciosas_no_se_procesan(nombre, monkeypatch):
    """El módulo de bloqueo no acepta como usuario cadenas vacías, inyecciones (SQL/LDAP)
    ni nombres con espacios o saltos de línea: no cuentan ni reinician a ninguna cuenta."""
    assert not bloqueo.USUARIO_OK.match(nombre)
    monkeypatch.setattr(bloqueo, 'avisar', lambda *a, **k: None)
    est = {}
    bloqueo.procesar(est, 'RECHAZO', nombre, 1000)
    assert est == {}


def test_1_1_2_R1_02_un_nombre_con_salto_de_linea_no_fabrica_lineas():
    """FreeRADIUS escribe el usuario en hexadecimal: 'x\\nACEPTA admin01' es una sola
    línea, que además se descarta por no ser un nombre válido."""
    linea = 'RECHAZO ' + 'x\nACEPTA admin01'.encode().hex()
    assert bloqueo.leer_linea(linea) == ('RECHAZO', 'x\nACEPTA admin01')
    assert bloqueo.leer_linea('ACEPTA zz-no-hex') is None
    assert bloqueo.leer_linea('BORRAR 616c753031') is None


def test_1_1_2_R1_02_sin_respuesta_de_radius_no_hay_sesion_ni_rol(idn):
    idn.on_approved(DEV, 4, MAC, 'no_existe')
    assert idn.sessions == {}


# 1.2 Bloqueo por intentos fallidos (N = 5 en 15 min, bloqueo de 15 min)
def test_1_2_1_R1_03_cuatro_fallos_no_bloquean_el_quinto_si():
    est, t = {}, 1000.0
    for i in range(4):
        r = bloqueo.register_failed_attempt(est, 'a.lopez', t + i)
        assert not r['bloqueado']
    assert not bloqueo.is_locked(est, 'a.lopez', t + 4)
    r = bloqueo.register_failed_attempt(est, 'a.lopez', t + 5)
    assert r['bloqueado'] and r['nuevo_bloqueo'] and r['fallos'] == 5
    assert bloqueo.is_locked(est, 'a.lopez', t + 6)


def test_1_2_2_R1_03_bloqueada_rechaza_incluso_un_acceso_correcto_y_vence_a_los_15_min():
    est, t = {}, 1000.0
    for i in range(5):
        bloqueo.register_failed_attempt(est, 'a.lopez', t + i)
    bloqueo.register_success(est, 'a.lopez')                 # credencial válida
    assert bloqueo.is_locked(est, 'a.lopez', t + 10)          # sigue bloqueada
    assert bloqueo.vencidos(est, t + 4 + 899) == []
    assert bloqueo.vencidos(est, t + 4 + 900) == ['a.lopez']  # 900 s tras el 5.º fallo
    assert not bloqueo.is_locked(est, 'a.lopez', t + 905)
    assert est['a.lopez']['fallos'] == []                     # contador a cero


def test_1_2_3_R1_03_fallos_fuera_de_la_ventana_o_tras_un_acierto_no_suman():
    est = {}
    for i in range(4):
        bloqueo.register_failed_attempt(est, 'u', 1000 + i)
    assert not bloqueo.register_failed_attempt(est, 'u', 1000 + 901)['bloqueado']   # ventana 900 s
    est = {}
    for i in range(4):
        bloqueo.register_failed_attempt(est, 'u', 1000 + i)
    bloqueo.register_success(est, 'u')                       # fallos *seguidos*
    assert bloqueo.register_failed_attempt(est, 'u', 1010)['fallos'] == 1


# ============================================================ Módulo 2 · R2
# 2.1 Decisión de acceso
def test_2_1_1_R2_01_admin_entra_al_recurso_critico_y_el_docente_no(r2ctl, politica):
    pol, _ = politica
    d, m = r2ctl.evaluate_access(pol, ADMIN, 'G04')
    assert d == 'PERMIT' and 'G04' in m
    d, m = r2ctl.evaluate_access(pol, DOCENTE, 'G04')
    assert d == 'DENY' and 'sin permiso' in m and 'critico' in m


def test_2_1_2_R2_01_servicio_no_ofrecido_se_deniega(r2ctl, politica):
    pol, _ = politica
    assert r2ctl.evaluate_access(pol, DOCENTE, 'G06', 'tcp', 443)[0] == 'PERMIT'
    d, m = r2ctl.evaluate_access(pol, DOCENTE, 'G06', 'tcp', 22)
    assert d == 'DENY' and 'no ofrece tcp/22' in m


@pytest.mark.parametrize('rol,recurso', [('Invitado', 'G10'), (99, 'G10'), (None, 'G10'),
                                         (ADMIN, 'consola_inexistente'), (ADMIN, None), (ALUMNO, 'g10')])
def test_2_1_3_R2_02_rol_o_recurso_no_registrado_se_deniega_por_defecto(r2ctl, politica, rol, recurso):
    pol, _ = politica
    d, m = r2ctl.evaluate_access(pol, rol, recurso)
    assert d == 'DENY' and 'no registrado' in m and 'por defecto' in m


def test_2_1_4_R2_02_ip_fuera_del_inventario_se_deniega(r2ctl, politica):
    pol, _ = politica
    assert not r2ctl.allowed(pol, ALUMNO, '10.200.0.5', 'tcp', 443)      # intranet sin recurso
    assert not r2ctl.allowed(pol, 77, '10.100.1.10', 'tcp', 443)         # rol inexistente


# 2.2 Traducción de la política a OpenFlow
def test_2_2_1_R2_03_permit_y_deny_sobre_el_mismo_recurso_prevalece_deny(r2ctl, politica):
    pol, topo = politica
    pol = copy.deepcopy(pol)
    pol['roles'][DOCENTE]['deniega'] = ['G07']               # ya permitido: G06, G07, G08...
    assert 'G07' in pol['roles'][DOCENTE]['permite']
    assert r2ctl.validate(pol, topo, quiet=True)
    mac, ip = '02:05:00:00:00:aa', '10.30.0.150'
    reglas = reglas_rsw1(r2ctl, pol, topo, [sesion('doc', DOCENTE, mac, ip)])
    pref = pol['recursos']['G07']['prefijo']
    sobre = [r for r in reglas if r['tableId'] == 4
             and {'type': 'VLAN_VID', 'vlanId': 300} in r['selector']['criteria']
             and {'type': 'IPV4_DST', 'ip': pref} in r['selector']['criteria']]
    deny = [r for r in sobre if not r['treatment']['instructions']]
    permit = [r for r in sobre if r['treatment']['instructions']]
    assert deny and permit
    assert min(r['priority'] for r in deny) > max(r['priority'] for r in permit)
    for port in (443, 22):                                   # ambos servicios de G07
        sal, traza = simular(reglas, ipv4(mac, ip, '10.100.0.146', 'tcp', port))
        assert not llega_a_core1(sal, topo, DOCENTE, r2ctl)
        assert any('deniega docente -> G07' in t for t in traza)
    assert llega_a_core1(simular(reglas, ipv4(mac, ip, '10.100.0.130', 'tcp', 443))[0], topo, DOCENTE, r2ctl)
    assert r2ctl.evaluate_access(pol, DOCENTE, 'G07')[0] == 'DENY'


def test_2_2_2_R2_03_deny_explicito_gana_tambien_al_permiso_total(r2ctl, politica):
    pol, topo = politica
    pol = copy.deepcopy(pol)
    pol['roles'][ADMIN]['deniega'] = ['G05']
    mac, ip = '02:05:00:00:00:aa', '10.50.0.150'
    reglas = reglas_rsw1(r2ctl, pol, topo, [sesion('adm', ADMIN, mac, ip)])
    assert not llega_a_core1(simular(reglas, ipv4(mac, ip, '10.100.0.66', 'tcp', 443))[0], topo, ADMIN, r2ctl)
    assert llega_a_core1(simular(reglas, ipv4(mac, ip, '10.100.0.50', 'tcp', 443))[0], topo, ADMIN, r2ctl)
    assert r2ctl.evaluate_access(pol, ADMIN, 'G05')[0] == 'DENY'


def test_2_2_3_R2_03_la_politica_compilada_coincide_con_la_decision(r2ctl, politica):
    """Las 216 combinaciones: lo que hace el switch (simulado) = evaluate_access/allowed."""
    pol, topo = politica
    errores = 0
    for rol in pol['roles']:
        mac, ip = '02:05:00:00:00:aa', f'10.{rol * 10}.0.150'
        reglas = reglas_rsw1(r2ctl, pol, topo, [sesion('u', rol, mac, ip)])
        for g, n, dst, pr, pt in r2ctl.targets(pol, topo):
            errores += llega_a_core1(simular(reglas, ipv4(mac, ip, dst, pr, pt))[0], topo, rol, r2ctl) \
                != r2ctl.allowed(pol, rol, dst, pr, pt)
    assert errores == 0


def test_2_3_1_R2_registro_de_accesos_permitidos_y_denegados(idn):
    """Logs de acceso a recursos: los accesos permitidos y los denegados se registran
    con usuario, rol, MAC y destino (las firmas las genera r2ctl ids-reglas)."""
    aprobar(idn, 'alu01', 200)
    idn.on_dhcp('add', MAC, '10.20.0.105')
    base = {'src_ip': '10.20.0.105', 'src_mac': MAC, 'dest_port': 443, 'proto': 'TCP'}
    idn.on_alert({**base, 'sid': 2502010, 'dest_ip': '10.100.1.10', 'firma': 'G05 R2 acceso permitido: alumno -> G10 portal'})
    idn.on_alert({**base, 'sid': 2002004, 'dest_ip': '10.100.0.50', 'firma': 'G05 R2 intento denegado: alumno -> G04 matricula'})
    ev = {e['ev']: e for e in eventos(idn)}
    assert ev['ACCESO_PERMITIDO']['recurso'] == 'alumno -> G10 portal' and ev['ACCESO_PERMITIDO']['usuario'] == 'alu01'
    assert ev['INTENTO_DENEGADO']['recurso'] == 'alumno -> G04 matricula'
    assert idn.blocks == {}                                  # registrar no es bloquear


# ============================================================ Módulo 3 · R3
def test_3_1_3_R3_03_solo_el_paquete_con_ip_ajena_es_spoofing(r2ctl, politica):
    """Mismo puerto y MAC: el paquete con la IP registrada pasa; el de IP ajena se
    descarta y cuenta en la regla del sensor de spoofing (alerta de identity)."""
    pol, topo = politica
    mac, ip = '02:05:00:00:00:aa', '10.20.0.150'
    reglas = reglas_rsw1(r2ctl, pol, topo, [sesion('alu', ALUMNO, mac, ip)])
    sal, traza = simular(reglas, ipv4(mac, ip, '10.100.1.10', 'tcp', 443))
    assert llega_a_core1(sal, topo, ALUMNO, r2ctl) and not any('R3 spoofing detectado' in t for t in traza)
    sal, traza = simular(reglas, ipv4(mac, '10.20.0.99', '10.100.1.10', 'tcp', 443))
    assert sal == [] and any('R3 spoofing detectado' in t for t in traza)


def test_3_1_3_R3_03_el_sensor_alerta_al_superar_el_umbral(idn, monkeypatch):
    """identity convierte el contador de la regla de spoofing en bloqueo: bajo el umbral
    (SPOOF_THRESHOLD - 1 paquetes en una lectura) no hace nada; al superarlo, bloquea."""
    aprobar(idn, 'alu01', 200)
    idn.on_dhcp('add', MAC, '10.20.0.105')
    idn.spoof_prev.clear()
    th = idn.SPOOF_THRESHOLD
    vistos = []

    def flows(n):
        return 200, {'flows': [{'id': 'f1', 'tableId': '1', 'priority': 45000, 'packets': n,
                                'selector': {'criteria': [{'type': 'ETH_SRC', 'mac': MAC.upper()}]}}]}
    lecturas = iter([flows(0), flows(th - 1), flows(th - 1 + th)])

    def onos(*a, **k):
        vistos.append(dict(idn.blocks))
        try:
            return next(lecturas)
        except StopIteration:
            raise KeyboardInterrupt                         # fin del bucle de vigilancia
    monkeypatch.setattr(idn.r2ctl, 'onos', onos)
    with pytest.raises(KeyboardInterrupt):
        idn.watch_spoofing()
    assert vistos[2] == {}                                  # th - 1 paquetes: sin bloqueo
    assert MAC in idn.blocks                                # th paquetes más: bloqueo
    assert any(e['ev'] == 'BLOQUEO' and e['fuente'] == 'switch' for e in eventos(idn))


def test_3_2_1_R3_05_regla_de_bloqueo_solo_para_el_atacante(r2ctl, politica):
    pol, topo = politica
    atk, otro = '02:05:00:00:00:aa', '02:05:00:00:00:bb'
    s = [sesion('atk', ALUMNO, atk, '10.20.0.150', bloqueado=True, motivo_bloqueo='sid 1000001'),
         sesion('otro', ALUMNO, otro, '10.20.0.151')]
    reglas = reglas_rsw1(r2ctl, pol, topo, s)
    t2 = [r for r in reglas if r['tableId'] == 2 and r['priority'] == 40000]
    assert len(t2) == 1 and t2[0]['treatment']['instructions'] == []           # descarte
    crit = t2[0]['selector']['criteria']
    assert {'type': 'ETH_SRC', 'mac': atk.upper()} in crit and len(crit) == 2  # sin comodines
    assert simular(reglas, ipv4(atk, '10.20.0.150', '10.100.1.10', 'tcp', 443))[0] == []
    assert llega_a_core1(simular(reglas, ipv4(otro, '10.20.0.151', '10.100.1.10', 'tcp', 443))[0], topo, ALUMNO, r2ctl)


def test_3_2_2_R3_05_el_bloqueo_expira_y_la_regla_se_retira(idn):
    aprobar(idn, 'alu01', 200)
    idn.on_dhcp('add', MAC, '10.20.0.105')
    idn.do_block(MAC, 'sid 1000001 prueba', ttl=300)
    t0 = idn.blocks[MAC]['desde']
    idn.vencer(t0 + 299)
    assert MAC in idn.blocks
    idn.vencer(t0 + 301)
    assert MAC not in idn.blocks
    venc = [e for e in eventos(idn) if e['ev'] == 'BLOQUEO_VENCIDO'][0]
    assert venc['accion'] == 'REGLA_T2_RETIRADA' and venc['duracion_s'] >= 300


def test_3_3_1_R3_06_incidente_con_fecha_tipo_origen_destino_y_accion(idn):
    aprobar(idn, 'alu01', 200)
    idn.on_dhcp('add', MAC, '10.20.0.105')
    idn.on_alert({'sid': 1000001, 'firma': 'G05 R3 escaneo de puertos (SYN a puertos no ofrecidos)',
                  'src_ip': '10.20.0.105', 'src_mac': MAC, 'dest_ip': '10.100.1.150', 'dest_port': 1011,
                  'proto': 'TCP', 'ts': time.time(), 'retardo_agente_ms': 40})
    alerta = [e for e in eventos(idn) if e['ev'] == 'ALERTA_IDS'][0]
    bloq = [e for e in eventos(idn) if e['ev'] == 'BLOQUEO'][0]
    for e in (alerta, bloq):
        assert e['fecha'][:4].isdigit() and 'T' in e['fecha']              # ISO-8601
    assert 'escaneo de puertos' in alerta['firma'] and alerta['src_ip'] == '10.20.0.105'
    assert alerta['dst'] == '10.100.1.150:1011/TCP' and alerta['usuario'] == 'alu01'
    assert bloq['accion'] == 'REGLA_T2_DROP' and bloq['dst'] == alerta['dst'] and bloq['ttl'] == 300
    json.dumps(bloq)                                                         # serializable
