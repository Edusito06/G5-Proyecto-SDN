#!/usr/bin/env python3
"""identity (M1 de G05): une autenticación 802.1X, rol y dirección IP.

Versión para el slice final (clúster ONOS, varios usuarios por puerto, Kea):

  * ONOS AAA   -> eventos del log (STARTED, APPROVED, DENIED, IDLE...) que envía
                  aaa-agent.py desde cada nodo ONOS (solo el master del switch los
                  escribe), más la REST /onos/aaa/app/users para saber qué MAC y
                  usuario quedaron autorizados en el puerto. La REST no refleja el
                  EAPOL-Logoff: se detecta con IDLE + el contador EAPOL del puerto.
  * FreeRADIUS -> POST /identity/sessions con el usuario y la VLAN (= rol x 100).
                  RADIUS no recibe la MAC: se une por nombre de usuario con AAA.
  * Kea        -> POST /identity/dhcp (hook run_script) con la MAC y la IP.

Cada sesión se identifica por switch/puerto/MAC. Sin IP solo se abre la ventana
DHCP de su rol; con IP se instalan el anti-spoofing (T1) y la identidad (T3), y
r2ctl reconcilia las reglas en ONOS.

API REST (puerto 5001):
  POST   /identity/sessions            FreeRADIUS (usuario, vlan)
  GET    /identity/sessions            lista de vinculaciones
  DELETE /identity/sessions/<mac>      fin de sesión
  POST   /identity/dhcp                Kea (ev, mac, ip)
  POST   /identity/aaa                 aaa-agent de cada nodo ONOS (ev, dev, port, mac)
  POST   /identity/alert               R3: alerta de Suricata (src_ip, src_mac, firma, sid, ts)
  POST   /identity/block/<mac>         R3: bloqueo manual (motivo, ttl); DELETE lo levanta
  GET    /identity/blocks              R3: bloqueos vigentes
  GET    /identity/quarantine/<mac>    200 si está en cuarentena, 404 si no
  POST   /identity/quarantine/<mac>    pone en cuarentena (motivo, ttl)
  DELETE /identity/quarantine/<mac>    levanta la cuarentena (fuerza re-login)
  POST   /identity/guest/<mac>         invitado (sin 802.1X, simula el portal cautivo)
  GET    /identity/sync                ¿quedan reglas pendientes de instalar?
"""
import ipaddress
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

os.environ['R2_LOCAL'] = '1'
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import r2ctl  # noqa: E402
import ddos  # noqa: E402

STATE = os.getenv('R2_SESSIONS', '/var/lib/r2/sessions.json')
RADIUS_IP = os.getenv('RADIUS_IP', '192.168.0.19')      # FreeRADIUS (red de gestión)
KEA_IP = os.getenv('KEA_IP', '192.168.0.20')            # Kea (red de gestión)
ONOS_IPS = set(os.getenv('ONOS_IPS', '192.168.0.16 192.168.0.17').split())  # agentes AAA
IDS_IP = os.getenv('IDS_IP', '192.168.0.22')            # Suricata (agente de alertas, R3)
BLOCK_TTL = int(os.getenv('BLOCK_TTL', '300'))           # s de bloqueo por alerta
QUARANTINE_AFTER = 3                                     # alertas en 10 min -> cuarentena
SPOOF_THRESHOLD = 3                                      # paquetes con IP ajena en SPOOF_VENTANA s
SPOOF_VENTANA = 10       # s: cubre dos lecturas de ONOS (cada 5 s), así 3 paquetes en 3 s cuentan juntos
SESSION_TTL = 3600           # = Session-Timeout de FreeRADIUS
JOIN_WINDOW = 30             # s para unir la respuesta de RADIUS con AAA
AAA_REST = 'http://127.0.0.1:8181/onos/aaa/app/users'

pol, topo = r2ctl.load()
DEV2SW = {i['dpid']: sw for sw, i in topo['switches'].items()}
PHYS = {u['mac'].lower(): (u['switch'], u['puerto']) for u in topo['usuarios'].values()}
lock = threading.RLock()
sessions = {}                # "sw/puerto/mac" -> vinculación
quarantine = {}              # mac -> {motivo, expira}
radius_q = []                # [(ts, usuario, vlan)] sin unir
blocks = {}                  # mac -> {motivo, expira, desde} (R3: tabla 2)
alert_hist = {}              # mac -> [ts de alertas] (reincidencia)
mitigacion_pendiente = {}    # mac -> ts del bloqueo aún no aplicado en el switch
dirty = threading.Event()
busy = threading.Event()


# Registro de seguridad (R1 y R3): los eventos de seguridad se guardan además, con fecha
# completa, en un JSONL persistente que consulta GET /identity/incidents.
INCIDENTES = os.environ.get('G05_INCIDENTES', '/var/log/g05/incidentes.jsonl')
EV_INCIDENTE = {'ALERTA_IDS', 'ALERTA_SIN_ORIGEN', 'BLOQUEO', 'BLOQUEO_RENOVADO',
                'MITIGACION_APLICADA', 'BLOQUEO_LEVANTADO', 'BLOQUEO_VENCIDO',
                'CUARENTENA', 'CUARENTENA_VENCIDA', 'CUARENTENA_LEVANTADA',
                # R1: intentos fallidos (802.1X rechazado, DHCP o acceso sin sesión)
                'SESION_RECHAZADA', 'ACCESO_DENEGADO', 'DHCP_SIN_SESION',
                # R2: accesos a recursos, permitidos y denegados por la política del rol
                'INTENTO_DENEGADO', 'ACCESO_PERMITIDO',
                # R1: cuentas bloqueadas por intentos fallidos (FreeRADIUS + LDAP)
                'CUENTA_BLOQUEADA', 'CUENTA_DESBLOQUEADA', 'INTENTO_FALLIDO',
                # R4: fuentes de DDoS limitadas con meter
                'DDOS_DETECTADO', 'LIMITE_LEVANTADO'}
inc_lock = threading.Lock()


def log(ev, **kw):
    kw = {'t': time.strftime('%H:%M:%S'), 'ev': ev, **kw}
    print(json.dumps(kw, ensure_ascii=False), flush=True)
    if ev in EV_INCIDENTE:
        reg = {'fecha': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'ts': round(time.time(), 3), **kw}
        try:
            with inc_lock:
                os.makedirs(os.path.dirname(INCIDENTES), exist_ok=True)
                with open(INCIDENTES, 'a') as fh:
                    fh.write(json.dumps(reg, ensure_ascii=False) + '\n')
        except OSError:
            pass


def leer_incidentes(desde=0.0):
    try:
        with open(INCIDENTES) as fh:
            regs = [json.loads(x) for x in fh if x.strip()]
    except OSError:
        return []
    return [r for r in regs if r.get('ts', 0) >= desde]


def skey(sw, port, mac):
    return f'{sw}/{port}/{mac.lower()}'


def subred(rol):
    return ipaddress.ip_network(f'10.{int(rol) * 10}.0.0/24')


# ---------------------------------------------------------------- estado
def save():
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + '.tmp'
    # El archivo se cierra (y se vuelca al disco) antes del os.replace: con
    # json.dump(..., open(...)) Python 3.12 renombraba el archivo todavía vacío.
    with open(tmp, 'w') as f:
        json.dump(list(sessions.values()), f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, STATE)


def push():
    """Guarda y pide que el worker reconcilie las reglas de ONOS."""
    save()
    dirty.set()


def worker():
    while True:
        dirty.wait()
        dirty.clear()
        busy.set()
        try:
            with lock:
                snap = [dict(s) for s in sessions.values()]
                for x in snap:
                    b = blocks.get(x['mac'])
                    if b and b['expira'] > time.time():
                        x['bloqueado'], x['motivo_bloqueo'] = True, b['motivo']
                    lim = limits.get(x['mac'])
                    if lim and lim.get('meter'):
                        x['limite_meter'] = lim['meter']
                pend = dict(mitigacion_pendiente)
                mitigacion_pendiente.clear()
            t0 = time.time()
            add, rem, _ = r2ctl.reconcile(pol, topo, snap)
            log('REGLAS', agregadas=add, retiradas=rem, ms=int((time.time() - t0) * 1000))
            for m, tb in pend.items():                # bloqueo -> regla T2 aceptada por ONOS
                log('MITIGACION_APLICADA', mac=m, ms=int((time.time() - tb) * 1000))
        except Exception as e:                       # noqa: BLE001
            log('ERROR_REGLAS', error=str(e)[:200])
            time.sleep(3)
            dirty.set()
        finally:
            busy.clear()


def vencer(now):
    """Retira lo que expiró: sesiones (reautenticación), cuarentenas y bloqueos de R3."""
    with lock:
        for k, s in list(sessions.items()):
            if s['expira'] < now:
                finalize(k, 'REAUTENTICACION_VENCIDA')
        for m, q in list(quarantine.items()):
            if q['expira'] < now:
                quarantine.pop(m)
                log('CUARENTENA_VENCIDA', mac=m)
        for m, b in list(blocks.items()):
            if b['expira'] < now:
                blocks.pop(m)
                log('BLOQUEO_VENCIDO', mac=m, motivo=b['motivo'], accion='REGLA_T2_RETIRADA',
                    duracion_s=round(now - b['desde'], 1))
                push()


def expiry():
    while True:
        time.sleep(5)
        vencer(time.time())


def finalize(key, causa):
    s = sessions.pop(key, None)
    if s:
        log('SESION_FINALIZADA', usuario=s['usuario'], mac=s['mac'], puerto=key, causa=causa)
        push()


# --------------------------------------------------------------- eventos AAA
def aaa_users():
    r = subprocess.run(['curl', '-sn', '-m', '5', AAA_REST], capture_output=True, text=True)
    try:
        return json.loads(r.stdout).get('entries', [])
    except ValueError:
        return None


def take_radius(usuario):
    """Toma la respuesta de FreeRADIUS más reciente de ese usuario (unión exacta)."""
    with lock:
        fresh = [r for r in radius_q if time.time() - r[0] < JOIN_WINDOW]
        radius_q[:] = fresh
        for i in range(len(fresh) - 1, -1, -1):
            if fresh[i][1] == usuario:
                return fresh.pop(i)
    return None


def on_approved(dev, port, mac, usuario):
    sw = DEV2SW.get(dev)
    if not sw:
        log('SESION_RECHAZADA', motivo='switch sin política R2', dispositivo=dev, puerto=port)
        return
    rad = None
    for _ in range(15):                  # el POST de RADIUS suele llegar antes
        rad = take_radius(usuario)
        if rad:
            break
        time.sleep(0.2)
    if not rad:
        log('SESION_RECHAZADA', motivo='sin respuesta de RADIUS para el usuario',
            usuario=usuario, mac=mac)
        return
    t_radius, _, vlan = rad
    rol = int(vlan) // 100
    if rol not in pol['roles']:
        log('SESION_RECHAZADA', motivo=f'rol {rol} inexistente', usuario=usuario)
        return
    key = skey(sw, port, mac)
    with lock:
        s = {'nombre': usuario, 'usuario': usuario, 'mac': mac, 'switch': sw,
             'puerto': int(port), 'ip': None, 'rol': rol, 'estado': 'SIN_IP',
             'inicio': time.time(), 'expira': time.time() + SESSION_TTL}
        q = quarantine.get(mac)
        if q and q['expira'] > time.time():
            s['rol_orig'], s['rol'], s['estado'] = rol, 9, 'CUARENTENA'
        old = sessions.get(key)
        if old and old.get('ip') and old['rol'] == s['rol']:
            s['ip'], s['estado'] = old['ip'], old['estado']       # reautenticación
        for k, o in list(sessions.items()):                       # el host se movió
            if o['mac'] == mac and k != key:
                sessions.pop(k)
        sessions[key] = s
        push()
    log('SESION_AUTORIZADA', usuario=usuario, mac=mac, puerto=key, rol=s['rol'],
        desde_radius_ms=int((time.time() - t_radius) * 1000))


started = {}                 # (dev, puerto) -> ts del último STARTED
last_event = {}              # (dev, puerto) -> ts del último evento AAA del puerto
idle_times = []              # ts de "AUTHORIZED -> IDLE" (logoff; AAA no dice el puerto)
eapol_prev = {}              # (dev, puerto) -> paquetes EAPOL vistos (regla T0 por puerto)


def on_port_approved(dev, port):
    """APPROVED (del log del nodo master): busca en la REST quién quedó autorizado."""
    cp = f'{dev}/{port}'
    for _ in range(25):
        entries = aaa_users() or []
        cand = [e for e in entries if e['connectPoint'] == cp and e['authState'] == 'AUTHORIZED_STATE']
        with lock:
            pendientes = {r[1] for r in radius_q if time.time() - r[0] < JOIN_WINDOW}
        # Con varios registros en el puerto, el recién aprobado es el que tiene RADIUS pendiente.
        e = next((x for x in cand if x['username'] in pendientes), None)
        if e:
            on_approved(dev, port, e['macAddress'].lower(), e['username'])
            return
        time.sleep(0.2)
    log('SESION_RECHAZADA', motivo='AAA no lista un supplicant autorizado con RADIUS pendiente', puerto=cp)


def on_aaa_event(b):
    ev, dev, port = b.get('ev'), b.get('dev'), b.get('port')
    now = time.time()
    if ev == 'IDLE':
        idle_times.append(now)
        return
    if not dev or not port:
        return
    last_event[(dev, port)] = now
    if ev == 'STARTED':
        started[(dev, port)] = now
    elif ev == 'APPROVED':
        threading.Thread(target=on_port_approved, args=(dev, port), daemon=True).start()
    elif ev in ('FAILURE', 'DENIED', 'UNAUTHORIZED', 'TIMEOUT'):
        sw = DEV2SW.get(dev)
        mac = b.get('mac')
        if mac is None:
            # DENIED/TIMEOUT no traen la MAC y el puerto puede tener otros usuarios:
            # el rechazo se aplica con el FAILURE (que sí la trae) o con sync_with_aaa.
            return
        with lock:
            for k, s in list(sessions.items()):
                if s['switch'] == sw and str(s['puerto']) == str(port) and s['usuario'] != 'invitado' \
                        and (mac is None or s['mac'] == mac):
                    finalize(k, f'AAA_{ev}')
        if mac or ev != 'DENIED':
            log('ACCESO_DENEGADO', dispositivo=dev, puerto=port, causa=ev, mac=mac)


def watch_logoff():
    """EAPOL-Logoff: AAA pasa a IDLE sin decir el puerto. Se busca el puerto de usuario
    cuyo contador EAPOL subió sin ningún evento de AAA (un supplicant por puerto)."""
    t_prev = time.time()
    while True:
        time.sleep(2)
        try:
            code, data = r2ctl.onos('GET', f'/flows/application/{r2ctl.APP}')
            if code != 200:
                continue
            now = time.time()
            for f in data.get('flows', []):
                if int(f['tableId']) != 0 or f['priority'] != 65100:
                    continue
                port = next((str(c['port']) for c in f['selector']['criteria']
                             if c['type'] == 'IN_PORT'), None)
                key = (f['deviceId'], port)
                prev = eapol_prev.get(key)
                eapol_prev[key] = f.get('packets', 0)
                if prev is None or f.get('packets', 0) <= prev:
                    continue
                # Logoff = IDLE posterior al último evento de autenticación del puerto.
                ultimo = last_event.get(key, 0)
                if not any(max(ultimo, now - 20) < t <= now + 1 for t in idle_times):
                    continue
                sw = DEV2SW.get(f['deviceId'])
                with lock:
                    for k, s in list(sessions.items()):
                        if s['switch'] == sw and str(s['puerto']) == port and s['usuario'] != 'invitado':
                            finalize(k, 'EAPOL_LOGOFF')
                    idle_times.clear()
            t_prev = now
        except Exception as e:                           # noqa: BLE001
            log('ERROR_LOGOFF', error=str(e)[:160])


def sync_with_aaa():
    """Red de seguridad: si AAA ya no tiene el (puerto, MAC) como autorizado
    (otro supplicant tomó el puerto, limpieza de AAA), la sesión se cierra."""
    while True:
        time.sleep(5)
        entries = aaa_users()
        if entries is None:
            continue
        ok = {(x['connectPoint'], x['macAddress'].lower()) for x in entries
              if x['authState'] == 'AUTHORIZED_STATE'}
        with lock:
            for k, s in list(sessions.items()):
                if s['usuario'] == 'invitado' or time.time() - s['inicio'] < 10:
                    continue
                dev = next((d for d, n in DEV2SW.items() if n == s['switch']), None)
                if (f'{dev}/{s["puerto"]}', s['mac']) not in ok:
                    finalize(k, 'AAA_SIN_REGISTRO')


# ------------------------------------------------------------------- DHCP
def on_dhcp(ev, mac, ip):
    mac = mac.lower()
    with lock:
        key = next((k for k, s in sessions.items() if s['mac'] == mac), None)
        if not key:
            log('DHCP_SIN_SESION', mac=mac, ip=ip)
            return False
        s = sessions[key]
        if ev == 'del':                                   # fin de concesión
            s['ip'] = None
            s['estado'] = 'CUARENTENA' if s['rol'] == 9 else 'SIN_IP'
            log('CONCESION_VENCIDA', mac=mac, usuario=s['usuario'])
            push()
            return True
        if ipaddress.ip_address(ip) not in subred(s['rol']):
            log('DHCP_FUERA_DE_RANGO', mac=mac, ip=ip, rol=s['rol'])
            return False
        s['ip'] = ip
        s['estado'] = 'CUARENTENA' if s['rol'] == 9 else 'VINCULADO'
        push()
    log('VINCULADO', usuario=s['usuario'], mac=mac, ip=ip, puerto=key, rol=s['rol'],
        desde_autorizacion_ms=int((time.time() - s['inicio']) * 1000))
    return True


# -------------------------------------------------- cuarentena e invitado
def do_quarantine(mac, motivo, ttl):
    mac = mac.lower()
    with lock:
        quarantine[mac] = {'motivo': motivo, 'expira': time.time() + int(ttl)}
        for s in sessions.values():
            if s['mac'] == mac and s['rol'] != 9:
                s['rol_orig'], s['rol'] = s['rol'], 9
                s['estado'] = 'CUARENTENA'
                s['ip'] = None                     # su IP era de otra subred: nuevo DHCP
        push()
    log('CUARENTENA', mac=mac, motivo=motivo, ttl=ttl)


def lift_quarantine(mac):
    mac = mac.lower()
    with lock:
        quarantine.pop(mac, None)
        for k, s in list(sessions.items()):
            if s['mac'] == mac and s['rol'] == 9:
                finalize(k, 'CUARENTENA_LEVANTADA')      # fuerza nueva autenticación
    log('CUARENTENA_LEVANTADA', mac=mac)


def do_guest(mac):
    mac = mac.lower()
    if mac not in PHYS:
        return False
    sw, port = PHYS[mac]
    with lock:
        sessions[skey(sw, port, mac)] = {
            'nombre': 'invitado-' + mac[-2:], 'usuario': 'invitado', 'mac': mac, 'switch': sw,
            'puerto': port, 'ip': None, 'rol': 1, 'estado': 'SIN_IP',
            'inicio': time.time(), 'expira': time.time() + SESSION_TTL}
        push()
    log('INVITADO', mac=mac, puerto=f'{sw}/{port}')
    return True


# --------------------------------------------------------------------- R3
def session_of(mac=None, ip=None):
    with lock:
        for s in sessions.values():
            if (mac and s['mac'] == mac.lower()) or (ip and s.get('ip') == ip):
                return s
    return None


def do_block(mac, motivo, ttl=BLOCK_TTL, t_alerta=None, fuente='ids', extra=None, dst=None):
    """Bloquea en T2 (descartar todo lo que envía esa MAC) y, si reincide, cuarentena."""
    mac = mac.lower()
    now = time.time()
    with lock:
        nuevo = mac not in blocks or blocks[mac]['expira'] < now
        blocks[mac] = {'motivo': motivo, 'expira': now + int(ttl), 'desde': now}
        hist = [t for t in alert_hist.get(mac, []) if now - t < 600] + [now]
        alert_hist[mac] = hist
        if nuevo:
            mitigacion_pendiente[mac] = now
        push()
    s = session_of(mac=mac)
    log('BLOQUEO' if nuevo else 'BLOQUEO_RENOVADO', mac=mac, usuario=s['usuario'] if s else None,
        src_ip=s.get('ip') if s else None, dst=dst, motivo=motivo, fuente=fuente,
        accion='REGLA_T2_DROP', prioridad=40000, ttl=ttl, **(extra or {}))
    if len(hist) >= QUARANTINE_AFTER and not quarantine.get(mac):
        do_quarantine(mac, f'reincidencia R3: {motivo}', 600)


intentos = {}                # (usuario, destino) -> {n, primero, ultimo} (R2)


def on_intento(b, s):
    """Trazabilidad de R2: el switch ya descartó el intento; aquí solo se registra quién
    (usuario 802.1X, rol, MAC) intentó llegar a qué recurso."""
    usuario = s['usuario'] if s else None
    destino = (b.get('firma') or '').split('intento denegado: ', 1)[-1]
    k = (usuario or b.get('src_ip'), destino)
    now = time.time()
    with lock:
        c = intentos.setdefault(k, {'n': 0, 'primero': now})
        c['n'] += 1
        c['ultimo'] = now
    log('INTENTO_DENEGADO', usuario=usuario, rol=s['rol'] if s else None,
        mac=s['mac'] if s else b.get('src_mac'), src_ip=b.get('src_ip'),
        dst=f"{b.get('dest_ip')}:{b.get('dest_port') or '-'}/{b.get('proto') or '-'}",
        recurso=destino, sid=b.get('sid'))
    return True


accesos = {}                 # (usuario, recurso) -> {n, primero, ultimo} (R2: permitidos)


def on_acceso(b, s):
    """Registro de accesos a recursos (R2): accesos que la política permite."""
    usuario = s['usuario'] if s else None
    recurso = (b.get('firma') or '').split('acceso permitido: ', 1)[-1]
    now = time.time()
    with lock:
        c = accesos.setdefault((usuario or b.get('src_ip'), recurso), {'n': 0, 'primero': now})
        c['n'] += 1
        c['ultimo'] = now
    log('ACCESO_PERMITIDO', usuario=usuario, rol=s['rol'] if s else None,
        mac=s['mac'] if s else b.get('src_mac'), src_ip=b.get('src_ip'),
        dst=f"{b.get('dest_ip')}:{b.get('dest_port') or '-'}/{b.get('proto') or '-'}",
        recurso=recurso, sid=b.get('sid'))
    return True


def on_alert(b):
    """Alerta de Suricata (agente del IDS): identifica al atacante y lo bloquea.
    Las firmas de R2 (sid 2000000-2999999) no bloquean: solo registran el acceso."""
    sid = int(b.get('sid') or 0)
    if 2500000 <= sid < 3000000:
        return on_acceso(b, session_of(mac=b.get('src_mac')) or session_of(ip=b.get('src_ip')))
    if 2000000 <= sid < 2500000:
        return on_intento(b, session_of(mac=b.get('src_mac')) or session_of(ip=b.get('src_ip')))
    s = session_of(mac=b.get('src_mac')) or session_of(ip=b.get('src_ip'))
    mac = (s['mac'] if s else b.get('src_mac') or '').lower()
    if not mac:
        log('ALERTA_SIN_ORIGEN', firma=b.get('firma'), src_ip=b.get('src_ip'))
        return False
    dst = f"{b.get('dest_ip')}:{b.get('dest_port') or '-'}/{b.get('proto') or '-'}"
    log('ALERTA_IDS', firma=b.get('firma'), sid=b.get('sid'), src_ip=b.get('src_ip'),
        dst=dst, mac=mac, usuario=s['usuario'] if s else None)
    # Los relojes de las VMs no están sincronizados: el retardo del agente lo mide el IDS
    # con su reloj; el resto (recepción -> reglas) lo mide identity con el suyo (REGLAS ms).
    do_block(mac, f"sid {b.get('sid')} {b.get('firma', '')}"[:80], dst=dst,
             extra={'retardo_agente_ms': b.get('retardo_agente_ms'), 'ts_alerta_ids': b.get('ts')})
    return True


# --------------------------------------------------------------------- R4
DDOS_POLL = float(os.getenv('DDOS_POLL', '2.5'))      # s (ONOS lee contadores cada 5 s)
LIMIT_KBPS = int(os.getenv('DDOS_LIMIT_KBPS', '2000'))  # kbit/s por fuente (OVS: kbps)
limits = {}                  # mac -> {meter, dev, desde, motivo} (R4: tabla 2 con meter)
detector = ddos.Detector()
PREF2G = {rec['prefijo']: g for g, rec in pol['recursos'].items()}


def crear_meter(dev):
    """Meter propio de la fuente: descarta lo que supere LIMIT_KBPS. Devuelve su id."""
    antes = {r2ctl._mid(m) for m in r2ctl.list_meters(dev)}
    code, _ = r2ctl.onos('POST', f'/meters/{dev}', {
        'deviceId': dev, 'appId': r2ctl.APP, 'unit': 'KB_PER_SEC', 'burst': True,
        'bands': [{'type': 'DROP', 'rate': LIMIT_KBPS, 'burstSize': LIMIT_KBPS}]})
    if code not in (200, 201):
        return None
    for _ in range(20):
        nuevos = [r2ctl._mid(m) for m in r2ctl.list_meters(dev)
                  if r2ctl._mid(m) not in antes and m.get('unit') == 'KB_PER_SEC']
        if nuevos:
            return min(nuevos)
        time.sleep(0.1)
    return None


def do_limit(mac, det, fuente='monitor'):
    mac = mac.lower()
    s = session_of(mac=mac)
    if not s or mac in limits:
        return False
    dev = topo['switches'][s['switch']]['dpid']
    meter = crear_meter(dev)
    if meter is None:
        log('ERROR_LIMITE', mac=mac, error='ONOS no creó el meter')
        return False
    now = time.time()
    with lock:
        limits[mac] = {'meter': meter, 'dev': dev, 'desde': now, 'motivo': det.get('motivo')}
        mitigacion_pendiente[mac] = now
        push()
    log('DDOS_DETECTADO', usuario=s['usuario'], rol=s['rol'], mac=mac, ip=s.get('ip'),
        fuente=fuente, limite_kbps=LIMIT_KBPS, meter=meter, **det)
    return True


def lift_limit(mac, det=None):
    mac = mac.lower()
    with lock:
        lim = limits.pop(mac, None)
        if not lim:
            return False
        push()
    for _ in range(50):                      # primero se retira la regla, luego el meter
        time.sleep(0.1)
        if not dirty.is_set() and not busy.is_set():
            break
    r2ctl.onos('DELETE', f'/meters/{lim["dev"]}/{lim["meter"]}')
    log('LIMITE_LEVANTADO', mac=mac, duracion_s=round(time.time() - lim['desde'], 1), **(det or {}))
    return True


def leer_contadores(flows):
    usuarios, ofrecido, recursos, entrada = {}, {}, {}, {}
    for f in flows:
        t = f.get('lastSeen', 0) / 1000
        crit = {c['type']: c for c in f['selector']['criteria']}
        tb, pr = int(f['tableId']), f['priority']
        mac = crit.get('ETH_SRC', {}).get('mac', '').lower()
        if tb == 3 and pr == 35000 and mac:
            usuarios[mac] = (f['bytes'], f['packets'], t)
        elif tb == 2 and pr == 39000 and mac:
            ofrecido[mac] = (f['bytes'], f['packets'], t)
        elif tb == 5 and pr == 10100 and 'ETH_DST' in crit:     # entrega al usuario
            m = crit['ETH_DST']['mac'].lower()
            b, pk, tt = entrada.get(m, (0, 0, 0))
            entrada[m] = (b + f['bytes'], pk + f['packets'], max(tt, t))
        elif tb == 4 and pr == 25000 and 'IPV4_DST' in crit:
            g = PREF2G.get(crit['IPV4_DST']['ip'])
            if g:
                b, pk, tt = recursos.get(g, (0, 0, 0))
                recursos[g] = (b + f['bytes'], pk + f['packets'], max(tt, t))
    return usuarios, ofrecido, recursos, entrada


def watch_ddos():
    """R4: consumo por usuario (T3) y por recurso (T4) desde los contadores de ONOS."""
    while True:
        time.sleep(DDOS_POLL)
        try:
            code, data = r2ctl.onos('GET', f'/flows/application/{r2ctl.APP}')
            if code != 200:
                continue
            usuarios, ofrecido, recursos, entrada = leer_contadores(data.get('flows', []))
            with lock:
                lim = list(limits)
                for m in lim:                      # la sesión terminó: fuera el límite
                    if not session_of(mac=m):
                        threading.Thread(target=lift_limit, args=(m, {'causa': 'sin sesión'}),
                                         daemon=True).start()
            for acc, mac, det in detector.actualizar(usuarios, recursos, ofrecido, lim, time.time(),
                                                     entrada):
                if acc == 'limitar':
                    do_limit(mac, det)
                else:
                    lift_limit(mac, det)
        except Exception as e:                           # noqa: BLE001
            log('ERROR_DDOS', error=str(e)[:160])


spoof_prev = {}              # flow id -> [(t, paquetes)] de la regla T1 de spoofing (ventana)
spoof_gracia = {}            # mac -> hasta cuándo no se evalúa (tras levantar un bloqueo)
SPOOF_GRACIA = 8             # s: las estadísticas de ONOS llegan con hasta ~5 s de retraso


def watch_spoofing():
    """Sensor en el switch: la regla T1 'IP de origen ajena' de cada usuario cuenta los
    paquetes falsificados (que ya se descartan). Si en los últimos SPOOF_VENTANA segundos
    suma SPOOF_THRESHOLD o más, se bloquea la MAC."""
    while True:
        time.sleep(2)
        try:
            code, data = r2ctl.onos('GET', f'/flows/application/{r2ctl.APP}')
            if code != 200:
                continue
            for f in data.get('flows', []):
                if int(f['tableId']) != 1 or f['priority'] != 45000:
                    continue
                mac = next((c['mac'].lower() for c in f['selector']['criteria']
                            if c['type'] == 'ETH_SRC'), None)
                now, pk = time.time(), f.get('packets', 0)
                hist = [(t, n) for t, n in spoof_prev.get(f['id'], []) if now - t <= SPOOF_VENTANA and n <= pk]
                hist.append((now, pk))                   # n > pk: regla reinstalada, se reinicia
                spoof_prev[f['id']] = hist
                if mac and spoof_gracia.get(mac, 0) > now:
                    spoof_prev[f['id']] = [(now, pk)]    # paquetes viejos del ataque ya levantado
                    continue
                suma = pk - hist[0][1]
                if len(hist) > 1 and mac and suma >= SPOOF_THRESHOLD:
                    with lock:
                        ya = mac in blocks and blocks[mac]['expira'] > now
                    if not ya:
                        do_block(mac, f'IP spoofing ({suma} paquetes en {SPOOF_VENTANA} s)',
                                 fuente='switch')
                        spoof_prev[f['id']] = [(now, pk)]
        except Exception as e:                           # noqa: BLE001
            log('ERROR_SPOOFING', error=str(e)[:160])


# --------------------------------------------------------------------- HTTP
class H(BaseHTTPRequestHandler):
    def reply(self, code, body=None):
        data = json.dumps(body if body is not None else {}).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        n = int(self.headers.get('Content-Length') or 0)
        try:
            return json.loads(self.rfile.read(n)) if n else {}
        except ValueError:
            return {}

    def allowed(self, res, method, arg):
        ip = self.client_address[0]
        if ip == '127.0.0.1':
            return True
        if ip == RADIUS_IP and res == 'sessions' and method == 'POST' and not arg:
            return True
        if ip == RADIUS_IP and res == 'cuenta' and method == 'POST' and not arg:
            return True
        if ip in ONOS_IPS and res == 'aaa' and method == 'POST':
            return True
        if ip == IDS_IP and res == 'alert' and method == 'POST':
            return True
        return ip == KEA_IP and res == 'dhcp' and method == 'POST'

    def route(self, method):
        path = self.path.split('?')[0].rstrip('/')
        parts = path.split('/')[1:]              # ['identity', ...]
        if not parts or parts[0] != 'identity':
            return self.reply(404)
        res = parts[1] if len(parts) > 1 else ''
        arg = parts[2] if len(parts) > 2 else None
        if not self.allowed(res, method, arg):
            return self.reply(403, {'error': 'origen no permitido'})
        b = self.body() if method in ('POST', 'PUT') else {}
        if res == 'sessions' and method == 'POST':
            vlan = str(b.get('vlan', '')).strip()
            if not b.get('usuario') or not vlan.isdigit():
                return self.reply(400, {'error': 'usuario y vlan obligatorios'})
            with lock:
                radius_q.append((time.time(), b['usuario'], vlan))
            log('RADIUS_ACEPTADO', usuario=b['usuario'], vlan=vlan)
            return self.reply(200)
        if res == 'sessions' and method == 'GET':
            with lock:
                return self.reply(200, list(sessions.values()))
        if res == 'sessions' and method == 'DELETE' and arg:
            with lock:
                for k, s in list(sessions.items()):
                    if s['mac'] == arg.lower():
                        finalize(k, 'ADMIN')
            return self.reply(200)
        if res == 'cuenta' and method == 'POST':
            # R1-03: el módulo de bloqueo de ldap-radius avisa fallos y bloqueos de cuentas
            ev = {'fallo': 'INTENTO_FALLIDO', 'bloqueo': 'CUENTA_BLOQUEADA',
                  'desbloqueo': 'CUENTA_DESBLOQUEADA'}.get(b.get('ev'))
            if not ev:
                return self.reply(400, {'error': 'ev debe ser fallo, bloqueo o desbloqueo'})
            log(ev, usuario=str(b.get('usuario', ''))[:64], fallos=b.get('fallos'),
                limite=b.get('limite'), hasta=b.get('hasta'))
            return self.reply(200)
        if res == 'accesos' and method == 'GET':
            with lock:
                return self.reply(200, [{'usuario': u, 'recurso': r, **c}
                                        for (u, r), c in sorted(accesos.items())])
        if res == 'aaa' and method == 'POST':
            on_aaa_event(b)
            return self.reply(200)
        if res == 'alert' and method == 'POST':
            return self.reply(200 if on_alert(b) else 202)
        if res == 'block' and arg:
            if method == 'POST':
                do_block(arg, b.get('motivo', 'manual'), b.get('ttl', BLOCK_TTL), fuente='admin')
                return self.reply(200)
            if method == 'DELETE':
                with lock:
                    blocks.pop(arg.lower(), None)
                    alert_hist.pop(arg.lower(), None)
                    spoof_gracia[arg.lower()] = time.time() + SPOOF_GRACIA
                    push()
                log('BLOQUEO_LEVANTADO', mac=arg.lower())
                return self.reply(200)
        if res == 'trafico' and method == 'GET':
            with lock:
                return self.reply(200, {**detector.resumen(), 'limitados': dict(limits),
                                        'umbrales': {k: v for k, v in vars(detector).items()
                                                     if isinstance(v, (int, float))}})
        if res == 'limit' and arg:
            if method == 'POST':
                return self.reply(200 if do_limit(arg, {'motivo': b.get('motivo', 'manual')},
                                                  fuente='admin') else 404)
            if method == 'DELETE':
                return self.reply(200 if lift_limit(arg, {'causa': 'admin'}) else 404)
        if res == 'intentos' and method == 'GET':
            with lock:
                return self.reply(200, [{'usuario': u, 'destino': d, **c}
                                        for (u, d), c in sorted(intentos.items())])
        if res == 'incidents' and method == 'GET':
            q = dict(x.split('=', 1) for x in self.path.partition('?')[2].split('&') if '=' in x)
            return self.reply(200, leer_incidentes(float(q.get('desde', 0) or 0)))
        if res == 'blocks' and method == 'GET':
            with lock:
                return self.reply(200, {m: b for m, b in blocks.items() if b['expira'] > time.time()})
        if res == 'dhcp' and method == 'POST':
            ok = on_dhcp(b.get('ev', 'add'), b.get('mac', ''), b.get('ip', ''))
            return self.reply(200 if ok else 202)
        if res == 'quarantine' and arg:
            if method == 'GET':
                q = quarantine.get(arg.lower())
                return self.reply(200 if q and q['expira'] > time.time() else 404, q or {})
            if method == 'POST':
                do_quarantine(arg, b.get('motivo', 'manual'), b.get('ttl', 600))
                return self.reply(200)
            if method == 'DELETE':
                lift_quarantine(arg)
                return self.reply(200)
        if res == 'guest' and method == 'POST' and arg:
            return self.reply(200 if do_guest(arg) else 404)
        if res == 'sync' and method == 'GET':
            return self.reply(200, {'pendiente': dirty.is_set() or busy.is_set()})
        return self.reply(404)

    def do_GET(self): self.route('GET')
    def do_POST(self): self.route('POST')
    def do_DELETE(self): self.route('DELETE')
    def log_message(self, *a): pass


def main():
    try:
        for s in json.load(open(STATE)):                 # reinicio: se reinstala todo
            sessions[skey(s['switch'], s['puerto'], s['mac'])] = s
    except (OSError, ValueError):
        pass
    log('ARRANQUE', sesiones=len(sessions))
    for fn in (worker, expiry, watch_logoff, sync_with_aaa, watch_spoofing, watch_ddos):
        threading.Thread(target=fn, daemon=True).start()
    push()
    ThreadingHTTPServer(('0.0.0.0', 5001), H).serve_forever()


if __name__ == '__main__':
    main()
