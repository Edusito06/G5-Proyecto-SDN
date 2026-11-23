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

STATE = os.getenv('R2_SESSIONS', '/var/lib/r2/sessions.json')
RADIUS_IP = os.getenv('RADIUS_IP', '192.168.0.19')      # FreeRADIUS (red de gestión)
KEA_IP = os.getenv('KEA_IP', '192.168.0.20')            # Kea (red de gestión)
ONOS_IPS = set(os.getenv('ONOS_IPS', '192.168.0.16 192.168.0.17').split())  # agentes AAA
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
dirty = threading.Event()
busy = threading.Event()


def log(ev, **kw):
    kw = {'t': time.strftime('%H:%M:%S'), 'ev': ev, **kw}
    print(json.dumps(kw, ensure_ascii=False), flush=True)


def skey(sw, port, mac):
    return f'{sw}/{port}/{mac.lower()}'


def subred(rol):
    return ipaddress.ip_network(f'10.{int(rol) * 10}.0.0/24')


# ---------------------------------------------------------------- estado
def save():
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + '.tmp'
    json.dump(list(sessions.values()), open(tmp, 'w'))
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
            t0 = time.time()
            add, rem, _ = r2ctl.reconcile(pol, topo, snap)
            log('REGLAS', agregadas=add, retiradas=rem, ms=int((time.time() - t0) * 1000))
        except Exception as e:                       # noqa: BLE001
            log('ERROR_REGLAS', error=str(e)[:200])
            time.sleep(3)
            dirty.set()
        finally:
            busy.clear()


def expiry():
    while True:
        time.sleep(5)
        now = time.time()
        with lock:
            for k, s in list(sessions.items()):
                if s['expira'] < now:
                    finalize(k, 'REAUTENTICACION_VENCIDA')
            for m, q in list(quarantine.items()):
                if q['expira'] < now:
                    quarantine.pop(m)
                    log('CUARENTENA_VENCIDA', mac=m)


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
        if ip in ONOS_IPS and res == 'aaa' and method == 'POST':
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
        if res == 'aaa' and method == 'POST':
            on_aaa_event(b)
            return self.reply(200)
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
    for fn in (worker, expiry, watch_logoff, sync_with_aaa):
        threading.Thread(target=fn, daemon=True).start()
    push()
    ThreadingHTTPServer(('0.0.0.0', 5001), H).serve_forever()


if __name__ == '__main__':
    main()
