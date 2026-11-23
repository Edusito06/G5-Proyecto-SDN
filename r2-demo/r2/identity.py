#!/usr/bin/env python3
"""identity (M1 de G05): une autenticación 802.1X, rol y dirección IP.

Une tres fuentes por caminos distintos (LLSD §4.4):
  * ONOS AAA   -> el instante de cada evento (log de ONOS) y el registro por puerto
                  (REST /onos/aaa/app/users: MAC, usuario y estado). La ruta real
                  lleva el prefijo /app, no /users como supone la documentación.
  * FreeRADIUS -> POST /identity/sessions con el usuario y la VLAN (= rol x 100).
                  RADIUS no recibe la MAC (no hay Calling-Station-Id): se une por
                  nombre de usuario con el registro de AAA.
  * dnsmasq    -> POST /identity/dhcp (dhcp-script) con la MAC y la IP concedida.

Por cada sesión mantiene la vinculación puerto-MAC-IP-rol y pide a r2ctl que
reconcilie las reglas de ONOS: sin IP solo se abre la ventana DHCP (tabla 0); con
IP se instalan el anti-spoofing (tabla 1) y la identidad (tabla 3).

API REST (puerto 5001):
  POST   /identity/sessions            FreeRADIUS (usuario, vlan)
  GET    /identity/sessions            lista de vinculaciones
  DELETE /identity/sessions/<mac>      fin de sesión
  POST   /identity/dhcp                dnsmasq (ev, mac, ip)
  GET    /identity/quarantine/<mac>    200 si está en cuarentena, 404 si no
  POST   /identity/quarantine/<mac>    pone en cuarentena (motivo, ttl)
  DELETE /identity/quarantine/<mac>    levanta la cuarentena (fuerza re-login)
  POST   /identity/guest/<mac>         invitado simulado (portal cautivo, Fase 3)
  GET    /identity/sync                ¿quedan reglas pendientes de instalar?
"""
import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

os.environ['R2_LOCAL'] = '1'
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import r2ctl  # noqa: E402

STATE = os.getenv('R2_SESSIONS', '/var/lib/r2/sessions.json')
HOSTS_FILE = '/etc/dnsmasq.d/hosts.d/r1.hosts'
RADIUS_IP = os.getenv('RADIUS_IP', '192.168.0.23')
SESSION_TTL = 3600           # = Session-Timeout de FreeRADIUS
JOIN_WINDOW = 20             # s para unir RADIUS con el evento de AAA
ANSI = re.compile(r'\x1b\[[0-9;]*m')

pol, topo = r2ctl.load()
DEV2SW = {i['dpid']: sw for sw, i in topo['switches'].items()}
PHYS = {u['mac'].lower(): (u['switch'], u['puerto']) for u in topo['usuarios'].values()}
lock = threading.RLock()
sessions = {}                # "sw2/3" -> vinculación
quarantine = {}              # mac -> {motivo, expira}
radius_q = []                # [(ts, usuario, vlan)] sin unir
started = {}                 # (dev, puerto) -> ts del evento STARTED
dirty = threading.Event()
busy = threading.Event()


def log(ev, **kw):
    kw = {'t': time.strftime('%H:%M:%S'), 'ev': ev, **kw}
    print(json.dumps(kw, ensure_ascii=False), flush=True)


def subred(rol):
    return ipaddress.ip_network(f'10.{int(rol) * 10}.0.0/24')


# ---------------------------------------------------------------- estado
def save():
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + '.tmp'
    json.dump(list(sessions.values()), open(tmp, 'w'))
    os.replace(tmp, STATE)
    os.makedirs(os.path.dirname(HOSTS_FILE), exist_ok=True)
    tmp = os.path.join(os.path.dirname(STATE), 'r1.hosts.tmp')   # fuera del directorio vigilado
    with open(tmp, 'w') as f:        # dnsmasq lee este directorio en caliente
        for s in sessions.values():
            f.write(f'{s["mac"]},set:rol{s["rol"]}\n')
    os.replace(tmp, HOSTS_FILE)


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
            log('REGLAS', agregadas=add, retiradas=rem,
                ms=int((time.time() - t0) * 1000))
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
        log('SESION_FINALIZADA', usuario=s['usuario'], mac=s['mac'], puerto=key,
            causa=causa)
        push()


# --------------------------------------------------------------- eventos AAA
AAA_REST = 'http://127.0.0.1:8181/onos/aaa/app/users'
last_event = {}              # (dev, puerto) -> ts del último evento AAA del puerto
idle_times = []              # ts de "AUTHORIZED -> IDLE" (logoff; AAA no dice qué puerto)
eapol_prev = {}              # (dev, puerto) -> paquetes EAPOL vistos


def aaa_users():
    """Registros de la app AAA: connectPoint, authState, MAC y usuario.
    La ruta real lleva el prefijo /app (la lista el WADL del servicio)."""
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


def on_approved(dev, port):
    sw = DEV2SW.get(dev)
    e = None
    for _ in range(15):                  # la REST de AAA se actualiza al instante
        entries = aaa_users() or []
        e = next((x for x in entries if x['connectPoint'] == f'{dev}/{port}'
                  and x['authState'] == 'AUTHORIZED_STATE'), None)
        if e:
            break
        time.sleep(0.2)
    if not (sw and e):
        log('SESION_RECHAZADA', motivo='AAA no lista el puerto como autorizado',
            dispositivo=dev, puerto=port)
        return
    usuario, mac = e['username'], e['macAddress'].lower()
    rad = None
    for _ in range(10):                  # el POST de RADIUS llega antes; margen 2 s
        rad = take_radius(usuario)
        if rad:
            break
        time.sleep(0.2)
    if not rad:
        log('SESION_RECHAZADA', motivo='sin respuesta de RADIUS para el usuario',
            usuario=usuario, mac=mac)
        return
    vlan = rad[2]
    rol = int(vlan) // 100
    if rol not in pol['roles']:
        log('SESION_RECHAZADA', motivo=f'rol {rol} inexistente', usuario=usuario)
        return
    t_start = started.get((dev, port))
    key = f'{sw}/{port}'
    with lock:
        s = {'nombre': usuario, 'usuario': usuario, 'mac': mac, 'switch': sw,
             'puerto': int(port), 'ip': None, 'rol': rol, 'estado': 'SIN_IP',
             'inicio': time.time(), 'expira': time.time() + SESSION_TTL}
        q = quarantine.get(mac)
        if q and q['expira'] > time.time():
            s['rol_orig'], s['rol'], s['estado'] = rol, 9, 'CUARENTENA'
        old = sessions.get(key)
        if old and old['mac'] == mac and old.get('ip') and old['rol'] == s['rol']:
            s['ip'], s['estado'] = old['ip'], old['estado']       # reautenticación
        for k, o in list(sessions.items()):                       # el host se movió
            if o['mac'] == mac and k != key:
                sessions.pop(k)
        sessions[key] = s
        push()
    log('SESION_AUTORIZADA', usuario=usuario, mac=mac, puerto=key, rol=s['rol'],
        latencia_ms=int((time.time() - t_start) * 1000) if t_start else None)


def on_end(dev, port, causa):
    sw = DEV2SW.get(dev)
    with lock:
        if f'{sw}/{port}' in sessions:
            finalize(f'{sw}/{port}', 'AAA_' + causa)
    log('ACCESO_DENEGADO', dispositivo=dev, puerto=port, causa=causa)


def follow_onos():
    """Sigue el log de ONOS: da los instantes de los eventos de la app AAA."""
    while True:
        p = subprocess.Popen(['docker', 'logs', '-f', '--since', '1s', 'onos'],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1)
        for raw in p.stdout:
            line = ANSI.sub('', raw)
            m = re.search(r'Auth event STARTED for (of:\w+)/(\d+)', line)
            if m:
                started[(m.group(1), m.group(2))] = time.time()
                last_event[(m.group(1), m.group(2))] = time.time()
                continue
            m = re.search(r'Auth event APPROVED for (of:\w+)/(\d+)', line)
            if m:
                last_event[(m.group(1), m.group(2))] = time.time()
                threading.Thread(target=on_approved, args=m.groups(), daemon=True).start()
                continue
            m = re.search(r'Auth event (DENIED|UNAUTHORIZED|TIMEOUT) for (of:\w+)/(\d+)', line)
            if m:
                last_event[(m.group(2), m.group(3))] = time.time()
                on_end(m.group(2), m.group(3), m.group(1))
                continue
            if 'Moving from AUTHORIZED state to IDLE state' in line:
                idle_times.append(time.time())           # logoff: sin dispositivo ni puerto
        log('LOG_ONOS_CERRADO', nota='reintento en 3 s')
        time.sleep(3)


def watch_logoff():
    """Detecta el EAPOL-Logoff: AAA pasa a IDLE sin decir qué puerto, así que se
    busca el puerto de usuario cuyo contador EAPOL subió sin ningún evento de AAA."""
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
                # subió el contador: ¿hubo handshake (evento AAA) o fue un logoff?
                if last_event.get(key, 0) > t_prev - 12:
                    continue
                if not any(now - 20 < t < now + 1 for t in idle_times):
                    continue
                sw = DEV2SW.get(f['deviceId'])
                with lock:
                    if f'{sw}/{port}' in sessions and sessions[f'{sw}/{port}']['usuario'] != 'invitado':
                        finalize(f'{sw}/{port}', 'EAPOL_LOGOFF')
                        idle_times.clear()
            t_prev = now
        except Exception as e:                           # noqa: BLE001
            log('ERROR_LOGOFF', error=str(e)[:160])


def sync_with_aaa():
    """Red de seguridad: una sesión sin registro AUTHORIZED en AAA se cierra."""
    while True:
        time.sleep(10)
        entries = aaa_users()
        if entries is None:
            continue
        ok = {(x['connectPoint'], x['macAddress'].lower()) for x in entries
              if x['authState'] == 'AUTHORIZED_STATE'}
        with lock:
            for k, s in list(sessions.items()):
                if s['usuario'] == 'invitado':
                    continue
                dev = next((d for d, n in DEV2SW.items() if n == s['switch']), None)
                if (f'{dev}/{s["puerto"]}', s['mac']) not in ok:
                    finalize(k, 'AAA_SINCRONIZACION')


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
        sessions[f'{sw}/{port}'] = {
            'nombre': 'invitado', 'usuario': 'invitado', 'mac': mac, 'switch': sw,
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

    def allowed(self, radius=False):
        ip = self.client_address[0]
        return ip == '127.0.0.1' or (radius and ip == RADIUS_IP)

    def route(self, method):
        path = self.path.split('?')[0].rstrip('/')
        parts = path.split('/')[1:]              # ['identity', ...]
        if not parts or parts[0] != 'identity':
            return self.reply(404)
        res = parts[1] if len(parts) > 1 else ''
        arg = parts[2] if len(parts) > 2 else None
        if not self.allowed(radius=(method == 'POST' and res == 'sessions' and not arg)):
            return self.reply(403, {'error': 'origen no permitido'})
        b = self.body() if method in ('POST', 'PUT') else {}
        if res == 'sessions' and method == 'POST':
            vlan = str(b.get('vlan', '')).strip()
            if not b.get('usuario') or not vlan.isdigit():
                return self.reply(400, {'error': 'usuario y vlan obligatorios'})
            with lock:
                radius_q.append((time.time(), b['usuario'], vlan))
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
    global sessions
    try:
        for s in json.load(open(STATE)):                 # reinicio: se reinstala todo
            sessions[f"{s['switch']}/{s['puerto']}"] = s
    except (OSError, ValueError):
        pass
    log('ARRANQUE', sesiones=len(sessions))
    for fn in (worker, expiry, follow_onos, watch_logoff, sync_with_aaa):
        threading.Thread(target=fn, daemon=True).start()
    push()
    ThreadingHTTPServer(('0.0.0.0', 5001), H).serve_forever()


if __name__ == '__main__':
    main()
