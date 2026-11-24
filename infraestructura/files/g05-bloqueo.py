#!/usr/bin/env python3
"""Bloqueo de cuentas por intentos fallidos (R1-03, G05). Corre en ldap-radius como root.

FreeRADIUS (linelog g05_intentos) escribe una línea por cada respuesta final:
    ACEPTA <usuario en hexadecimal>  |  RECHAZO <usuario en hexadecimal>
El nombre va en hexadecimal para que un User-Name con saltos de línea no pueda fabricar
líneas falsas (por ejemplo, un "ACEPTA" que reinicie el contador de otra cuenta).

Política (la misma de la ppolicy de LDAP): LIMITE fallos seguidos dentro de VENTANA
segundos bloquean la cuenta DURACION segundos. El bloqueo es el atributo
pwdAccountLockedTime en LDAP, que FreeRADIUS ya consulta en authorize: una cuenta
bloqueada se rechaza incluso con su certificado válido. Un acceso correcto reinicia el
contador. Cada fallo, bloqueo y desbloqueo se avisa a identity (registro de seguridad).

Uso: g05-bloqueo servir | estado | desbloquear <usuario>
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

LIMITE = int(os.getenv('BLOQUEO_LIMITE', '5'))
VENTANA = int(os.getenv('BLOQUEO_VENTANA', '900'))
DURACION = int(os.getenv('BLOQUEO_DURACION', '900'))
LOG = os.getenv('BLOQUEO_LOG', '/var/log/freeradius/g05-intentos.log')
ESTADO = os.getenv('BLOQUEO_ESTADO', '/var/lib/g05/bloqueo.json')
IDENTITY = os.getenv('IDENTITY_URL', 'http://192.168.0.16:5001') + '/identity/cuenta'
BASE = os.getenv('LDAP_BASE', 'dc=campus,dc=lab')
ADMIN_PW = os.getenv('LDAP_ADMIN_PW', '/root/g05-r1/ldap_admin')
USUARIO_OK = re.compile(r'^[A-Za-z0-9._-]{1,64}$')


# ------------------------------------------------------------ lógica (pura)
def register_failed_attempt(estado, usuario, ahora, limite=LIMITE, ventana=VENTANA, duracion=DURACION):
    """Registra un fallo. Devuelve {'fallos', 'bloqueado', 'nuevo_bloqueo', 'hasta'}."""
    e = estado.setdefault(usuario, {'fallos': [], 'hasta': 0})
    if e['hasta'] > ahora:                       # ya bloqueada: no alarga el bloqueo
        return {'fallos': len(e['fallos']), 'bloqueado': True, 'nuevo_bloqueo': False, 'hasta': e['hasta']}
    e['fallos'] = [t for t in e['fallos'] if ahora - t < ventana] + [ahora]
    nuevo = len(e['fallos']) >= limite
    if nuevo:
        e['hasta'] = ahora + duracion
    return {'fallos': len(e['fallos']), 'bloqueado': nuevo, 'nuevo_bloqueo': nuevo, 'hasta': e['hasta']}


def register_success(estado, usuario):
    """Acceso correcto: reinicia el contador (fallos *seguidos*)."""
    if usuario in estado and not estado[usuario]['hasta']:
        estado[usuario]['fallos'] = []


def is_locked(estado, usuario, ahora):
    return estado.get(usuario, {}).get('hasta', 0) > ahora


def vencidos(estado, ahora):
    """Cuentas cuyo bloqueo terminó: se desbloquean y su contador vuelve a cero."""
    fuera = [u for u, e in estado.items() if e['hasta'] and e['hasta'] <= ahora]
    for u in fuera:
        estado[u] = {'fallos': [], 'hasta': 0}
    return fuera


def leer_linea(linea):
    """'RECHAZO 616c753031' -> ('RECHAZO', 'alu01'); None si no es válida."""
    partes = linea.strip().split()
    if len(partes) != 2 or partes[0] not in ('ACEPTA', 'RECHAZO'):
        return None
    try:
        usuario = bytes.fromhex(partes[1]).decode('utf-8')
    except ValueError:
        return None
    return partes[0], usuario


# ------------------------------------------------------------ efectos
def ldap(usuario, bloquear):
    """Pone o quita pwdAccountLockedTime en la cuenta (cn=admin, contraseña en archivo)."""
    if bloquear:
        cambio = f"replace: pwdAccountLockedTime\npwdAccountLockedTime: {time.strftime('%Y%m%d%H%M%SZ', time.gmtime())}\n"
    else:
        cambio = 'delete: pwdAccountLockedTime\n'
    ldif = f'dn: uid={usuario},ou=people,{BASE}\nchangetype: modify\n{cambio}'
    r = subprocess.run(['ldapmodify', '-x', '-H', 'ldap://localhost', '-D', f'cn=admin,{BASE}', '-y', ADMIN_PW],
                       input=ldif, text=True, capture_output=True)
    ok = r.returncode == 0 or 'No such attribute' in r.stderr
    return ok, r.stderr.strip()[:120]


def avisar(ev, usuario, **kw):
    body = json.dumps({'ev': ev, 'usuario': usuario, 'limite': LIMITE, **kw}).encode()
    req = urllib.request.Request(IDENTITY, data=body, headers={'Content-Type': 'application/json'})
    try:
        urllib.request.urlopen(req, timeout=3).read()
    except OSError:
        pass


def guardar(estado):
    os.makedirs(os.path.dirname(ESTADO), exist_ok=True)
    tmp = ESTADO + '.tmp'
    json.dump(estado, open(tmp, 'w'))
    os.replace(tmp, ESTADO)


def cargar():
    try:
        return json.load(open(ESTADO))
    except (OSError, ValueError):
        return {}


def log(**kw):
    print(json.dumps({'t': time.strftime('%H:%M:%S'), **kw}, ensure_ascii=False), flush=True)


def procesar(estado, accion, usuario, ahora):
    if not USUARIO_OK.match(usuario):
        log(ev='USUARIO_INVALIDO', accion=accion, usuario=usuario[:40])   # inyección, vacío...
        return
    if accion == 'ACEPTA':
        register_success(estado, usuario)
        return
    r = register_failed_attempt(estado, usuario, ahora)
    hasta = time.strftime('%H:%M:%S', time.localtime(r['hasta'])) if r['hasta'] else None
    avisar('fallo', usuario, fallos=r['fallos'], hasta=hasta)
    log(ev='FALLO', usuario=usuario, fallos=r['fallos'], bloqueado=r['bloqueado'])
    if r['nuevo_bloqueo']:
        ok, err = ldap(usuario, True)
        avisar('bloqueo', usuario, fallos=r['fallos'], hasta=hasta)
        log(ev='BLOQUEO', usuario=usuario, hasta=hasta, ldap='ok' if ok else err)


def servir():
    estado = cargar()
    while not os.path.exists(LOG):
        time.sleep(1)
    f = open(LOG)
    f.seek(0, os.SEEK_END)
    ino = os.fstat(f.fileno()).st_ino
    ultimo = 0.0
    while True:
        linea = f.readline()
        if linea:
            par = leer_linea(linea)
            if par:
                procesar(estado, par[0], par[1], time.time())
                guardar(estado)
            continue
        time.sleep(0.2)
        if time.time() - ultimo > 5:              # desbloqueos vencidos
            ultimo = time.time()
            for u in vencidos(estado, ultimo):
                ok, err = ldap(u, False)
                avisar('desbloqueo', u)
                log(ev='DESBLOQUEO', usuario=u, ldap='ok' if ok else err)
                guardar(estado)
        try:
            if os.stat(LOG).st_ino != ino:        # rotación
                f = open(LOG)
                ino = os.fstat(f.fileno()).st_ino
        except OSError:
            pass


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'servir'
    if cmd == 'servir':
        servir()
    elif cmd == 'estado':
        ahora = time.time()
        for u, e in sorted(cargar().items()):
            print(f'{u:<12} fallos={len(e["fallos"])} bloqueada={"sí" if is_locked({u: e}, u, ahora) else "no"}')
    elif cmd == 'desbloquear':
        # Con el servicio detenido o no, el estado y LDAP quedan consistentes.
        u = sys.argv[2]
        estado = cargar()
        estado[u] = {'fallos': [], 'hasta': 0}
        guardar(estado)
        print(u, 'desbloqueada' if ldap(u, False)[0] else 'error en LDAP')
        avisar('desbloqueo', u)


if __name__ == '__main__':
    main()
