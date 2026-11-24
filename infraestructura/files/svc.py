#!/usr/bin/env python3
"""Servidores de prueba para la demo de R2.

Escucha en cada IP alias de h3 los puertos TCP/UDP indicados en un JSON y
responde con un banner que dice qué recurso contestó. Sirve para comprobar
con nc que una conexión permitida llega y una bloqueada no.

Uso: svc.py spec.json    donde spec = [{"name", "ip", "tcp": [..], "udp": [..]}]
"""
import json
import socket
import sys
import threading


def atender(c, banner):
    """Si el cliente habla HTTP se lee su request y se responde como HTTP (así el
    servidor confirma los datos y el IDS ve la transacción completa); si no envía nada
    (nc -z, o un cliente que espera el banner) se responde solo con el banner."""
    try:
        c.settimeout(0.3)
        try:
            data = c.recv(4096)
        except socket.timeout:
            data = b''
        if data[:8].split(b' ')[0] in (b'GET', b'POST', b'HEAD', b'PUT', b'DELETE', b'OPTIONS'):
            c.settimeout(1)
            while b'\r\n\r\n' not in data and len(data) < 65536:
                more = c.recv(4096)
                if not more:
                    break
                data += more
            ruta = data.split(b' ', 2)[1] if data.count(b' ') >= 2 else b'/'
            if ruta.startswith(b'/descarga'):
                # R4: descarga de N MB (tráfico legítimo de prueba y medida de capacidad)
                try:
                    mb = min(200, max(1, int(ruta.split(b'mb=')[1].split(b'&')[0])))
                except (IndexError, ValueError):
                    mb = 10
                c.settimeout(60)
                c.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n'
                          b'Connection: close\r\nContent-Length: ' + str(mb << 20).encode() + b'\r\n\r\n')
                bloque = bytes(1 << 16)
                for _ in range(mb << 4):
                    c.sendall(bloque)
            else:
                body = banner.encode()
                c.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n'
                          b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
        else:
            c.sendall(banner.encode())
        c.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    finally:
        c.close()


def tcp(name, ip, port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(128)
    banner = f'SRV {name} {ip}:{port}/tcp\n'
    while True:
        c, _ = s.accept()
        threading.Thread(target=atender, args=(c, banner), daemon=True).start()


def udp(name, ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, port))
    while True:
        _, addr = s.recvfrom(512)
        s.sendto(f'SRV {name} {ip}:{port}/udp\n'.encode(), addr)


for r in json.load(open(sys.argv[1])):
    for p in r.get('tcp', []):
        threading.Thread(target=tcp, args=(r['name'], r['ip'], p), daemon=True).start()
    for p in r.get('udp', []):
        threading.Thread(target=udp, args=(r['name'], r['ip'], p), daemon=True).start()
threading.Event().wait()
