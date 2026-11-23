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


def tcp(name, ip, port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(32)
    while True:
        c, _ = s.accept()
        try:
            c.sendall(f'SRV {name} {ip}:{port}/tcp\n'.encode())
        finally:
            c.close()


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
