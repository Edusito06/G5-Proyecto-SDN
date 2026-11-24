"""Capturas sintéticas (pcap) para probar las firmas de Suricata de R3, sin scapy.

Arma tramas Ethernet/IPv4 con TCP o ICMP y checksums correctos. `sesion_http` arma una
conexión TCP completa (handshake, GET, respuesta y cierre) para las firmas HTTP.
"""
import struct

ATK_MAC, SRV_MAC = '02:05:00:00:00:02', '02:00:00:00:00:fe'


def _mac(m):
    return bytes(int(x, 16) for x in m.split(':'))


def _ip(a):
    return bytes(int(x) for x in a.split('.'))


def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack(f'!{len(b) // 2}H', b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def _ipv4(src, dst, proto, payload, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident & 0xffff, 0x4000, 64, proto, 0,
                    _ip(src), _ip(dst))
    h = h[:10] + struct.pack('!H', _csum(h)) + h[12:]
    return h + payload


def tcp(src, dst, sport, dport, flags, seq=1, ack=0, data=b'', smac=ATK_MAC, dmac=SRV_MAC):
    f = {'S': 0x02, 'A': 0x10, 'F': 0x01, 'P': 0x08, 'R': 0x04}
    fl = sum(f[c] for c in flags)
    h = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, fl, 65535, 0, 0)
    pseudo = _ip(src) + _ip(dst) + struct.pack('!BBH', 0, 6, len(h) + len(data))
    c = _csum(pseudo + h + data)
    h = h[:16] + struct.pack('!H', c) + h[18:]
    return _mac(dmac) + _mac(smac) + b'\x08\x00' + _ipv4(src, dst, 6, h + data)


def icmp_echo(src, dst, ident=1, seq=1, smac=ATK_MAC, dmac=SRV_MAC):
    h = struct.pack('!BBHHH', 8, 0, 0, ident, seq) + b'g05' * 8
    h = h[:2] + struct.pack('!H', _csum(h)) + h[4:]
    return _mac(dmac) + _mac(smac) + b'\x08\x00' + _ipv4(src, dst, 1, h)


def sesion_http(cli, srv, sport, ruta='/', t0=0.0, ua='Mozilla/5.0'):
    """[(t, trama)] de una conexión HTTP completa del cliente al servidor (puerto 80)."""
    req = f'GET {ruta} HTTP/1.1\r\nHost: {srv}\r\nUser-Agent: {ua}\r\nAccept: */*\r\n\r\n'.encode()
    resp = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok'
    c, s = 1000, 5000
    d = 0.0005
    return [
        (t0, tcp(cli, srv, sport, 80, 'S', c)),
        (t0 + d, tcp(srv, cli, 80, sport, 'SA', s, c + 1, smac=SRV_MAC, dmac=ATK_MAC)),
        (t0 + 2 * d, tcp(cli, srv, sport, 80, 'A', c + 1, s + 1)),
        (t0 + 3 * d, tcp(cli, srv, sport, 80, 'PA', c + 1, s + 1, req)),
        (t0 + 4 * d, tcp(srv, cli, 80, sport, 'PA', s + 1, c + 1 + len(req), resp, smac=SRV_MAC, dmac=ATK_MAC)),
        (t0 + 5 * d, tcp(cli, srv, sport, 80, 'FA', c + 1 + len(req), s + 1 + len(resp))),
        (t0 + 6 * d, tcp(srv, cli, 80, sport, 'FA', s + 1 + len(resp), c + 2 + len(req), smac=SRV_MAC, dmac=ATK_MAC)),
        (t0 + 7 * d, tcp(cli, srv, sport, 80, 'A', c + 2 + len(req), s + 2 + len(resp))),
    ]


def escribir(ruta, paquetes, base=1_800_000_000.0):
    """paquetes: [(t relativo en s, trama)] -> archivo pcap (Ethernet)."""
    with open(ruta, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for t, b in sorted(paquetes, key=lambda x: x[0]):
            ts = base + t
            f.write(struct.pack('<IIII', int(ts), int((ts % 1) * 1e6), len(b), len(b)) + b)
