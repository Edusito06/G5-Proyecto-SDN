#!/usr/bin/env python3
"""Segmentos de servicio del campus G05 sobre la fábrica OpenFlow (fase DHCP).

Cada segmento es un circuito L2 punto a punto transportado con una VLAN entre
switches y entregado sin etiqueta en sus extremos:

  VLAN 200 (alumnos)  R-SW1/ens7 (Alumno)  <->  Core-1 puerto interno v200 (10.20.0.1/24)
  VLAN 111 (G11)      Core-1 puerto interno g11 (10.100.1.129/28)  <->  DC-DIST/ens8 (DNS/DHCP)

Core-1 actúa como relay DHCP (dhcrelay) entre ambos segmentos. Su reenvío IPv4
queda desactivado: en esta fase el alumno solo puede hacer DHCP, ARP y ping a
su gateway; el acceso a servicios lo abrirán R1/R2.

Uso (como root en el switch):  g05-servicios {apply|status|remove}
"""
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

BR = "br0"
COOKIE = "0x473500000003"
SELECT = f"cookie={COOKIE}/-1"
PRIO = 50000
OF = ["ovs-ofctl", "-O", "OpenFlow13", "--no-names"]
VS = ["ovs-vsctl", "--timeout=10"]
NETDIR = Path("/etc/systemd/network")

VLAN_ALUMNOS, VLAN_G11 = 200, 111
GW_ALUMNOS, ROUTER_G11, DHCP_SERVER = "10.20.0.1", "10.100.1.129", "10.100.1.130"

# Puertos internos L3 de Core-1: nombre -> (ofport, dirección)
L3 = {"v200": (200, f"{GW_ALUMNOS}/24"), "g11": (111, f"{ROUTER_G11}/28")}
# Puertos de hosts usados en esta fase (verificados enviando tramas desde cada host)
HOST_PORTS = {"r-sw1": ["ens7"], "dc-dist": ["ens8"]}


def run(*args, **kw):
    return subprocess.run(args, check=True, text=True, **kw)


def out(*args):
    return subprocess.check_output(args, text=True).strip()


def ofport(nic):
    return int(out(*VS, "get", "Interface", nic, "ofport"))


def untagged(in_port, match, actions):
    return f"cookie={COOKIE},table=0,priority={PRIO},in_port={in_port},vlan_tci=0x0000/0x1fff,{match} actions={actions}"


def tagged(in_port, vid, actions):
    return f"cookie={COOKIE},table=0,priority={PRIO},in_port={in_port},dl_vlan={vid} actions={actions}"


def push(vid, port):
    return f"push_vlan:0x8100,set_field:{vid | 0x1000}->vlan_vid,output:{port}"


def pop(port):
    return f"pop_vlan,output:{port}"


def plan(host):
    if host == "r-sw1":
        alumno, up = ofport("ens7"), ofport("ens4")          # hacia Core-1
        return [
            untagged(alumno, "arp", push(VLAN_ALUMNOS, up)),
            untagged(alumno, "udp,tp_src=68,tp_dst=67", push(VLAN_ALUMNOS, up)),
            untagged(alumno, f"icmp,nw_dst={GW_ALUMNOS}", push(VLAN_ALUMNOS, up)),
            tagged(up, VLAN_ALUMNOS, pop(alumno)),
        ]
    if host == "core-1":
        rsw1, dc = ofport("ens7"), ofport("ens6")
        v200, g11 = L3["v200"][0], L3["g11"][0]
        return [
            tagged(rsw1, VLAN_ALUMNOS, pop(v200)),
            untagged(v200, "arp", push(VLAN_ALUMNOS, rsw1)),
            untagged(v200, "ip", push(VLAN_ALUMNOS, rsw1)),
            tagged(dc, VLAN_G11, pop(g11)),
            untagged(g11, "arp", push(VLAN_G11, dc)),
            untagged(g11, "ip", push(VLAN_G11, dc)),
        ]
    if host == "dc-dist":
        server, up = ofport("ens8"), ofport("ens4")          # hacia Core-1
        return [
            tagged(up, VLAN_G11, pop(server)),
            untagged(server, "arp", push(VLAN_G11, up)),
            untagged(server, "udp,tp_src=67", push(VLAN_G11, up)),
            untagged(server, f"icmp,nw_dst={ROUTER_G11}", push(VLAN_G11, up)),
        ]
    return []


def ensure_l3_ports():
    for name, (number, address) in L3.items():
        if not out(*VS, "--if-exists", "get", "Interface", name, "ofport"):
            run(*VS, "add-port", BR, name, "--", "set", "Interface", name, "type=internal",
                f"ofport_request={number}", "external_ids:g05-l3=true")
        profile = NETDIR / f"06-g05-{name}.network"
        content = (f"[Match]\nName={name}\n[Network]\nAddress={address}\nDHCP=no\n"
                   "LinkLocalAddressing=no\nIPv6AcceptRA=no\nConfigureWithoutCarrier=yes\n")
        changed = not profile.exists() or profile.read_text() != content
        if changed:
            profile.write_text(content)
            run("networkctl", "reload")
        run("ip", "link", "set", "dev", name, "up")
        if changed or address not in out("ip", "-4", "-o", "addr", "show", "dev", name):
            run("networkctl", "reconfigure", name)


def ensure_host_ports(host):
    for nic in HOST_PORTS.get(host, []):
        run("ip", "link", "set", "dev", nic, "up")
        run(*OF, "mod-port", BR, nic, "up")


def install(flows):
    dump = out(*OF, "dump-flows", BR, SELECT)
    with tempfile.TemporaryDirectory() as tmp:
        live, want = Path(tmp) / "live", Path(tmp) / "want"
        live.write_text("".join(l.strip() + "\n" for l in dump.splitlines() if "cookie=" in l))
        want.write_text("\n".join(flows) + "\n" if flows else "")
        diff = subprocess.run([*OF, "diff-flows", live, want], stdout=subprocess.DEVNULL)
        if diff.returncode not in (0, 2):
            diff.check_returncode()
        if diff.returncode == 2:
            bundle = [f"delete {SELECT}", *("add " + f for f in flows)]
            run(*OF, "--bundle", "add-flows", BR, "-", input="\n".join(bundle) + "\n")


def do_apply(host):
    if host == "core-1":
        ensure_l3_ports()
    ensure_host_ports(host)
    flows = plan(host)
    install(flows)
    print(f"{host}: {len(flows)} reglas de servicio")


def do_status(host):
    print(out(*OF, "dump-flows", BR, SELECT))
    if host == "core-1":
        print(out("ip", "-br", "-4", "addr", "show", "dev", "v200"))
        print(out("ip", "-br", "-4", "addr", "show", "dev", "g11"))


def do_remove(host):
    run(*OF, "del-flows", BR, SELECT)
    if host == "core-1":
        for name in L3:
            run(*VS, "--if-exists", "del-port", BR, name)
            (NETDIR / f"06-g05-{name}.network").unlink(missing_ok=True)
        run("networkctl", "reload")
    print(f"{host}: segmentos de servicio retirados")


def main():
    host = socket.gethostname()
    actions = {"apply": do_apply, "status": do_status, "remove": do_remove}
    if len(sys.argv) != 2 or sys.argv[1] not in actions:
        raise SystemExit(__doc__)
    actions[sys.argv[1]](host)


if __name__ == "__main__":
    main()
