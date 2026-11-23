#!/usr/bin/env python3
"""Segmentos de servicio del campus G05 sobre la fábrica OpenFlow.

Cada segmento es un circuito L2 transportado con una VLAN entre switches y
entregado sin etiqueta en sus extremos. Core-1 tiene un puerto interno L3 por
segmento y enruta entre ellos (con nftables aislando la red de gestión):

  Roles (R2)  VLAN rol x 100   R-SW1 (lo programa r2ctl)  <->  Core-1 v100..v900
  G11         VLAN 111         Core-1 g11  <->  DC-DIST/ens8 (DNS/DHCP)
  G02/G03     VLAN 112         Core-1 g02  <->  DC-DIST/ens7 (LDAP/RADIUS)
  Recursos    VLAN 113         Core-1 srv  <->  DC-DIST/ens9 (Recursos)

En R-SW1 el puerto de usuarios lo programa r2ctl por ONOS (pipeline R2); este
módulo solo transporta las VLAN de rol entre R-SW1 y los puertos L3 de Core-1.

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

ROLES = {1: "invitado", 2: "alumno", 3: "docente", 4: "administrativo", 5: "admin", 9: "cuarentena"}
VLAN_G11, VLAN_G02, VLAN_SRV = 111, 112, 113

# Puertos internos L3 de Core-1: nombre -> (ofport, VLAN, direcciones, rutas on-link extra)
L3 = {f"v{r * 100}": (r * 100, r * 100, [f"10.{r * 10}.0.1/24"], []) for r in ROLES}
L3.update({
    "g11": (VLAN_G11, VLAN_G11, ["10.100.1.129/28"], []),
    "g02": (VLAN_G02, VLAN_G02, ["10.100.0.17/28", "10.100.0.33/28"], []),
    "srv": (VLAN_SRV, VLAN_SRV, ["10.100.0.49/28", "10.100.0.65/28", "10.100.0.129/28",
                                 "10.100.0.145/28", "10.100.0.161/28", "10.100.0.177/28",
                                 "10.100.1.1/25", "10.100.1.145/28"], ["203.0.113.10/32"]),
})
# Extremos en DC-DIST: VLAN -> interfaz del host
DC_HOSTS = {VLAN_G11: "ens8", VLAN_G02: "ens7", VLAN_SRV: "ens9"}
HOST_PORTS = {"dc-dist": list(DC_HOSTS.values())}


def run(*args, **kw):
    return subprocess.run(args, check=True, text=True, **kw)


def out(*args):
    return subprocess.check_output(args, text=True).strip()


def ofport(nic):
    return int(out(*VS, "get", "Interface", nic, "ofport"))


def untagged(in_port, match, actions):
    m = f",{match}" if match else ""
    return f"cookie={COOKIE},table=0,priority={PRIO},in_port={in_port},vlan_tci=0x0000/0x1fff{m} actions={actions}"


def tagged(in_port, vid, actions):
    return f"cookie={COOKIE},table=0,priority={PRIO},in_port={in_port},dl_vlan={vid} actions={actions}"


def push(vid, port):
    return f"push_vlan:0x8100,set_field:{vid | 0x1000}->vlan_vid,output:{port}"


def pop(port):
    return f"pop_vlan,output:{port}"


def plan(host):
    flows = []
    if host == "core-1":
        rsw1, dc = ofport("ens7"), ofport("ens6")
        for name, (number, vid, _, _) in L3.items():
            far = rsw1 if vid in {r * 100 for r in ROLES} else dc
            flows.append(tagged(far, vid, pop(number)))
            flows.append(untagged(number, "arp", push(vid, far)))
            flows.append(untagged(number, "ip", push(vid, far)))
    elif host == "dc-dist":
        up = ofport("ens4")                                   # hacia Core-1
        for vid, nic in DC_HOSTS.items():
            server = ofport(nic)
            flows.append(tagged(up, vid, pop(server)))
            flows.append(untagged(server, "arp", push(vid, up)))
            flows.append(untagged(server, "ip", push(vid, up)))
    return flows


def ensure_l3_ports():
    for name, (number, _, addresses, extra) in L3.items():
        if not out(*VS, "--if-exists", "get", "Interface", name, "ofport"):
            run(*VS, "add-port", BR, name, "--", "set", "Interface", name, "type=internal",
                f"ofport_request={number}", "external_ids:g05-l3=true")
        profile = NETDIR / f"06-g05-{name}.network"
        content = (f"[Match]\nName={name}\n[Network]\n"
                   + "".join(f"Address={a}\n" for a in addresses)
                   + "DHCP=no\nLinkLocalAddressing=no\nIPv6AcceptRA=no\nConfigureWithoutCarrier=yes\n"
                   + "".join(f"[Route]\nDestination={r}\nScope=link\n" for r in extra))
        changed = not profile.exists() or profile.read_text() != content
        if changed:
            profile.write_text(content)
            run("networkctl", "reload")
        run("ip", "link", "set", "dev", name, "up")
        present = out("ip", "-4", "-o", "addr", "show", "dev", name)
        if changed or any(a not in present for a in addresses):
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
        print(out("ip", "-br", "-4", "addr", "show", "type", "openvswitch"))


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
