#!/usr/bin/env python3
"""Redundancia del canal de control in-band de G05 (ONOS-1 en 10.100.0.2).

Instala en cada switch, de forma proactiva, caminos de respaldo para el tráfico
ARP y OpenFlow (TCP/6653) entre el puerto LOCAL de cada br0 y ONOS-1:

  * BFD en los enlaces entre switches (el VNRT no propaga la caída de portadora).
  * Grupos OpenFlow Fast Failover cuyo puerto vigilado usa la vida que reporta BFD.
  * Reglas de prioridad superior a las del bootstrap (cookie propia), de modo que
    el camino primario coincide con el árbol actual y el respaldo entra solo.

Uso (como root en el switch):  g05-redundancia {ports|apply|controllers|status|remove}
"""
import re
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

BR = "br0"
ONOS = "10.100.0.2"      # ONOS-1, colgado de DC-DIST (DF1)
ONOS2 = "10.100.0.9"     # ONOS-2, colgado de R-SW2 (DF2)
TARGETS = [f"tcp:{ONOS}:6653", f"tcp:{ONOS2}:6653"]
CONTROLLER_PEERS = ("onos-1", "onos-2")   # puertos hacia VMs de control: sin BFD
COOKIE = "0x473500000002"
SELECT = f"cookie={COOKIE}/-1"
P_LOCAL = 64600      # por encima de las reglas LOCAL del bootstrap (64500)
P_TRANSIT = 64000    # por encima del tránsito de org.g05.inband (62500)
GBASE = 50001
GRANGE = range(GBASE, GBASE + 99)
BFD = {"enable": "true", "min_rx": "100", "min_tx": "100"}

IP = {"core-1": "10.100.0.3", "core-2": "10.100.0.4", "dc-dist": "10.100.0.5",
      "r-sw1": "10.100.0.6", "r-sw2": "10.100.0.7", "s-dist": "10.100.0.8"}
# Vecino -> interfaz local (verificado por LLDP en ONOS antes de instalar reglas).
FABRIC = {
    "core-1": {"dc-dist": "ens6", "core-2": "ens5", "r-sw1": "ens7", "r-sw2": "ens8", "s-dist": "ens9"},
    "core-2": {"dc-dist": "ens6", "core-1": "ens5", "r-sw1": "ens7", "r-sw2": "ens8", "s-dist": "ens9"},
    "dc-dist": {"core-1": "ens4", "core-2": "ens5", "onos-1": "ens6"},
    "r-sw1": {"core-1": "ens4", "core-2": "ens5"},
    "r-sw2": {"core-1": "ens4", "core-2": "ens5", "onos-2": "ens6"},
    "s-dist": {"core-1": "ens4", "core-2": "ens5"},
}
CORES = ("core-1", "core-2")
LEAVES = ("r-sw1", "r-sw2", "s-dist")
ROOT = "dc-dist"
OF = ["ovs-ofctl", "-O", "OpenFlow13", "--no-names"]
VS = ["ovs-vsctl", "--timeout=10"]


def run(*args, **kw):
    return subprocess.run(args, check=True, text=True, **kw)


def out(*args):
    return subprocess.check_output(args, text=True).strip()


def ofport(nic):
    number = out(*VS, "get", "Interface", nic, "ofport")
    if not number.isdigit() or int(number) <= 0:
        raise SystemExit(f"{nic}: ofport no válido ({number})")
    return int(number)


def pairs(src, dst, up):
    port = "tp_dst=6653" if up else "tp_src=6653"
    return [f"arp,arp_spa={src},arp_tpa={dst}", f"tcp,nw_src={src},nw_dst={dst},{port}"]


def flow(prio, in_port, match, action):
    return (f"cookie={COOKIE},table=0,priority={prio},in_port={in_port},"
            f"vlan_tci=0x0000/0x1fff,{match} actions={action}")


def plan(host):
    """Devuelve (grupos {id: [puertos en orden de preferencia]}, reglas)."""
    me = IP[host]
    fab = {peer: ofport(nic) for peer, nic in FABRIC[host].items()}
    groups, flows = {}, []

    def add(prio, in_port, src, dst, up, action):
        for match in pairs(src, dst, up):
            flows.append(flow(prio, in_port, match, action))

    if host in LEAVES:
        c1, c2 = fab["core-1"], fab["core-2"]
        groups[GBASE] = [c1, c2]
        add(P_LOCAL, "LOCAL", me, ONOS, True, f"group:{GBASE}")
        for p in (c1, c2):
            add(P_TRANSIT, p, ONOS, me, False, "LOCAL")
    elif host in CORES:
        other = "core-2" if host == "core-1" else "core-1"
        d, x = fab[ROOT], fab[other]
        groups[GBASE] = [d, x]
        add(P_LOCAL, "LOCAL", me, ONOS, True, f"group:{GBASE}")
        for i, leaf in enumerate(LEAVES):
            gid, p = GBASE + 1 + i, fab[leaf]
            groups[gid] = [p, x]
            add(P_TRANSIT, p, IP[leaf], ONOS, True, f"group:{GBASE}")   # subida desde la hoja
            add(P_TRANSIT, d, ONOS, IP[leaf], False, f"group:{gid}")    # bajada desde DC-DIST
            add(P_TRANSIT, x, ONOS, IP[leaf], False, f"output:{p}")     # bajada desviada por el otro core
        for peer in LEAVES + (other,):
            add(P_TRANSIT, x, IP[peer], ONOS, True, f"output:{d}")      # lo que llega del otro core no rebota
        add(P_TRANSIT, d, ONOS, IP[other], False, f"output:{x}")        # DC-DIST perdió su enlace al otro core
        for p in (d, x):
            add(P_TRANSIT, p, ONOS, me, False, "LOCAL")
    elif host == ROOT:
        c1, c2, o = fab["core-1"], fab["core-2"], fab["onos-1"]
        groups[GBASE] = [c1, c2]
        groups[GBASE + 1] = [c2, c1]
        for peer in CORES + LEAVES:
            for p in (c1, c2):
                add(P_TRANSIT, p, IP[peer], ONOS, True, f"output:{o}")
            gid = GBASE + 1 if peer == "core-2" else GBASE
            add(P_TRANSIT, o, ONOS, IP[peer], False, f"group:{gid}")
    else:
        raise SystemExit(f"Host desconocido: {host}")
    plan_onos2(host, me, fab, add, groups)
    return groups, flows


def plan_onos2(host, me, fab, add, groups):
    """Caminos ARP/OpenFlow hacia ONOS-2 (10.100.0.9), colgado de R-SW2.

    Reutiliza los grupos Fast Failover del plan principal: en las hojas y en DC-DIST
    el grupo GBASE sube por Core-1 o Core-2; en los cores, el grupo de R-SW2 baja
    por su enlace directo o por el otro core, y GBASE va hacia DC-DIST.
    """
    others = [s for s in IP if s != host]
    if host == "r-sw2":
        o2 = fab["onos-2"]
        # Hacia cada core, primero su enlace directo: por el otro core haría falta el
        # enlace entre cores, que el grupo FF de R-SW2 no puede vigilar.
        groups[GBASE + 1] = [fab["core-2"], fab["core-1"]]
        add(P_LOCAL, "LOCAL", me, ONOS2, True, f"output:{o2}")
        add(P_TRANSIT, o2, ONOS2, me, False, "LOCAL")
        for peer in others:
            add(P_TRANSIT, o2, ONOS2, IP[peer], False,
                f"group:{GBASE + 1 if peer == 'core-2' else GBASE}")
            for p in (fab["core-1"], fab["core-2"]):
                add(P_TRANSIT, p, IP[peer], ONOS2, True, f"output:{o2}")
    elif host in LEAVES or host == ROOT:
        add(P_LOCAL, "LOCAL", me, ONOS2, True, f"group:{GBASE}")
        for p in (fab["core-1"], fab["core-2"]):
            add(P_TRANSIT, p, ONOS2, me, False, "LOCAL")
    elif host in CORES:
        other = "core-2" if host == "core-1" else "core-1"
        d, x, r2 = fab[ROOT], fab[other], fab["r-sw2"]
        g_r2 = GBASE + 1 + LEAVES.index("r-sw2")              # [R-SW2, otro core]
        add(P_LOCAL, "LOCAL", me, ONOS2, True, f"group:{g_r2}")
        for leaf in LEAVES:
            if leaf != "r-sw2":
                add(P_TRANSIT, fab[leaf], IP[leaf], ONOS2, True, f"group:{g_r2}")
        add(P_TRANSIT, d, IP[ROOT], ONOS2, True, f"group:{g_r2}")
        for peer in [l for l in LEAVES if l != "r-sw2"] + [ROOT, other]:
            add(P_TRANSIT, x, IP[peer], ONOS2, True, f"output:{r2}")     # desviado por el otro core
        for p in (r2, x):
            add(P_TRANSIT, p, ONOS2, me, False, "LOCAL")
        for i, leaf in enumerate(LEAVES):
            if leaf != "r-sw2":
                add(P_TRANSIT, r2, ONOS2, IP[leaf], False, f"group:{GBASE + 1 + i}")
                add(P_TRANSIT, x, ONOS2, IP[leaf], False, f"output:{fab[leaf]}")
        add(P_TRANSIT, r2, ONOS2, IP[ROOT], False, f"group:{GBASE}")
        add(P_TRANSIT, x, ONOS2, IP[ROOT], False, f"output:{d}")
        add(P_TRANSIT, r2, ONOS2, IP[other], False, f"output:{x}")


def group_spec(gid, ports):
    buckets = ",".join(f"bucket=watch_port:{p},actions=output:{p}" for p in ports)
    return f"group_id={gid},type=ff,{buckets}"


def live_groups():
    found = {}
    for line in out(*OF, "dump-groups", BR).splitlines():
        m = re.search(r"group_id=(\d+),type=(\w+)", line)
        if m:
            found[int(m.group(1))] = (m.group(2), [int(p) for p in re.findall(r"watch_port:(\d+)", line)])
    return found


def do_ports(host):
    for peer, nic in FABRIC[host].items():
        run("ip", "link", "set", "dev", nic, "up")
        run(*OF, "mod-port", BR, nic, "up")
        if peer in CONTROLLER_PEERS:
            continue  # ONOS no habla BFD: activarlo dejaría el puerto como no vivo
        current = out(*VS, "get", "Interface", nic, "bfd")
        if any(f'{k}="{v}"' not in current and f"{k}={v}" not in current for k, v in BFD.items()):
            run(*VS, "set", "Interface", nic, *[f"bfd:{k}={v}" for k, v in BFD.items()])
    print(f"{host}: enlaces entre switches activos con BFD")


def do_apply(host):
    groups, flows = plan(host)
    live = live_groups()
    for gid, ports in groups.items():
        if live.get(gid) != ("ff", ports):
            run(*OF, "mod-group" if gid in live else "add-group", BR, group_spec(gid, ports))
    dump = out(*OF, "dump-flows", BR, SELECT)
    with tempfile.TemporaryDirectory() as tmp:
        current, wanted = Path(tmp) / "live", Path(tmp) / "want"
        current.write_text("".join(l.strip() + "\n" for l in dump.splitlines() if "cookie=" in l))
        wanted.write_text("\n".join(flows) + "\n")
        diff = subprocess.run([*OF, "diff-flows", current, wanted], stdout=subprocess.DEVNULL)
        if diff.returncode not in (0, 2):
            diff.check_returncode()
        if diff.returncode == 2:
            bundle = [f"delete {SELECT}", *("add " + f for f in flows)]
            run(*OF, "--bundle", "add-flows", BR, "-", input="\n".join(bundle) + "\n")
    for gid in live:
        if gid in GRANGE and gid not in groups:
            run(*OF, "del-groups", BR, f"group_id={gid}")
    print(f"{host}: {len(groups)} grupos FF y {len(flows)} reglas de respaldo")


def do_controllers(host):
    """Registra ONOS-1 y ONOS-2 como controladores de br0, sin asistencia in-band de OVS."""
    current = out(*VS, "get-controller", BR).split()
    for target in TARGETS:
        if target not in current:
            run(*VS, "--", "--id=@c", "create", "Controller", f'target="{target}"',
                "connection_mode=out-of-band", "--", "add", "Bridge", BR, "controller", "@c")
    for ref in out(*VS, "get", "Bridge", BR, "controller").strip("[]").split(","):
        if ref.strip():
            run(*VS, "set", "Controller", ref.strip(), "connection_mode=out-of-band")
    print(f"{host}: controladores {out(*VS, 'get-controller', BR).split()}")


def do_status(host):
    print(out(*OF, "dump-groups", BR))
    print(out(*OF, "dump-group-stats", BR))
    for peer, nic in FABRIC[host].items():
        if peer not in CONTROLLER_PEERS:
            print(f"{nic} -> {peer}: {out(*VS, 'get', 'Interface', nic, 'bfd_status')}")
    print(out(*VS, "--columns=target,is_connected,role", "list", "Controller"))


def do_remove(host):
    run(*OF, "del-flows", BR, SELECT)
    for gid in live_groups():
        if gid in GRANGE:
            run(*OF, "del-groups", BR, f"group_id={gid}")
    for peer, nic in FABRIC[host].items():
        if peer not in CONTROLLER_PEERS:
            run(*VS, "remove", "Interface", nic, "bfd", *BFD.keys())
    print(f"{host}: respaldo retirado (los puertos quedan como estaban)")


def main():
    host = socket.gethostname()
    actions = {"ports": do_ports, "apply": do_apply, "controllers": do_controllers,
               "status": do_status, "remove": do_remove}
    if len(sys.argv) != 2 or sys.argv[1] not in actions:
        raise SystemExit(__doc__)
    actions[sys.argv[1]](host)


if __name__ == "__main__":
    main()
