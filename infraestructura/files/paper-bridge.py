#!/usr/bin/env python3
"""Provision a lab bridge and maintain only packets generated/received by LOCAL."""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

BR = "br0"
ONOS = "10.100.0.2"
TARGET = f"tcp:{ONOS}:6653"
COOKIE = "0x473500000001"
OLD_COOKIE = "0x4730350000006653"
SELECT = f"table=0,cookie={COOKIE}/0xffffffffffffffff"
PROFILE = "g05-paper-local"
OVS = ["ovs-vsctl", "--timeout=10"]
OF = ["ovs-ofctl", "-O", "OpenFlow13", "--no-names"]


def output(*args):
    return subprocess.check_output(args, text=True).strip()


def require(ok, message):
    if not ok:
        raise SystemExit(message)


def ovs_get(table, record, column):
    return output(*OVS, "--if-exists", "get", table, record, column).strip('"')


def resolve(config):
    interfaces = {}
    root = Path("/sys/class/net")
    for nic in root.iterdir():
        if re.fullmatch(r"ens(?:[4-9]|[1-9][0-9]+)", nic.name) and (nic / "device").is_dir():
            interfaces[nic.name] = (nic / "address").read_text().strip()
    inventory = {name: mac.lower() for name, mac in config["data_ports"].items()}
    require(inventory == interfaces, f"NIC de datos del inventario y de la VM distintas: {inventory} / {interfaces}")
    names = {}
    for peer, identifier in config["ports"].items():
        matches = [n for n, mac in interfaces.items() if identifier.lower() in (n, mac.lower())]
        require(len(matches) == 1, f"{peer}: se esperaba una NIC física de datos con nombre/MAC {identifier}.")
        names[peer] = matches[0]
    require(len(set(names.values())) == len(names), "Hay una NIC asociada a varios vecinos.")
    require(config["parent"] in names, "Falta la interfaz que conduce a ONOS.")
    return names


def assign_ports(names):
    """Preserve live ofports and reserve distinct stable numbers for new NICs."""
    ports = {}
    for peer, nic in names.items():
        number = ovs_get("Interface", nic, "ofport")
        if number:
            require(output(*OVS, "iface-to-br", nic) == BR and number.isdigit() and 0 < int(number) < 65280,
                    f"{nic} está en otro bridge o tiene ofport no operativo ({number}).")
            ports[peer] = int(number)
    require(len(set(ports.values())) == len(ports), "Ofports duplicados en br0.")
    for peer, nic in names.items():
        if peer not in ports:
            preferred = int(nic[3:])
            ports[peer] = preferred if preferred not in ports.values() else next(
                n for n in range(1, 65280) if n not in ports.values())
    return ports


def preflight(config, names):
    mgmt = json.loads(output("ip", "-j", "-4", "address", "show", "dev", "ens3"))
    require(any(addr["local"] == config["mgmt_address"] for addr in mgmt[0]["addr_info"]),
            "La dirección de gestión de ens3 no corresponde al inventario.")
    require(not ovs_get("Interface", "ens3", "ofport"), "ens3 está en OVS. Revisa la gestión antes de continuar.")
    old_timer = False
    for flag in ("is-active", "is-enabled"):
        rc = subprocess.run(["systemctl", "--quiet", flag, "vnrt-control-inband.timer"]).returncode
        old_timer = old_timer or rc == 0
    migrate = config.get("migrate_previous") is True
    require(not old_timer or migrate, "Está activo el perfil anterior. Para migrarlo en una ventana usa -e migrate_previous_bootstrap=true.")
    old_cookie = False
    if BR in output(*OVS, "list-br").splitlines():
        owned = ovs_get("Bridge", BR, "external_ids:g05-bootstrap") == PROFILE
        existing_ports = set(output(*OVS, "list-ports", BR).splitlines())
        unknown = existing_ports - config["data_ports"].keys()
        require(not unknown, f"br0 contiene puertos fuera del inventario físico: {sorted(unknown)}.")
        existing_target = output(*OVS, "get-controller", BR)
        configured_dpid = ovs_get("Bridge", BR, "other_config:datapath-id")
        dpid = f"{int(config['address'].split('.')[-1]):016x}"
        require(configured_dpid in ("", "[]", dpid), f"br0 tiene DPID explícito distinto de {dpid}.")
        iplist = json.loads(output("ip", "-j", "-4", "addr", "show", "dev", BR))
        require(all(ip["local"] == config["address"] and ip["prefixlen"] == 28
                    for entry in iplist for ip in entry["addr_info"]), "br0 tiene otra IP de datos.")
        flows = output(*OF, "dump-flows", BR)
        old_cookie = OLD_COOKIE in flows
        require(not old_cookie or migrate, "br0 conserva flujos del bootstrap anterior. Requiere migración explícita.")
        require(not existing_target or existing_target == TARGET,
                "br0 ya tiene un controlador ajeno al perfil. Revisa el bootstrap existente.")
        if not owned:
            for flow in flows.splitlines():
                if "cookie=" in flow:
                    require((OLD_COOKIE in flow and migrate) or
                            ("cookie=0x0," in flow and "priority=0 actions=NORMAL" in flow),
                            "br0 tiene reglas de terceros. Inspección y ventana de migración requeridas.")
    for nic in config["data_ports"]:
        require(not output("ip", "-4", "-o", "address", "show", "dev", nic), f"{nic} ya tiene IPv4.")
        if ovs_get("Interface", nic, "ofport"):
            require(output(*OVS, "iface-to-br", nic) == BR, f"{nic} pertenece a otro bridge.")
            require(output(*OVS, "port-to-br", nic) == BR, f"{nic} debe ser un puerto individual.")
            interface_id = ovs_get("Interface", nic, "_uuid")
            require(ovs_get("Port", nic, "interfaces").strip("[]") == interface_id, f"{nic} pertenece a un bond.")
        else:
            require(not Path(f"/sys/class/net/{nic}/master").is_symlink(), f"{nic} pertenece a otro master.")
    return old_timer, old_cookie


def apply(config, names, all_ports):
    old_timer, old_cookie = preflight(config, names)
    dpid = f"{int(config['address'].split('.')[-1]):016x}"
    cmd = [*OVS, "--may-exist", "add-br", BR, "--", "set", "Bridge", BR,
           "protocols=OpenFlow13", "fail_mode=secure", "other_config:disable-in-band=true",
           f"other_config:datapath-id={dpid}", f"external_ids:g05-bootstrap={PROFILE}"]
    for nic, number in all_ports.items():
        cmd += ["--", "--may-exist", "add-port", BR, nic, "--", "set", "Interface", nic,
                f"ofport_request={number}"]
    ref = ovs_get("Bridge", BR, "controller").strip("[] ")
    if ref:
        cmd += ["--", "set", "Controller", ref, "connection_mode=out-of-band"]
    else:
        cmd += ["--", "--id=@c", "create", "Controller", f"target={json.dumps(TARGET)}",
                "connection_mode=out-of-band", "--", "set", "Bridge", BR, "controller=@c"]
    subprocess.run([cmd[0], "--no-wait", "--dry-run", *cmd[1:]], check=True)
    if old_timer:
        subprocess.run(["systemctl", "disable", "--now", "vnrt-control-inband.timer"], check=True)
        subprocess.run(["systemctl", "stop", "vnrt-control-inband.service"], check=True)
    if old_cookie or old_timer:
        subprocess.run([*OF, "del-flows", BR, f"table=0,cookie={OLD_COOKIE}/0xffffffffffffffff"], check=True)
    for nic in all_ports:
        if nic not in names.values():
            subprocess.run(["ip", "link", "set", "dev", nic, "down"], check=True)
    subprocess.run(cmd, check=True)
    subprocess.run(["ip", "link", "set", "dev", BR, "up"], check=True)
    for nic, number in all_ports.items():
        active = nic in names.values()
        require(ovs_get("Interface", nic, "ofport") == str(number), f"{nic}: ofport inesperado.")
        state = "up" if active else "down"
        subprocess.run(["ip", "link", "set", "dev", nic, state], check=True)
        subprocess.run([*OF, "mod-port", BR, str(number), state], check=True)
        flags = json.loads(output("ip", "-j", "link", "show", "dev", nic))[0]["flags"]
        desc = output(*OF, "dump-ports-desc", BR)
        cfg = re.search(rf"(?ms)^\s*{number}\([^)]*\):.*?^\s*config:\s*(.*?)$", desc)
        require(cfg and (("PORT_DOWN" not in cfg.group(1)) == active) and (("UP" in flags) == active),
                f"{nic}: no se pudo confirmar estado administrativo {state} en OpenFlow y Linux: {desc}")


def compose(address, ports, parent):
    base = f"cookie={COOKIE},table=0,priority=64500,vlan_tci=0x0000/0x1fff,"
    flood = ",".join("output:" + str(p) for p in sorted(ports.values()))
    flows = [f"{base}in_port=LOCAL,arp,arp_spa={address},arp_tpa={ONOS} actions={flood}",
             f"{base}in_port=LOCAL,tcp,nw_src={address},nw_dst={ONOS},tp_dst=6653 actions=output:{ports[parent]}"]
    for port in ports.values():
        flows.extend([
            f"{base}in_port={port},arp,arp_spa={ONOS},arp_tpa={address} actions=LOCAL",
            f"{base}in_port={port},tcp,nw_src={ONOS},nw_dst={address},tp_src=6653 actions=LOCAL"])
    return flows


def restore(config, names, ports):
    require(ovs_get("Bridge", BR, "external_ids:g05-bootstrap") == PROFILE,
            "El perfil del bridge cambió, restauración detenida.")
    for peer, nic in names.items():
        require(ovs_get("Interface", nic, "ofport") == str(ports[peer]), f"ofport incoherente para {nic}.")
    rules = compose(config["address"], ports, config["parent"])
    dump = output(*OF, "dump-flows", BR, SELECT)
    with tempfile.TemporaryDirectory() as tmp:
        live, expected = Path(tmp) / "live", Path(tmp) / "expected"
        live.write_text("".join(line.strip() + "\n" for line in dump.splitlines() if "cookie=" in line))
        expected.write_text("\n".join(rules) + "\n")
        result = subprocess.run([*OF, "diff-flows", live, expected], stdout=subprocess.DEVNULL)
        if not result.returncode:
            return
        if result.returncode != 2:
            result.check_returncode()
    bundle = [f"delete {SELECT}", *("add " + flow for flow in rules)]
    subprocess.run([*OF, "--bundle", "add-flows", BR, "-"], input="\n".join(bundle) + "\n", text=True, check=True)


def main():
    data = os.getenv("PAPER_CONFIG")
    config = json.loads(data if data else Path("/etc/g05-paper-bridge.json").read_text())
    require(re.fullmatch(r"10\.100\.0\.[3-8]", config["address"]), "Dirección LOCAL fuera del inventario.")
    names = resolve(config)
    ports = config.get("ofports")
    if sys.argv[1:] in (["check"], ["apply"]):
        if sys.argv[1:] == ["check"]:
            preflight(config, names)
        # Include reserves and access ports so their existing numbers remain occupied.
        all_ports = assign_ports({nic: nic for nic in config["data_ports"]})
        selected = {peer: all_ports[nic] for peer, nic in names.items()}
        if sys.argv[1:] == ["check"]:
            print(json.dumps(selected))
        else:
            require(ports == selected, "El estado de ofports cambió desde la comprobación.")
            apply(config, names, all_ports)
    elif sys.argv[1:] == ["restore"]:
        restore(config, names, ports)
    else:
        raise SystemExit("Uso: paper-bridge.py check|apply|restore")


if __name__ == "__main__":
    main()
