"""Read each switch's Linux, OVSDB and OpenFlow view of the bootstrap tree."""
import datetime
import json
import re
import subprocess
import sys


def report(host, ip, active):
    errors = []

    def run(*args):
        cmd = subprocess.run(args, capture_output=True, text=True, timeout=15)
        if cmd.returncode:
            errors.append(" ".join(args) + ": " + cmd.stderr.strip())
        return cmd.stdout.strip()

    linux = {l["ifname"]: l for l in json.loads(run("ip", "-j", "link") or "[]")}
    members = set(run("ovs-vsctl", "--timeout=6", "list-ports", "br0").splitlines())
    raw = run("ovs-ofctl", "-O", "OpenFlow13", "dump-ports-desc", "br0")
    desc = {}
    for part in re.finditer(r"^\s*(LOCAL|\d+)\(([^)]+)\):([^\n]*)\n((?:[ \t]+[a-z]+:[^\n]*\n?)*)", raw, re.M):
        number, name, _, fields = part.groups()
        desc[name] = {"ofport": number, **dict(re.findall(r"^\s*(config|state):\s*([^\n]+)", fields, re.M))}
    issues = []
    for name in sorted(active - members):
        issues.append(f"{name}: falta puerto del árbol en br0")
    for name in sorted(linux.keys() - members):
        if re.fullmatch(r"ens(?:[4-9]|[1-9][0-9]+)", name):
            issues.append(f"{name}: interfaz de datos presente en Linux, ausente de br0")
    if "ens3" in members:
        issues.append("ens3 de gestión pertenece a br0")
    ports = {}
    for name in sorted(members):
        data = desc.get(name, {})
        linux_state = linux.get(name, {})
        ports[name] = {**data, "tree": name in active, "linux_flags": linux_state.get("flags", []),
                       "mac": linux_state.get("address"), "linux_operstate": linux_state.get("operstate")}
        if not {"config", "state"} <= data.keys():
            issues.append(f"{name}: no se pudo leer su descriptor OpenFlow")
        elif name in active:
            if ("PORT_DOWN" in data["config"] or "LINK_DOWN" in data["state"]
                    or "LOWER_UP" not in ports[name]["linux_flags"]):
                issues.append(f"{name}: enlace del árbol sin servicio")
        else:
            if "PORT_DOWN" not in data["config"]:
                issues.append(f"{name}: falta PORT_DOWN administrativo fuera del árbol")
            if "UP" in ports[name]["linux_flags"]:
                issues.append(f"{name}: interfaz Linux administrativamente UP fuera del árbol")
    expected_dpid = "of:%016x" % int(ip.split(".")[-1])
    dpid = "of:" + run("ovs-vsctl", "get", "Bridge", "br0", "datapath_id").strip('"')
    reference = run("ovs-vsctl", "get", "Bridge", "br0", "controller").strip("[] ")
    target, connected = "", ""
    if re.fullmatch(r"[a-fA-F0-9-]{36}", reference):
        target = run("ovs-vsctl", "get", "Controller", reference, "target").strip('"')
        connected = run("ovs-vsctl", "get", "Controller", reference, "is_connected")
    if dpid != expected_dpid or target != "tcp:10.100.0.2:6653" or connected != "true":
        issues.append("DPID, destino o sesión de br0 no coinciden con el inventario")
    route = run("ip", "-4", "route", "get", "10.100.0.2", "from", ip)
    tcp = run("ss", "-ntH", "state", "established", "( dport = :6653 )")
    if not re.search(r"\bdev br0\b", route) or not re.search(re.escape(ip) + r":\d+\s+10\.100\.0\.2:6653\b", tcp):
        issues.append("No se comprobó el canal TCP establecido desde la dirección LOCAL por br0")
    if "UP" not in linux.get("br0", {}).get("flags", []):
        issues.append("br0/LOCAL no está administrativamente UP")
    return {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "host": host, "ip": ip,
            "dpid": dpid, "controller_target": target, "is_connected": connected, "route": route, "tcp": tcp,
            "ports": ports, "raw_port_descriptions": raw, "issues": errors + issues}


if __name__ == "__main__":
    print(json.dumps(report(sys.argv[1], sys.argv[2], set(sys.argv[3:])), ensure_ascii=False))
