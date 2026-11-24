"""Pruebas obligatorias del Lab 7 sobre los módulos reales del slice: R1-01, R1-02, R1-03,
multirol (FreeRADIUS + LDAP con eapol_test) y R3-01, R3-02, R3-04 (firmas de Suricata
con capturas sintéticas). Cada módulo se prueba aislado: FreeRADIUS sin AAA ni ONOS, y
Suricata leyendo un pcap (`suricata -r`), no el tráfico vivo.

Necesitan los canales ~/.ssh/ctl-5809 (ldap-radius) y ~/.ssh/ctl-5812 (IDS) abiertos; si
no están, se omiten (SKIPPED). Umbrales medidos: detection_filter de Suricata alerta en
la coincidencia N+1 (count 10 -> alerta en la 11.ª).
"""
import json
import os
import subprocess
import tempfile

import pytest

import pcap as P

GW = '10.20.12.7'
A, SRV = '10.20.0.150', '10.100.1.150'


def canal(port):
    """El canal sirve si un comando real responde en 8 s (`ssh -O check` solo mira el
    proceso local: sigue "vivo" aunque la VPN se haya caído)."""
    sock = os.path.expanduser(f'~/.ssh/ctl-{port}')
    if not os.path.exists(sock):
        return False
    try:
        return subprocess.run(['ssh', '-S', sock, f'x@{GW}', 'true'], capture_output=True,
                              timeout=8).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def ssh(port, cmd, stdin=None, timeout=120):
    r = subprocess.run(['ssh', '-S', os.path.expanduser(f'~/.ssh/ctl-{port}'), f'x@{GW}', cmd],
                       input=stdin, capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip()


# ---------------------------------------------------------------- FreeRADIUS
EAP = r'''
set -u
ident=$1; cert=$2
case $cert in /*) pem=$cert.pem; key=$cert.key ;; *) pem=/etc/freeradius/3.0/certs-r1/clientes/$cert.pem; key=${pem%.pem}.key ;; esac
T=$(mktemp -d)
printf 'network={\n key_mgmt=WPA-EAP\n eap=TLS\n identity="%s"\n ca_cert="/etc/freeradius/3.0/certs-r1/ca.pem"\n client_cert="%s"\n private_key="%s"\n}\n' "$ident" "$pem" "$key" > $T/c.conf
eapol_test -c $T/c.conf -a 127.0.0.1 -s "$(cat /root/g05-r1/radius_secret)" -t 8 > $T/out 2>&1
python3 - $T/out <<'PY'
import json, re, sys
t = open(sys.argv[1], errors='replace').read()
msgs = re.split(r'RADIUS message: ', t)[1:]
ult = msgs[-1] if msgs else ''
code = re.match(r'code=\d+ \(([A-Za-z-]+)\)', ult)
attrs = [int(a) for a in re.findall(r'Attribute (\d+) ', ult)]
vlan = re.search(r'Attribute 81 [^\n]*\n\s*Value: ([0-9a-f]+)', ult)
print(json.dumps({'respuesta': code.group(1) if code else None, 'atributos': sorted(set(attrs)),
                  'vlan': bytes.fromhex(vlan.group(1)).decode() if vlan else None}))
PY
rm -rf $T
'''

radius_ok = pytest.mark.skipif(not canal(5809), reason='sin canal SSH a ldap-radius (5809)')
ids_ok = pytest.mark.skipif(not canal(5812), reason='sin canal SSH al IDS (5812)')


def autenticar(ident, cert):
    q = lambda x: "'" + x.replace("'", "'\\''") + "'"
    return json.loads(ssh(5809, f'sudo bash -s -- {q(ident)} {q(cert)}', stdin=EAP))


@radius_ok
@pytest.mark.parametrize('usuario,vlan', [('alu01', '200'), ('doc01', '300'), ('adm01', '400'), ('admin01', '500')])
def test_1_1_1_R1_01_usuario_valido_recibe_aceptacion_y_vlan_de_su_rol(usuario, vlan):
    r = autenticar(usuario, usuario)
    assert r['respuesta'] == 'Access-Accept' and r['vlan'] == vlan


PRUEBAS = '/root/g05-r1/pruebas'
INVALIDOS = [
    ('certificado de otro usuario (alu01 se presenta como admin01)', 'admin01', 'alu01'),
    ('usuario inexistente (certificado válido de la CA)', 'fantasma01', f'{PRUEBAS}/fantasma01'),
    ('certificado de una CA ajena', 'alu01', f'{PRUEBAS}/alu01-ajena'),
    ('certificado caducado', 'alu01', f'{PRUEBAS}/alu01-caducado'),
    ('certificado revocado (CRL)', 'alu01', f'{PRUEBAS}/alu01-revocado'),
    ('identidad vacía', '', 'alu01'),
    ("inyección ' OR '1'='1", "' OR '1'='1", 'alu01'),
    ('comodín LDAP *', '*', 'alu01'),
    ('inyección de filtro LDAP', 'alu01)(uid=*', 'alu01'),
    ('usuario válido sin grupo de red', 'sing01', 'sing01'),
]


@radius_ok
def test_1_1_2_R1_02_todos_los_intentos_invalidos_reciben_el_mismo_rechazo():
    """Mismo Access-Reject con los mismos atributos (EAP-Failure + Message-Authenticator),
    sin VLAN ni Reply-Message, exista o no la cuenta: no se puede enumerar usuarios. La
    identidad vacía no llega a enviar User-Name: se rechaza igual, sin EAP que cerrar."""
    res = {d: autenticar(i, c) for d, i, c in INVALIDOS}
    autenticar('alu01', 'alu01')                  # aciertos: reinician los contadores de
    autenticar('admin01', 'admin01')              # alu01 y admin01 (R1-03)
    for d, r in res.items():
        assert r['respuesta'] == 'Access-Reject', (d, r)
        assert r['vlan'] is None and 18 not in r['atributos'], (d, r)        # 18 = Reply-Message
    vacia = res.pop('identidad vacía')
    assert {tuple(r['atributos']) for r in res.values()} == {(79, 80)}, res
    assert set(vacia['atributos']) <= {79, 80}


@radius_ok
def test_1_1_3_R1_multirol_recibe_el_rol_de_mayor_privilegio():
    """multi01 está en net-docente y net-admin: recibe la VLAN del admin (500)."""
    r = autenticar('multi01', 'multi01')
    assert r['respuesta'] == 'Access-Accept' and r['vlan'] == '500'


@radius_ok
def test_1_2_1_R1_03_quinto_fallo_bloquea_la_cuenta_incluso_con_su_certificado():
    reset = 'sudo systemctl stop g05-bloqueo; sudo g05-bloqueo desbloquear prueba01 >/dev/null; sudo systemctl start g05-bloqueo; sleep 1'
    ssh(5809, reset)
    try:
        for _ in range(4):
            assert autenticar('prueba01', 'alu01')['respuesta'] == 'Access-Reject'
        assert 'bloqueada=no' in ssh(5809, 'sleep 1; sudo g05-bloqueo estado | grep prueba01')
        assert autenticar('prueba01', 'alu01')['respuesta'] == 'Access-Reject'           # 5.º fallo
        assert 'bloqueada=sí' in ssh(5809, 'sleep 1; sudo g05-bloqueo estado | grep prueba01')
        assert autenticar('prueba01', 'prueba01')['respuesta'] == 'Access-Reject'        # su certificado
        lock = ssh(5809, 'sudo ldapsearch -x -LLL -H ldap://localhost -D cn=admin,dc=campus,dc=lab '
                         '-y /root/g05-r1/ldap_admin -b uid=prueba01,ou=people,dc=campus,dc=lab pwdAccountLockedTime')
        assert 'pwdAccountLockedTime:' in lock
    finally:
        ssh(5809, reset)
    assert autenticar('prueba01', 'prueba01')['respuesta'] == 'Access-Accept'           # desbloqueada


# ------------------------------------------------------------------ Suricata
CORRER = r'''
o=$(mktemp -d)
suricata -c /etc/suricata/suricata.yaml -r "$1" -l "$o" -k none --runmode single \
         --set unix-command.enabled=no >/dev/null 2>&1
python3 - "$o/eve.json" <<'PY'
import json, sys
try:
    al = [json.loads(l) for l in open(sys.argv[1])]
except OSError:
    al = []
print(json.dumps([{'sid': a['alert']['signature_id'], 'src': a['src_ip'], 'dst': a['dest_ip']}
                  for a in al if a.get('event_type') == 'alert']))
PY
rm -rf "$o" "$1"
'''


def suricata(paquetes):
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        ruta = f.name
    P.escribir(ruta, paquetes)
    remoto = f'/tmp/g05-prueba-{os.getpid()}-{os.path.basename(ruta)}'
    subprocess.run(['scp', '-q', '-o', f'ControlPath={os.path.expanduser("~/.ssh/ctl-5812")}', ruta,
                    f'x@{GW}:{remoto}'], check=True)
    os.unlink(ruta)
    return json.loads(ssh(5812, f'sudo bash -s -- {remoto}', stdin=CORRER, timeout=180))


def de(alertas, sid):
    return [a for a in alertas if a['sid'] == sid]


def r3(alertas):
    return [a for a in alertas if a['sid'] < 2000000]          # sin las firmas de R2


@ids_ok
def test_3_1_1_R3_01_escaneo_de_puertos_en_el_umbral():
    """10 SYN a puertos no ofrecidos en 2 s: sin alerta. 11: alerta con origen y destino."""
    syn = lambda n: [(i * 0.2, P.tcp(A, SRV, 40000 + i, 1000 + i, 'S')) for i in range(n)]
    assert de(suricata(syn(10)), 1000001) == []
    al = de(suricata(syn(11)), 1000001)
    assert len(al) == 1 and al[0]['src'] == A and al[0]['dst'] == SRV


@ids_ok
def test_3_1_2_R3_01_trafico_legitimo_a_puertos_ofrecidos_no_alerta():
    """Falso positivo: 15 conexiones a 22, 53, 80 y 443 (los servicios del campus)."""
    legit = [(i * 0.3, P.tcp(A, SRV, 42000 + i, (22, 53, 80, 443)[i % 4], 'S')) for i in range(15)]
    assert r3(suricata(legit)) == []


@ids_ok
def test_3_1_3_R3_02_escaneo_de_red_identifica_al_origen():
    """Barrido ICMP: 15 hosts en 3 s sin alerta; 16, alerta. Escaneo TCP de 11 hosts, alerta."""
    ping = lambda n: [(i * 0.2, P.icmp_echo(A, f'10.100.0.{60 + i}', seq=i)) for i in range(n)]
    assert de(suricata(ping(15)), 1000002) == []
    al = de(suricata(ping(16)), 1000002)
    assert len(al) == 1 and al[0]['src'] == A
    tcp = [(i * 0.2, P.tcp(A, f'10.30.0.{10 + i}', 40000 + i, 80, 'S')) for i in range(11)]
    al = de(suricata(tcp), 1000003)
    assert len(al) == 1 and al[0]['src'] == A


@ids_ok
def test_3_1_4_R3_04_rafaga_de_requests_todos_contra_uno():
    """40 GET en 8 s: sin alerta. 41: alerta. Con dos clientes sobre el umbral, se
    identifica a cada uno contra el mismo servidor."""
    def http(clientes, n):
        pk = []
        for j, c in enumerate(clientes):
            for i in range(n):
                pk += P.sesion_http(c, SRV, 41000 + 100 * j + i, '/', t0=i * 0.2 + j * 0.01)
        return pk
    assert de(suricata(http([A], 40)), 1000020) == []
    al = de(suricata(http([A, '10.10.0.150'], 41)), 1000020)
    assert {a['src'] for a in al} == {A, '10.10.0.150'} and {a['dst'] for a in al} == {SRV}
