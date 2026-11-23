#!/bin/bash
# R1 (G05): OpenLDAP con ppolicy + FreeRADIUS con EAP-TLS en la VM LDAP/RADIUS.
# Se ejecuta en la VM (con sudo). Las contraseñas y claves se generan aquí, en
# /root/g05-r1 (solo root), y nunca se versionan.
#
# - Usuarios de prueba y su grupo de red (rol):  admin01 net-admin (5),
#   adm01 net-administrativo (4), doc01 net-docente (3), alu01 net-alumno (2),
#   sing01 sin grupo (debe ser rechazado).
# - ppolicy: bloqueo tras 5 intentos fallidos (15 min).
# - FreeRADIUS: EAP-TLS (la app AAA de ONOS solo maneja EAP-MD5 y EAP-TLS); el
#   rol sale del grupo de LDAP como Tunnel-Private-Group-Id = VLAN (rol x 100) y
#   se entrega al servicio identity por REST.
# - Clientes RADIUS: los dos nodos ONOS (la app AAA corre en el master del switch).
set -euo pipefail
BASE=dc=campus,dc=lab
DOM=campus.lab
IDENTITY_URL=${IDENTITY_URL:-http://192.168.0.16:5001}
NAS_IPS=${NAS_IPS:-"192.168.0.16 192.168.0.17"}
C=/root/g05-r1
sudo install -d -m 700 $C
gen() { sudo test -s $C/$1 || sudo sh -c "head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c ${2:-20} > $C/$1; chmod 600 $C/$1"; }
gen ldap_admin; gen ldap_radius; gen radius_secret 24
declare -A USUARIOS=([admin01]=net-admin [adm01]=net-administrativo [doc01]=net-docente [alu01]=net-alumno [sing01]=)
for u in "${!USUARIOS[@]}"; do gen "user_$u" 14; done
ADMIN_PW_FILE=$C/ldap_admin

# ------------------------------------------------------------------ LDAP
sudo ldapmodify -Q -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1 <<'EOF' || true
dn: cn=module{0},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: ppolicy
EOF
sudo ldapadd -Q -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1 <<EOF || true
dn: olcOverlay=ppolicy,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcPPolicyConfig
olcOverlay: ppolicy
olcPPolicyDefault: cn=default,ou=policies,$BASE
olcPPolicyHashCleartext: FALSE
EOF
ladd() { sudo ldapadd -c -x -H ldap://localhost -D cn=admin,$BASE -y $ADMIN_PW_FILE 2>&1 | grep -vE "^$|adding new entry" | grep -v "Already exists" || true; }
ladd <<EOF
dn: ou=people,$BASE
objectClass: organizationalUnit
ou: people

dn: ou=groups,$BASE
objectClass: organizationalUnit
ou: groups

dn: ou=policies,$BASE
objectClass: organizationalUnit
ou: policies

dn: cn=default,ou=policies,$BASE
objectClass: device
objectClass: pwdPolicy
cn: default
pwdAttribute: userPassword
pwdMaxFailure: 5
pwdFailureCountInterval: 900
pwdLockout: TRUE
pwdLockoutDuration: 900
pwdAllowUserChange: FALSE
EOF
ladd <<EOF
dn: cn=radius,$BASE
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: radius
userPassword: $(sudo slappasswd -T $C/ldap_radius)
EOF
for u in "${!USUARIOS[@]}"; do
  ladd <<EOF
dn: uid=$u,ou=people,$BASE
objectClass: inetOrgPerson
uid: $u
cn: $u
sn: $u
mail: $u@$DOM
userPassword: $(sudo slappasswd -T $C/user_$u)
EOF
done
for g in net-admin net-administrativo net-docente net-alumno; do
  members=""
  for u in "${!USUARIOS[@]}"; do [ "${USUARIOS[$u]}" = "$g" ] && members+="member: uid=$u,ou=people,$BASE"$'\n'; done
  ladd <<EOF
dn: cn=$g,ou=groups,$BASE
objectClass: groupOfNames
cn: $g
${members:-member: cn=radius,$BASE}
EOF
done

# ------------------------------------------------------------------ PKI (EAP-TLS)
D=/etc/freeradius/3.0/certs-r1
sudo bash -s "$D" "${!USUARIOS[@]}" <<'EOF'
set -e
D=$1; shift
mkdir -p $D/clientes && cd $D
[ -f ca.key ] || openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -subj "/C=PE/O=Campus/CN=Campus CA" -keyout ca.key -out ca.pem 2>/dev/null
if [ ! -f server.key ]; then
  openssl req -newkey rsa:2048 -nodes -subj "/C=PE/O=Campus/CN=radius.campus.lab" \
    -keyout server.key -out server.csr 2>/dev/null
  printf "basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:radius.campus.lab\n" > srv.ext
  openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 \
    -extfile srv.ext -out server.pem 2>/dev/null
fi
for u in "$@"; do
  [ -f clientes/$u.key ] && continue
  openssl req -newkey rsa:2048 -nodes -subj "/C=PE/O=Campus/CN=$u" \
    -keyout clientes/$u.key -out clientes/$u.csr 2>/dev/null
  printf "basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n" > cli.ext
  openssl x509 -req -in clientes/$u.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 \
    -extfile cli.ext -out clientes/$u.pem 2>/dev/null
done
chown -R freerad:freerad $D
chmod 640 server.key ca.key; chmod 644 ca.pem server.pem clientes/*.pem; chmod 600 clientes/*.key
EOF


# Revocación (CRL): base mínima de `openssl ca`. FreeRADIUS valida contra ca-crl.pem
# (CA + CRL vigente, check_crl = yes). Revocar: sudo g05-revocar <cert.pem>
sudo bash -s <<'EOF'
set -e
D=/etc/freeradius/3.0/certs-r1; cd $D
mkdir -p ca-db; touch ca-db/index.txt; [ -f ca-db/crlnumber ] || echo 1000 > ca-db/crlnumber
cat > ca-db/ca.cnf <<'CNF'
[ ca ]
default_ca = g05
[ g05 ]
dir = /etc/freeradius/3.0/certs-r1
database = $dir/ca-db/index.txt
crlnumber = $dir/ca-db/crlnumber
new_certs_dir = $dir/ca-db
certificate = $dir/ca.pem
private_key = $dir/ca.key
serial = $dir/ca.srl
default_md = sha256
default_crl_days = 365
default_days = 825
policy = libre
unique_subject = no
copy_extensions = none
[ libre ]
commonName = supplied
countryName = optional
organizationName = optional
CNF
openssl ca -config ca-db/ca.cnf -gencrl -out crl.pem 2>/dev/null
cat ca.pem crl.pem > ca-crl.pem
chown -R freerad:freerad ca-db crl.pem ca-crl.pem
EOF
sudo tee /usr/local/sbin/g05-revocar >/dev/null <<'EOF'
#!/bin/bash
# Revoca un certificado de usuario de R1 y publica la CRL nueva en FreeRADIUS.
set -euo pipefail
D=/etc/freeradius/3.0/certs-r1
openssl ca -config $D/ca-db/ca.cnf -revoke "${1:?uso: g05-revocar <cert.pem>}" 2>&1 | tail -1
openssl ca -config $D/ca-db/ca.cnf -gencrl -out $D/crl.pem 2>/dev/null
cat $D/ca.pem $D/crl.pem > $D/ca-crl.pem
chown freerad:freerad $D/crl.pem $D/ca-crl.pem
systemctl restart freeradius
echo "CRL: $(openssl crl -in $D/crl.pem -noout -text | grep -c 'Serial Number') certificados revocados"
EOF
sudo chmod 755 /usr/local/sbin/g05-revocar

# ------------------------------------------------------------------ FreeRADIUS
R=/etc/freeradius/3.0
SECRET=$(sudo cat $C/radius_secret)
{
  for ip in $NAS_IPS; do
    printf 'client onos-%s {\n    ipaddr = %s\n    secret = %s\n    shortname = onos\n    require_message_authenticator = yes\n}\n' "${ip##*.}" "$ip" "$SECRET"
  done
  # Cliente local para las pruebas de carga con eapol_test (solo desde esta VM).
  printf 'client pruebas-local {\n    ipaddr = 127.0.0.1\n    secret = %s\n    shortname = pruebas\n    require_message_authenticator = yes\n}\n' "$SECRET"
} | sudo tee $R/clients.conf >/dev/null

sudo tee $R/mods-available/ldap >/dev/null <<EOF
ldap {
    server = 'localhost'
    port = 389
    identity = 'cn=radius,$BASE'
    password = '$(sudo cat $C/ldap_radius)'
    base_dn = '$BASE'
    update {
        control:Tmp-String-0 := 'pwdAccountLockedTime'
    }
    user {
        base_dn = "ou=people,\${..base_dn}"
        filter = "(uid=%{%{Stripped-User-Name}:-%{User-Name}})"
    }
    group {
        base_dn = "ou=groups,\${..base_dn}"
        filter = '(objectClass=groupOfNames)'
        name_attribute = cn
        membership_filter = "(&(objectClass=groupOfNames)(member=%{control:Ldap-UserDn}))"
        cacheable_name = 'no'
        cacheable_dn = 'no'
    }
    options {
        chase_referrals = no
        rebind = no
        res_timeout = 10
        srv_timelimit = 3
        net_timeout = 1
        idle = 60
        probes = 3
        interval = 3
        ldap_debug = 0x0000
    }
    pool {
        start = 1
        min = 1
        max = 8
        spare = 2
        uses = 0
        retry_delay = 30
        lifetime = 0
        idle_timeout = 60
    }
}
EOF
sudo ln -sf $R/mods-available/ldap $R/mods-enabled/ldap

sudo tee $R/mods-available/eap >/dev/null <<'EOF'
eap {
    default_eap_type = tls
    timer_expire = 60
    ignore_unknown_eap_types = no
    cisco_accounting_username_bug = no
    max_sessions = ${max_requests}
    tls-config tls-common {
        private_key_file = /etc/freeradius/3.0/certs-r1/server.key
        certificate_file = /etc/freeradius/3.0/certs-r1/server.pem
        ca_file = /etc/freeradius/3.0/certs-r1/ca-crl.pem
        check_crl = yes
        cipher_list = "DEFAULT"
        tls_min_version = "1.2"
        tls_max_version = "1.2"
        # El CN del certificado debe ser la identidad EAP (el uid de LDAP).
        check_cert_cn = "%{User-Name}"
    }
    tls {
        tls = tls-common
    }
}
EOF

sudo tee $R/sites-available/default >/dev/null <<'EOF'
server default {
    listen {
        type = auth
        ipaddr = *
        port = 1812
    }
    authorize {
        filter_username
        preprocess
        # El usuario debe existir en LDAP y no estar bloqueado por ppolicy.
        ldap
        if (notfound) {
            update request { &Module-Failure-Message := "usuario inexistente en LDAP" }
            reject
        }
        if (&control:Tmp-String-0) {
            reject
        }
        eap {
            ok = return
        }
    }
    authenticate {
        eap
    }
    post-auth {
        # Precedencia de roles: gana el de mayor privilegio.
        if (&LDAP-Group == "net-admin") {
            update reply { &Tunnel-Private-Group-Id := "500" }
        }
        elsif (&LDAP-Group == "net-administrativo") {
            update reply { &Tunnel-Private-Group-Id := "400" }
        }
        elsif (&LDAP-Group == "net-docente") {
            update reply { &Tunnel-Private-Group-Id := "300" }
        }
        elsif (&LDAP-Group == "net-alumno") {
            update reply { &Tunnel-Private-Group-Id := "200" }
        }
        else {
            update request { &Module-Failure-Message := "usuario sin grupo de red" }
            reject                      # usuario válido sin grupo de red
        }
        update reply {
            &Tunnel-Type := VLAN
            &Tunnel-Medium-Type := IEEE-802
            &Session-Timeout := 3600
            &Termination-Action := RADIUS-Request
        }
        rest
        Post-Auth-Type REJECT {
            attr_filter.access_reject
        }
    }
}
EOF

sudo tee $R/mods-available/rest >/dev/null <<EOF
rest {
    tls {
    }
    connect_uri = "$IDENTITY_URL"
    connect_timeout = 3.0
    post-auth {
        uri = "\${..connect_uri}/identity/sessions"
        method = 'post'
        body = 'json'
        data = '{ "usuario": "%{User-Name}", "vlan": "%{reply:Tunnel-Private-Group-Id}" }'
        tls = \${..tls}
    }
    pool {
        # Conexión bajo demanda: FreeRADIUS arranca aunque identity no esté arriba.
        start = 0
        min = 0
        max = 8
        spare = 0
        uses = 0
        retry_delay = 5
        lifetime = 0
        idle_timeout = 60
    }
}
EOF
sudo ln -sf $R/mods-available/rest $R/mods-enabled/rest
sudo rm -f $R/sites-enabled/inner-tunnel
sudo chown -R freerad:freerad $R/mods-available/ldap $R/mods-available/eap $R/mods-available/rest $R/sites-available/default $R/clients.conf
sudo chmod 640 $R/mods-available/ldap $R/clients.conf
# Registro de autenticaciones (R1: intentos fallidos registrados) en radius.log.
sudo sed -i 's/^\(\s*\)auth = no/\1auth = yes/' $R/radiusd.conf
sudo freeradius -C >/tmp/frc.log 2>&1 || { tail -15 /tmp/frc.log; exit 1; }
sudo systemctl enable freeradius slapd >/dev/null 2>&1
sudo systemctl restart freeradius
sleep 2
echo "slapd: $(systemctl is-active slapd)  freeradius: $(systemctl is-active freeradius)"
echo "usuarios LDAP: $(sudo ldapsearch -x -LLL -H ldap://localhost -D cn=admin,$BASE -y $ADMIN_PW_FILE -b ou=people,$BASE uid | grep -c '^uid:')"
echo "grupos: $(sudo ldapsearch -x -LLL -H ldap://localhost -D cn=admin,$BASE -y $ADMIN_PW_FILE -b ou=groups,$BASE cn | grep '^cn:' | tr '\n' ' ')"
echo "certificados de usuario: $(sudo sh -c "ls $D/clientes/*.pem" | wc -l)"
