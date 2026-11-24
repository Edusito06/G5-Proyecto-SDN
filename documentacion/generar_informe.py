#!/usr/bin/env python3
"""Genera EXP_TEL354_LAB7_G5.pdf (Lab 7, TEL354, G05) a partir del repositorio.

- La matriz de acceso sale de politica/policy.yaml con r2ctl.evaluate_access.
- El "Resultado obtenido" de cada ficha sale de documentacion/evidencia/pytest.txt
  (salida de `pytest -v`): PASS, FAIL o NT (no ejecutada / omitida).
- Las evidencias de consola son las capturas de documentacion/evidencia/.

Uso (desde la raíz del repo, con reportlab y pyyaml):
    python3 -m pytest pruebas/unitarias -v > documentacion/evidencia/pytest.txt
    python3 documentacion/generar_informe.py
"""
import os
import re
import sys
from datetime import date
from pathlib import Path

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, Preformatted, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

RAIZ = Path(__file__).resolve().parents[1]
EV = RAIZ / 'documentacion' / 'evidencia'
SALIDA = RAIZ / 'documentacion' / 'EXP_TEL354_LAB7_G5.pdf'
sys.path.insert(0, str(RAIZ / 'politica'))
os.environ.setdefault('R2_LOCAL', '1')
import r2ctl  # noqa: E402

REPO = 'https://github.com/Edusito06/G5-Proyecto-SDN'
# Integrantes del grupo (completar antes de entregar).
INTEGRANTES = [
    '20221862 · Antaurco Corsino, Willian (líder de grupo)',
    '20192676 · Cuadros David, Jairo Leonardo',
    '20207779 · Mauricio Cristóbal, Eva María',
    '20213805 · Gutiérrez Hurtado, Jeanpier Gustavo',
    '20227163 · Rodas Arias, Eduardo',
]

# ------------------------------------------------------------------ estilo
F = '/System/Library/Fonts/Supplemental/'
pdfmetrics.registerFont(TTFont('Arial', F + 'Arial.ttf'))
pdfmetrics.registerFont(TTFont('Arial-B', F + 'Arial Bold.ttf'))
pdfmetrics.registerFont(TTFont('Mono', F + 'Courier New.ttf'))
pdfmetrics.registerFontFamily('Arial', normal='Arial', bold='Arial-B', italic='Arial', boldItalic='Arial-B')

AZUL = colors.HexColor('#1F3A5F')
AZUL_C = colors.HexColor('#E8EEF6')
GRIS = colors.HexColor('#F3F4F6')
GRIS_L = colors.HexColor('#9CA3AF')
VERDE = colors.HexColor('#1E7D45')
ROJO = colors.HexColor('#B42318')
AMBAR = colors.HexColor('#B7791F')

ss = getSampleStyleSheet()
S = {
    'n': ParagraphStyle('n', parent=ss['Normal'], fontName='Arial', fontSize=9.5, leading=13.5, spaceAfter=4),
    'p': ParagraphStyle('p', parent=ss['Normal'], fontName='Arial', fontSize=8.3, leading=10.8),
    'pb': ParagraphStyle('pb', parent=ss['Normal'], fontName='Arial-B', fontSize=8.3, leading=10.8),
    'h1': ParagraphStyle('h1', parent=ss['Heading1'], fontName='Arial-B', fontSize=15, leading=19,
                         textColor=AZUL, spaceBefore=4, spaceAfter=8),
    'h2': ParagraphStyle('h2', parent=ss['Heading2'], fontName='Arial-B', fontSize=11.5, leading=15,
                         textColor=AZUL, spaceBefore=10, spaceAfter=5),
    'h3': ParagraphStyle('h3', parent=ss['Heading3'], fontName='Arial-B', fontSize=9.8, leading=13,
                         spaceBefore=6, spaceAfter=3),
    'li': ParagraphStyle('li', parent=ss['Normal'], fontName='Arial', fontSize=9.5, leading=13.2,
                         leftIndent=12, bulletIndent=2, spaceAfter=2),
    'code': ParagraphStyle('code', fontName='Mono', fontSize=6.9, leading=8.3, textColor=colors.HexColor('#111827'),
                           backColor=GRIS, borderPadding=(4, 4, 4, 4), leftIndent=2, rightIndent=2),
    'cap': ParagraphStyle('cap', parent=ss['Normal'], fontName='Arial', fontSize=8, leading=10,
                          textColor=colors.HexColor('#4B5563'), alignment=TA_CENTER, spaceBefore=2, spaceAfter=8),
    'tit': ParagraphStyle('tit', parent=ss['Title'], fontName='Arial-B', fontSize=21, leading=26, textColor=AZUL),
    'sub': ParagraphStyle('sub', parent=ss['Normal'], fontName='Arial', fontSize=12, leading=16,
                          alignment=TA_CENTER, textColor=colors.HexColor('#374151')),
}


def P(t, st='p'):
    return Paragraph(t, S[st])


def tabla(filas, anchos, cab=True, estilo_extra=()):
    datos = [[c if not isinstance(c, str) else P(c, 'pb' if (cab and i == 0) else 'p') for c in f]
             for i, f in enumerate(filas)]
    t = Table(datos, colWidths=anchos, repeatRows=1 if cab else 0)
    st = [('GRID', (0, 0), (-1, -1), 0.4, GRIS_L), ('VALIGN', (0, 0), (-1, -1), 'TOP'),
          ('LEFTPADDING', (0, 0), (-1, -1), 4), ('RIGHTPADDING', (0, 0), (-1, -1), 4),
          ('TOPPADDING', (0, 0), (-1, -1), 2.5), ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5)]
    if cab:
        st += [('BACKGROUND', (0, 0), (-1, 0), AZUL_C)]
    t.setStyle(TableStyle(st + list(estilo_extra)))
    return t


def lista(items):
    return [Paragraph(i, S['li'], bulletText='•') for i in items]


def codigo(txt, maxl=None, ancho=112):
    """Bloque de consola: las líneas largas se parten (con sangría) en vez de cortarse."""
    lineas = [re.sub(r'^\{\}', '', l) for l in txt.rstrip('\n').splitlines() if l.strip() != '{}']
    if maxl:
        lineas = lineas[:maxl]
    out = []
    for l in lineas:
        while len(l) > ancho:
            out.append(l[:ancho])
            l = '      ' + l[ancho:]
        out.append(l)
    return Preformatted('\n'.join(out), S['code'])


def leer(nombre):
    p = EV / nombre
    return p.read_text(errors='replace') if p.exists() else ''


# ------------------------------------------------------------------ diagramas
def caja(d, x, y, w, h, texto, fondo=colors.white, borde=AZUL, tam=7, negrita=True, color_t=colors.black):
    d.add(Rect(x, y, w, h, rx=3, ry=3, fillColor=fondo, strokeColor=borde, strokeWidth=0.8))
    lineas = texto.split('\n')
    alto = tam + 1.5
    y0 = y + h / 2 + (len(lineas) - 1) * alto / 2 - tam / 3
    for i, l in enumerate(lineas):
        d.add(String(x + w / 2, y0 - i * alto, l, fontName='Arial-B' if (negrita and i == 0) else 'Arial',
                     fontSize=tam if i == 0 else tam - 0.8, textAnchor='middle', fillColor=color_t))


def flecha(d, x1, y1, x2, y2, color=AZUL, ancho=0.9, punta=True, guion=None, texto=None, tam=6.2, dx=0, dy=3):
    d.add(Line(x1, y1, x2, y2, strokeColor=color, strokeWidth=ancho, strokeDashArray=guion))
    if punta:
        import math
        a = math.atan2(y2 - y1, x2 - x1)
        L, Wd = 5.5, 2.6
        bx, by = x2 - L * math.cos(a), y2 - L * math.sin(a)
        d.add(Polygon([x2, y2, bx - Wd * math.sin(a), by + Wd * math.cos(a), bx + Wd * math.sin(a), by - Wd * math.cos(a)],
                      fillColor=color, strokeColor=color, strokeWidth=0.1))
    if texto:
        d.add(String((x1 + x2) / 2 + dx, (y1 + y2) / 2 + dy, texto, fontName='Arial', fontSize=tam,
                     textAnchor='middle', fillColor=colors.HexColor('#374151')))


def diagrama_red():
    W, H = 510, 330
    d = Drawing(W, H)
    # dominios de falla
    for x, w, et, c in ((4, 205, 'DF1 · Centro de datos', '#EEF4FB'), (215, 190, 'DF2 · Edificio R', '#F1F8F1'),
                        (411, 95, 'DF3 · Edificio S', '#FBF6EC')):
        d.add(Rect(x, 30, w, 222, fillColor=colors.HexColor(c), strokeColor=colors.HexColor('#D1D5DB'), strokeWidth=0.5))
        d.add(String(x + 5, 242, et, fontName='Arial-B', fontSize=7, fillColor=colors.HexColor('#4B5563')))
    caja(d, 205, 292, 100, 30, 'Gateway\nNAT · bastión SSH · 10.20.12.7', colors.HexColor('#F9FAFB'))
    caja(d, 70, 196, 92, 32, 'Core-1 (router L3)\nbr0 10.100.0.3 · dpid 3')
    caja(d, 420, 196, 80, 32, 'Core-2\nbr0 10.100.0.4 · dpid 4')
    caja(d, 18, 126, 84, 30, 'DC-DIST\n10.100.0.5 · dpid 5')
    caja(d, 225, 126, 78, 30, 'R-SW1 (acceso)\n10.100.0.6 · dpid 6', colors.HexColor('#FFF7E6'))
    caja(d, 320, 126, 78, 30, 'R-SW2\n10.100.0.7 · dpid 7')
    caja(d, 420, 126, 80, 30, 'S-DIST\n10.100.0.8 · dpid 8')
    # enlaces del fabric
    flecha(d, 162, 212, 420, 212, punta=False, ancho=1.6, texto='inter-core', dy=3)
    for (x, y) in ((60, 156), (264, 156), (359, 156), (460, 156)):
        flecha(d, 116, 196, x, y, punta=False, color=colors.HexColor('#2563EB'))
        flecha(d, 460, 196, x, y, punta=False, color=colors.HexColor('#7C3AED'), guion=[2, 1.5])
    flecha(d, 116, 228, 240, 292, punta=False, color=GRIS_L)
    flecha(d, 460, 228, 270, 292, punta=False, color=GRIS_L)
    # hosts
    hosts = [(7, 'ONOS-1\nAtomix-1\n10.100.0.2'), (57, 'LDAP\nRADIUS\n.0.19'),
             (107, 'DNS/DHCP\nKea\n.1.130'), (157, 'Recursos\nG02–G12\nsrv')]
    for x, t in hosts:
        caja(d, x, 62, 47, 34, t, colors.white, tam=6.2)
        flecha(d, 60, 126, x + 23, 96, punta=False, color=GRIS_L)
    caja(d, 222, 62, 44, 34, 'IDS\nSuricata\n.0.22', colors.white, tam=6.2)
    caja(d, 270, 62, 48, 34, 'Alumno\n6 usuarios\n(netns)', colors.white, tam=6.2)
    flecha(d, 264, 126, 244, 96, punta=False, color=GRIS_L)
    flecha(d, 264, 126, 294, 96, punta=False, color=GRIS_L)
    caja(d, 335, 62, 48, 34, 'ONOS-2\nAtomix-2\n10.100.0.9', colors.white, tam=6.2)
    flecha(d, 359, 126, 359, 96, punta=False, color=GRIS_L)
    caja(d, 425, 62, 70, 34, 'Atomix-3\n(árbitro Raft)\nsolo gestión', colors.white, tam=6.2)
    # espejo GRE
    flecha(d, 240, 126, 236, 96, color=ROJO, guion=[3, 2], ancho=0.8)
    d.add(String(206, 108, 'espejo GRE', fontName='Arial', fontSize=5.8, fillColor=ROJO))
    # gestión
    d.add(Rect(4, 4, 502, 20, fillColor=colors.HexColor('#F9FAFB'), strokeColor=GRIS_L, strokeWidth=0.5,
               strokeDashArray=[3, 2]))
    d.add(String(255, 11, 'Red de gestión 192.168.0.0/24 (ens3 de todas las VMs, fuera de OVS): SSH, Ansible, '
                          'clúster ONOS/Atomix, RADIUS, alertas del IDS y espejo GRE',
                 fontName='Arial', fontSize=6.3, textAnchor='middle', fillColor=colors.HexColor('#374151')))
    d.add(String(8, 262, 'Azul: enlaces a Core-1 · violeta: respaldo por Core-2 (BFD + Fast Failover)',
                 fontName='Arial', fontSize=6.3, fillColor=colors.HexColor('#374151')))
    return d


def diagrama_arquitectura():
    W, H = 510, 255
    d = Drawing(W, H)
    caja(d, 8, 150, 92, 44, 'Usuarios\n802.1X (wpa_supplicant)\nDHCP · tráfico', colors.HexColor('#F9FAFB'))
    caja(d, 130, 140, 112, 64, 'R-SW1 · OVS (OpenFlow 1.3)\nT0 ingreso · T1 anti-spoofing\nT2 mitigación R3/R4 · T3 rol\nT4 política · T5 salida',
         colors.HexColor('#FFF7E6'), tam=6.8)
    caja(d, 270, 140, 112, 64, 'Clúster ONOS 2.7\nONOS-1 + ONOS-2\nAtomix ×3 (Raft)\napps: AAA, inband, REST', colors.HexColor('#EEF4FB'), tam=6.8)
    caja(d, 404, 150, 100, 44, 'identity (Python)\nREST :5001 en ONOS-1\nsesiones · R2/R3/R4', colors.HexColor('#F1F8F1'), tam=6.8)
    caja(d, 270, 40, 112, 48, 'FreeRADIUS 3.2 + OpenLDAP\nEAP-TLS · ppolicy · CRL\ng05-bloqueo (R1-03)', colors.white, tam=6.8)
    caja(d, 404, 40, 100, 48, 'Kea DHCPv4\nsubred por rol\nhook run_script', colors.white, tam=6.8)
    caja(d, 130, 40, 112, 48, 'IDS Suricata 7\nfirmas R3 + R2 (generadas)\nids-agent → identity', colors.white, tam=6.8)
    caja(d, 8, 40, 92, 48, 'Core-1 (router)\nVLAN de rol → servicios\nnftables · dhcrelay', colors.white, tam=6.8)
    flecha(d, 100, 172, 130, 172, texto='EAPOL', dy=10)
    flecha(d, 242, 180, 270, 180, texto='OpenFlow', dy=10)
    flecha(d, 270, 164, 242, 164)
    flecha(d, 382, 176, 404, 176, texto='REST', dy=10)
    flecha(d, 404, 164, 382, 164)
    flecha(d, 326, 140, 326, 88, texto='RADIUS (AAA)', dx=26)
    flecha(d, 360, 88, 420, 150, texto='post-auth REST', dx=24, dy=-8)
    flecha(d, 454, 88, 454, 150, texto='concesiones', dx=24)
    flecha(d, 186, 140, 186, 88, color=ROJO, guion=[3, 2], texto='espejo GRE', dx=-22)
    flecha(d, 242, 64, 404, 160, color=ROJO, texto='alertas (gestión)', dx=-34, dy=8)
    flecha(d, 160, 140, 80, 88, texto='VLAN = rol×100', dx=-30, dy=-4)
    d.add(String(255, 230, 'Plano de datos (OVS) · plano de control (ONOS/Atomix, in-band) · servicios y microservicios (Python, REST)',
                 fontName='Arial-B', fontSize=7, textAnchor='middle', fillColor=AZUL))
    d.add(String(255, 14, 'Las flechas rojas discontinuas viajan por la red de gestión (GRE y alertas).',
                 fontName='Arial', fontSize=6.5, textAnchor='middle', fillColor=colors.HexColor('#374151')))
    return d


def diagrama_flujo(pasos, ramas, W=510, titulo=None):
    """pasos: lista vertical de (texto, color); ramas: [(indice, texto_flecha, texto_caja, color)]."""
    h, gap = 30, 14
    H = len(pasos) * (h + gap) + 20
    d = Drawing(W, H)
    x, w = 40, 250
    ys = []
    for i, (t, c) in enumerate(pasos):
        y = H - 20 - (i + 1) * h - i * gap
        ys.append(y)
        caja(d, x, y, w, h, t, colors.HexColor(c), tam=7)
        if i:
            flecha(d, x + w / 2, ys[i - 1], x + w / 2, y + h)
    for i, tf, tc, c in ramas:
        y = ys[i]
        caja(d, x + w + 70, y, 140, h, tc, colors.HexColor(c), tam=6.8)
        flecha(d, x + w, y + h / 2, x + w + 70, y + h / 2, texto=tf, dy=3)
    if titulo:
        d.add(String(x, H - 10, titulo, fontName='Arial-B', fontSize=7.5, fillColor=AZUL))
    return d


# ------------------------------------------------------------------ datos
pol, topo = r2ctl.load()
ROLES = [r for r in (5, 4, 3, 2, 1, 9) if r in pol['roles']] + [r for r in sorted(pol['roles']) if r not in (5, 4, 3, 2, 1, 9)]
NOMBRE_ROL = {r: pol['roles'][r]['nombre'] for r in ROLES}


def resultados_pytest():
    """{nombre_de_test (sin parámetros): PASS|FAIL|NT} desde la salida de pytest -v."""
    res = {}
    for l in leer('pytest.txt').splitlines():
        m = re.match(r'\S+::(\w+)(\[[^\]]*\])?\s+(PASSED|FAILED|SKIPPED|ERROR)', l)
        if m:
            nombre, est = m.group(1), m.group(3)
            est = {'PASSED': 'PASS', 'FAILED': 'FAIL', 'ERROR': 'FAIL', 'SKIPPED': 'NT'}[est]
            prev = res.get(nombre)
            res[nombre] = est if prev in (None, est) else ('FAIL' if 'FAIL' in (prev, est) else 'NT')
    return res


RES = resultados_pytest()


def estado(tests):
    est = [RES.get(t, 'NT') for t in tests]
    return 'FAIL' if 'FAIL' in est else ('NT' if 'NT' in est else 'PASS')


def resumen_pytest():
    m = re.search(r'=+ (.*?(passed|failed).*?) in ([\d.]+)s', leer('pytest.txt'))
    return m.group(1) if m else 'sin datos de pytest'


# ------------------------------------------------------------------ fichas
FICHAS = [
    # (caso, código, título, tipo, objetivo, prerrequisitos, procedimiento, esperado, tests, evidencia, comentario)
    ('1.1.1', 'R1-01', 'Autenticación de un usuario válido con su rol', 'Unitaria · caso normal',
     'Verificar que el módulo de autenticación (FreeRADIUS con EAP-TLS y LDAP) acepta a un usuario registrado y '
     'activo, y que identity devuelve su identificador y el rol asignado.',
     'FreeRADIUS y OpenLDAP activos en ldap-radius; certificados de alu01, doc01, adm01 y admin01 firmados por la CA del '
     'campus; cliente RADIUS local de pruebas (127.0.0.1). identity importado con estado en un directorio temporal.',
     '1. Autenticar con eapol_test a cada usuario con su propio certificado.<br/>2. Leer el Access-Accept y el atributo '
     'Tunnel-Private-Group-Id (VLAN = rol×100).<br/>3. Entregar a identity la respuesta de RADIUS (VLAN 300) y la '
     'aprobación de AAA para doc01.',
     'Access-Accept con VLAN 200, 300, 400 y 500 respectivamente. identity crea la sesión con usuario = doc01 y rol 3, '
     'sin registrar rechazos.',
     ['test_1_1_1_R1_01_usuario_valido_recibe_aceptacion_y_vlan_de_su_rol', 'test_1_1_1_R1_01_usuario_valido_obtiene_identidad_y_rol'],
     'pytest -v (test_lab7_slice.py y test_lab7.py); radius.log «Login OK: [alu01]».',
     'Función referencial validate_credentials: en G05 la credencial es un certificado X.509 (EAP-TLS) y la valida '
     'FreeRADIUS; el rol lo da el grupo LDAP. Criterio R1: flujo completo de usuario válido y asignación usuario-rol.'),
    ('1.1.2', 'R1-02', 'Rechazo uniforme de credenciales inválidas y entradas maliciosas', 'Unitaria · caso inválido',
     'Comprobar que todo intento inválido se rechaza sin interrumpir el módulo, con el mismo mensaje (no revela si la '
     'cuenta existe) y sin asignar rol.',
     'Certificados de prueba en ldap-radius: usuario inexistente (fantasma01), CA ajena, caducado y revocado por CRL.',
     '1. Autenticar 10 casos: certificado de otro usuario (alu01 como admin01), usuario inexistente, CA ajena, caducado, '
     "revocado, identidad vacía, <font name='Mono'>' OR '1'='1</font>, <font name='Mono'>*</font>, "
     "<font name='Mono'>alu01)(uid=*</font> y usuario sin grupo.<br/>2. Comparar la respuesta y los atributos.<br/>"
     '3. Probar que el módulo de bloqueo descarta nombres vacíos, inyecciones y saltos de línea.',
     'Los 10 reciben Access-Reject con los mismos atributos (EAP-Failure + Message-Authenticator), sin VLAN ni '
     'Reply-Message. Las entradas maliciosas no cuentan ni reinician ninguna cuenta.',
     ['test_1_1_2_R1_02_todos_los_intentos_invalidos_reciben_el_mismo_rechazo', 'test_1_1_2_R1_02_entradas_maliciosas_no_se_procesan',
      'test_1_1_2_R1_02_un_nombre_con_salto_de_linea_no_fabrica_lineas', 'test_1_1_2_R1_02_sin_respuesta_de_radius_no_hay_sesion_ni_rol'],
     'pytest -v; radius.log con el motivo real de cada rechazo (Anexo B).',
     'Defecto encontrado y corregido con esta prueba: un usuario inexistente se rechazaba sin EAP-Message y un '
     'certificado inválido con él, lo que permitía enumerar cuentas. Ahora la existencia y el bloqueo se comprueban en '
     'post-auth y REJECT lleva EAP-Failure. Criterio R1: flujo completo de usuario inválido.'),
    ('1.1.3', 'R1', 'Soporte multirol', 'Unitaria · caso normal',
     'Verificar que un usuario con varios roles recibe el de mayor privilegio.',
     'multi01 en los grupos LDAP net-docente y net-admin, con su certificado.',
     '1. Autenticar multi01 con eapol_test.<br/>2. Leer la VLAN de la respuesta.',
     'Access-Accept con VLAN 500 (admin), no 300 (docente).',
     ['test_1_1_3_R1_multirol_recibe_el_rol_de_mayor_privilegio'],
     'pytest -v; en el slice, multi01 por 802.1X real recibe el rol 5 y accede a Matrícula (crítico).',
     'Precedencia en post-auth: admin > administrativo > docente > alumno. Criterio R1: soporte multirol.'),
    ('1.2.1', 'R1-03', 'Bloqueo de la cuenta al N.º intento fallido (N = 5)', 'Unitaria · caso límite',
     'Validar que register_failed_attempt / is_locked mantienen la cuenta habilitada con N−1 fallos y la bloquean al '
     'llegar a N fallos seguidos en 15 min, durante 15 min.',
     'g05-bloqueo con LIMITE = 5, VENTANA = 900 s, DURACION = 900 s; en el slice, usuario de prueba prueba01.',
     '1. Registrar 4 fallos y consultar is_locked.<br/>2. Registrar el 5.º fallo y consultar.<br/>3. Intentar con el '
     'certificado correcto.<br/>4. Avanzar el reloj 899 s y 900 s.<br/>5. En el slice: 4 rechazos, estado, 5.º rechazo, '
     'estado y acceso con su certificado; comprobar pwdAccountLockedTime en LDAP.',
     'Tras 4 fallos sigue habilitada. Al 5.º queda bloqueada, rechaza incluso su certificado válido y vence a los 900 s '
     'con el contador a cero. Fallos fuera de la ventana o tras un acierto no suman.',
     ['test_1_2_1_R1_03_cuatro_fallos_no_bloquean_el_quinto_si', 'test_1_2_2_R1_03_bloqueada_rechaza_incluso_un_acceso_correcto_y_vence_a_los_15_min',
      'test_1_2_3_R1_03_fallos_fuera_de_la_ventana_o_tras_un_acierto_no_suman', 'test_1_2_1_R1_03_quinto_fallo_bloquea_la_cuenta_incluso_con_su_certificado'],
     'pytest -v; journal de g05-bloqueo (FALLO 1..5, BLOQUEO) y radius.log «cuenta bloqueada por intentos fallidos».',
     'Con EAP-TLS no hay contraseña: el fallo es un Access-Reject. Política igual a la ppolicy de LDAP '
     '(pwdMaxFailure 5, 900 s). Criterio R1: intentos fallidos registrados y cuarentena de la cuenta.'),
    ('2.1.1', 'R2-01', 'Decisión de acceso a un recurso crítico', 'Unitaria · caso normal / inválido',
     'Verificar que evaluate_access permite al Administrador el recurso crítico G04 (Matrícula) y lo deniega al Docente '
     'indicando el motivo.',
     'policy.yaml cargado (roles 1, 2, 3, 4, 5, 9; G04 nivel crítico).',
     '1. evaluate_access(5, "G04").<br/>2. evaluate_access(3, "G04").<br/>3. evaluate_access(3, "G06", "tcp", 22).',
     '(PERMIT, motivo) para el admin; (DENY, «sin permiso sobre G04 … nivel critico») para el docente; DENY por servicio '
     'no ofrecido en G06/22.',
     ['test_2_1_1_R2_01_admin_entra_al_recurso_critico_y_el_docente_no', 'test_2_1_2_R2_01_servicio_no_ofrecido_se_deniega'],
     'pytest -v; en el slice, matriz de 216 pruebas con 142/142 bloqueos.',
     'Función real r2ctl.evaluate_access. Criterio R2: acceso consistente con la política.'),
    ('2.1.3', 'R2-02', 'Denegación por defecto de rol o recurso no registrado', 'Unitaria · caso límite',
     'Confirmar que un rol inexistente o un recurso fuera del inventario se deniega por defecto, sin excepciones.',
     'policy.yaml con defecto: denegar.',
     "1. evaluate_access con roles 'Invitado', 99 y None.<br/>2. Con recursos 'consola_inexistente', None y 'g10'.<br/>"
     '3. allowed() con una IP de la intranet sin recurso y con un rol inexistente.',
     'Todas devuelven DENY con motivo «no registrado: denegado por defecto»; allowed() devuelve False.',
     ['test_2_1_3_R2_02_rol_o_recurso_no_registrado_se_deniega_por_defecto', 'test_2_1_4_R2_02_ip_fuera_del_inventario_se_deniega'],
     'pytest -v (6 + 1 casos).',
     'Antes del Lab 7, un rol desconocido lanzaba KeyError en el oráculo; se corrigió. Criterio R2: fallo seguro.'),
    ('2.2.1', 'R2-03', 'Traducción de políticas: PERMIT y DENY sobre el mismo recurso', 'Unitaria · caso normal',
     'Verificar que la traducción a OpenFlow genera reglas con su tráfico, acción y prioridad, y que si un permiso y una '
     'denegación coinciden prevalece la denegación.',
     'Copia de policy.yaml con el docente que permite G07 y además lo deniega (deniega: [G07]).',
     '1. Compilar las reglas de R-SW1 (r2ctl.compile_all).<br/>2. Comparar prioridades de las reglas de T4 sobre el '
     'prefijo de G07 (VLAN 300).<br/>3. Simular paquetes del docente a G07 (443 y 22) y a G06 (443).<br/>4. Repetir con '
     'el admin (permiso total) y deniega: [G05].',
     'Descarte con prioridad 29950 > permiso 25000; los paquetes a G07 se descartan en la regla «deniega docente -> G07» y '
     'G06 sigue permitido. El DENY explícito también gana al permiso total (29900). Las 216 combinaciones coinciden con la '
     'decisión de la política.',
     ['test_2_2_1_R2_03_permit_y_deny_sobre_el_mismo_recurso_prevalece_deny', 'test_2_2_2_R2_03_deny_explicito_gana_tambien_al_permiso_total',
      'test_2_2_3_R2_03_la_politica_compilada_coincide_con_la_decision'],
     'pytest -v; reglas T4 reales del alumno en R-SW1 (Anexo B).',
     'El simulador recorre las tablas como OVS (mayor prioridad gana). Criterio R2: permitir y denegar mediante flows.'),
    ('2.3.1', 'R2', 'Registro de accesos a recursos', 'Unitaria · caso normal',
     'Comprobar que se registran los accesos permitidos y los denegados con usuario, rol, MAC y destino, sin bloquear.',
     'identity con una sesión de alu01; firmas de R2 generadas desde policy.yaml (sid 2000000–2999999).',
     '1. Entregar a identity una alerta de acceso permitido (G10) y una de intento denegado (G04).<br/>2. Leer el registro.',
     'Eventos ACCESO_PERMITIDO e INTENTO_DENEGADO con usuario alu01 y recurso; ningún bloqueo.',
     ['test_2_3_1_R2_registro_de_accesos_permitidos_y_denegados', 'test_intento_denegado_se_registra_sin_bloquear'],
     'pytest -v; en el slice, 53/53 intentos de la matriz registrados con su usuario y 0 falsos.',
     'Criterio R2: registro de logs de acceso a recursos.'),
    ('3.1.1', 'R3-01', 'Escaneo de puertos en el límite del umbral', 'Unitaria · límite / falso positivo',
     'Validar que la firma de escaneo de puertos no alerta por debajo del umbral y alerta al alcanzarlo, identificando '
     'origen y destino; y que el tráfico legítimo no alerta.',
     'Suricata 7 del IDS con g05.rules (sid 1000001: SYN a puertos no ofrecidos, detection_filter count 10 en 5 s).',
     '1. Captura con 10 SYN a puertos distintos no ofrecidos en 2 s; suricata -r.<br/>2. Captura con 11 SYN.<br/>3. '
     'Captura con 15 SYN a 22/53/80/443.',
     '10 SYN: sin alerta. 11 SYN: una alerta 1000001 con src 10.20.0.150 y dst 10.100.1.150. 15 SYN legítimos: ninguna '
     'alerta de R3.',
     ['test_3_1_1_R3_01_escaneo_de_puertos_en_el_umbral', 'test_3_1_2_R3_01_trafico_legitimo_a_puertos_ofrecidos_no_alerta'],
     'pytest -v (capturas sintéticas, pcap.py).',
     'Umbral medido: detection_filter alerta en la coincidencia N+1. Criterios R3: umbrales, detección con origen y '
     'destino, tráfico legítimo sin bloqueo.'),
    ('3.1.3', 'R3-02', 'Escaneo de red', 'Unitaria · caso normal / límite',
     'Comprobar que un barrido a muchos equipos genera alerta que identifica al origen.',
     'Firmas 1000002 (ICMP echo, 15 en 5 s) y 1000003 (SYN a destinos fuera de los servicios, 10 en 5 s).',
     '1. Barrido ICMP a 15 hosts en 3 s.<br/>2. A 16 hosts.<br/>3. SYN a 11 hosts de otra subred.',
     '15 hosts: sin alerta; 16: alerta 1000002; 11 hosts TCP: alerta 1000003; todas con src = atacante.',
     ['test_3_1_3_R3_02_escaneo_de_red_identifica_al_origen'],
     'pytest -v; en el slice, nmap -sn bloqueado en 0,8 s.',
     'Criterio R3: amenazas definidas y detección de origen.'),
    ('3.1.5', 'R3-03', 'Suplantación de IP (terna puerto–MAC–IP)', 'Unitaria · caso normal / inválido',
     'Verificar que, por un mismo puerto y MAC, solo el paquete con IP de origen ajena se descarta y genera la alerta '
     'de spoofing, y que el sensor bloquea al superar el umbral.',
     'Sesión de alu01 (10.20.0.150) en R-SW1/4; reglas T1 compiladas; sensor de identity con umbral 3 paquetes en 10 s.',
     '1. Simular un paquete con la IP registrada y otro con 10.20.0.99.<br/>2. Simular lecturas de ONOS del contador '
     'de spoofing (0, 2, 3) y (1 cada 12 s).',
     'El legítimo pasa; el falso se descarta y cuenta en «T1 R3 spoofing detectado». Con 2 paquetes no hay bloqueo; con '
     '3 en la ventana sí. Paquetes sueltos fuera de la ventana no bloquean.',
     ['test_3_1_3_R3_03_solo_el_paquete_con_ip_ajena_es_spoofing', 'test_3_1_3_R3_03_el_sensor_alerta_al_superar_el_umbral',
      'test_3_1_3_R3_03_paquetes_sueltos_fuera_de_la_ventana_no_bloquean'],
     'pytest -v; en el slice, hping3 -c 3 -a 10.20.0.77 bloquea a alu01 a los ~6 s.',
     'Defecto encontrado en el slice: con hping3 -c 3 el sensor (diferencia de 2 s) no detectaba porque ONOS reparte los '
     '3 paquetes en dos lecturas; se pasó a una ventana de 10 s. Criterio R3: IP spoofing.'),
    ('3.1.6', 'R3-04', 'Requests maliciosos «todos contra uno»', 'Unitaria · caso normal',
     'Comprobar que uno o varios clientes que envían solicitudes a un mismo servidor sobre el umbral generan alerta que '
     'los identifica.',
     'Firma 1000020 (GET HTTP, 40 en 10 s por origen).',
     '1. Captura con 40 sesiones HTTP de un cliente en 8 s.<br/>2. Con 41 sesiones de dos clientes distintos.',
     '40: sin alerta. 41 de cada cliente: alertas con los dos orígenes y el mismo destino.',
     ['test_3_1_4_R3_04_rafaga_de_requests_todos_contra_uno'],
     'pytest -v; en el slice, ráfaga de 60 requests bloqueada en 0,9 s.',
     'El ataque distribuido por volumen lo cubre además R4 (test_ataque_distribuido_identifica_a_los_que_aportan). '
     'Criterio R3: detección del ataque.'),
    ('3.2.1', 'R3-05', 'Regla de bloqueo selectiva con expiración', 'Unitaria · caso normal',
     'Verificar que la alerta confirmada genera una regla que descarta solo el tráfico del atacante, con prioridad y '
     'tiempo de expiración, sin afectar a otros equipos del mismo puerto.',
     'Dos sesiones en R-SW1/4: atacante bloqueado y vecino legítimo; identity con BLOCK_TTL = 300 s.',
     '1. Compilar T2 y revisar criterios, acción y prioridad.<br/>2. Simular tráfico de ambos.<br/>3. Bloquear y llamar '
     'a identity.vencer a los 299 s y a los 301 s.',
     'Una regla T2 prioridad 40000 con in_port + eth_src del atacante y acción descartar, sin comodines; el vecino sigue '
     'pasando. A los 299 s sigue bloqueado; a los 301 s se retira (BLOQUEO_VENCIDO, acción REGLA_T2_RETIRADA).',
     ['test_3_2_1_R3_05_regla_de_bloqueo_solo_para_el_atacante', 'test_3_2_2_R3_05_el_bloqueo_expira_y_la_regla_se_retira'],
     'pytest -v; regla real en R-SW1 «priority=40000,in_port=4,dl_src=… actions=drop» (Anexo B).',
     'La expiración la gestiona identity (no hard_timeout) para poder renovar el bloqueo ante reincidencia y pasar a '
     'cuarentena a la 3.ª alerta. Criterio R3: bloqueo mediante flows.'),
    ('3.3.1', 'R3-06', 'Registro del incidente', 'Unitaria · caso normal',
     'Confirmar que el incidente detectado y mitigado queda registrado con fecha y hora, tipo de ataque, origen, destino '
     'y acción aplicada.',
     'identity con registro de seguridad en un archivo temporal.',
     '1. Entregar una alerta de escaneo de puertos de alu01 hacia 10.100.1.150:1011.<br/>2. Leer ALERTA_IDS y BLOQUEO.',
     'Fecha ISO-8601, firma (tipo), src_ip y usuario, dst 10.100.1.150:1011/TCP, acción REGLA_T2_DROP con TTL 300.',
     ['test_3_3_1_R3_06_incidente_con_fecha_tipo_origen_destino_y_accion'],
     'pytest -v; /var/log/g05/incidentes.jsonl y pruebas/incidentes.sh (Anexo B).',
     'Criterio R3: logs de incidentes.'),
]


# ------------------------------------------------------------------ documento
def portada(story):
    story += [Spacer(1, 3.2 * cm), P('TEL354 · Redes Definidas por Software', 'sub'), Spacer(1, 6),
              P('Experiencia de Laboratorio 7', 'tit'),
              P('Diseño, implementación y unit testing de los módulos del proyecto', 'sub'), Spacer(1, 1.2 * cm),
              P('Red de campus SDN con control in-band y alta disponibilidad', 'sub'),
              P('R1 · R2 · R3 (requerimiento específico) · R4 (adicional)', 'sub'), Spacer(1, 1.6 * cm)]
    integ = '<br/>'.join(INTEGRANTES) if INTEGRANTES else '<font color="#B42318">(completar en INTEGRANTES)</font>'
    filas = [['Grupo', 'G05'], ['Integrantes', integ], ['Profesor', 'Christian Quispe Ordoñez'],
             ['Jefe de práctica', 'William D. Lavado Gonzales'], ['Semestre', '2026-2'],
             ['Fecha', date.today().strftime('%d/%m/%Y')], ['Repositorio', f'<link href="{REPO}">{REPO}</link>']]
    story.append(tabla(filas, [4 * cm, 10 * cm], cab=False,
                       estilo_extra=[('BACKGROUND', (0, 0), (0, -1), AZUL_C), ('FONTNAME', (0, 0), (0, -1), 'Arial-B')]))
    story.append(PageBreak())


def seccion_1(story):
    story.append(P('1. Arquitectura del sistema', 'h1'))
    story.append(P('La solución separa tres planos. El <b>plano de datos</b> son seis switches Open vSwitch con OpenFlow '
                   '1.3. El <b>plano de control</b> es un clúster ONOS 2.7 de dos nodos sobre Atomix (Raft, tres '
                   'votantes, uno por dominio de falla) que controla los switches <b>in-band</b>, por los mismos enlaces '
                   'de datos. Los <b>servicios y microservicios</b> (Python, systemd) se comunican por REST: identity '
                   'une la autenticación 802.1X, el rol y la IP, y programa en ONOS la política de R2 y las mitigaciones '
                   'de R3 y R4.', 'n'))
    story += [diagrama_arquitectura(), P('Figura 1. Arquitectura lógica y comunicación entre módulos.', 'cap')]
    story.append(P('Módulos y despliegue', 'h2'))
    story.append(tabla([
        ['Módulo', 'Dónde corre', 'Responsabilidad'],
        ['ONOS 2.7 (Docker) + Atomix 3.1.5', 'onos-1, onos-2, atomix-3', 'Control OpenFlow, app AAA (802.1X), app org.g05.inband, REST'],
        ['identity (identity.py, REST :5001)', 'ONOS-1, g05-identity.service', 'Sesiones 802.1X + rol + IP; reconciliación de reglas (R2); alertas, bloqueos y cuarentena (R3); monitor y meters (R4); registro de seguridad'],
        ['r2ctl.py', 'Biblioteca de identity / CLI', 'Compilador de policy.yaml a 6 tablas OpenFlow; evaluate_access; generador de firmas de R2 para Suricata'],
        ['aaa-agent.py', 'ONOS-1 y ONOS-2', 'Reenvía a identity los eventos AAA del log del master'],
        ['FreeRADIUS 3.2 + OpenLDAP 2.6', 'ldap-radius', 'EAP-TLS, CN = identidad, CRL, ppolicy; rol por grupo (VLAN = rol×100)'],
        ['g05-bloqueo.py', 'ldap-radius', 'R1-03: bloqueo por intentos fallidos (pwdAccountLockedTime)'],
        ['Kea DHCPv4 + dhcrelay', 'dns-dhcp, Core-1', 'Subred por rol; avisa cada concesión a identity'],
        ['Suricata 7 + ids-agent.py', 'IDS', 'Firmas R3 y R2 sobre el espejo GRE; alertas a identity'],
        ['g05-redundancia.py', 'Los 6 switches', 'BFD + grupos Fast Failover del canal de control'],
    ], [4.2 * cm, 3.8 * cm, 9 * cm]))
    story.append(Spacer(1, 6))
    story += lista([
        '<b>Despliegue:</b> Ansible desde el Gateway (bootstrap in-band, redundancia, servicios y clúster) y scripts '
        'idempotentes por servicio (r1-identidad.sh, ids-setup.sh, instalar-identity.sh). Cada módulo es un servicio '
        'systemd con reinicio automático; las VMs no tienen Internet y los paquetes se instalan con dpkg.',
        '<b>Operación normal:</b> identity reconcilia las reglas ante cada evento (login, DHCP, alerta, límite); los '
        'servicios guardan su estado en disco (sesiones, bloqueos) y se recuperan tras un reinicio.',
        '<b>Actualización de un módulo:</b> se copia el archivo y se reinicia solo su servicio. Las sesiones persisten; '
        'el reinicio de identity reinstala las reglas desde el estado guardado. Antes, las 125 pruebas unitarias.',
    ])
    story.append(P('API REST de identity (expuesta e implementada)', 'h2'))
    story.append(tabla([
        ['Método y ruta', 'Quién la usa', 'Función'],
        ['POST /identity/sessions', 'FreeRADIUS (post-auth)', 'Respuesta de RADIUS: usuario y VLAN'],
        ['POST /identity/aaa', 'aaa-agent', 'Eventos AAA (APPROVED, DENIED, IDLE…)'],
        ['POST /identity/dhcp', 'Kea (hook)', 'Concesión o liberación de IP'],
        ['POST /identity/alert', 'ids-agent', 'Alerta de Suricata (R3 bloquea; R2 solo registra)'],
        ['POST /identity/cuenta', 'g05-bloqueo', 'Fallo, bloqueo o desbloqueo de cuenta (R1-03)'],
        ['GET /identity/sessions', 'Administración', 'Sesiones activas'],
        ['POST|DELETE /identity/block/&lt;mac&gt;', 'Administración (local)', 'Bloqueo manual / levantar (R3)'],
        ['POST|DELETE /identity/limit/&lt;mac&gt;', 'Administración (local)', 'Límite manual / levantar (R4)'],
        ['GET /identity/incidents?desde=', 'incidentes.sh', 'Registro de seguridad persistente'],
        ['GET /identity/accesos, /intentos, /trafico', 'Administración', 'Accesos permitidos, denegados y tasas en vivo (R4)'],
    ], [5.2 * cm, 3.6 * cm, 8.2 * cm]))
    story.append(P('Cada origen solo puede llamar lo suyo (FreeRADIUS solo /sessions y /cuenta, el IDS solo /alert, Kea '
                   'solo /dhcp); la administración solo desde 127.0.0.1 en ONOS-1. Verificado por 11 casos de prueba.', 'n'))
    story.append(PageBreak())


def seccion_2(story):
    story.append(P('2. Diagrama de red de la topología implementada', 'h1'))
    story += [diagrama_red(), P('Figura 2. Topología del slice (15 VMs en tres dominios de falla).', 'cap')]
    story.append(tabla([
        ['Red', 'Direccionamiento', 'Uso'],
        ['Gestión (out-of-band)', '192.168.0.0/24 en ens3', 'SSH/Ansible; clúster ONOS (9876) y Atomix (5679); RADIUS; alertas; espejo GRE'],
        ['Control (in-band)', '10.100.0.0/28: br0 de los switches .3–.8, ONOS-1 .2, ONOS-2 .9', 'OpenFlow 1.3 (TCP 6653) y ARP por los enlaces de datos'],
        ['Usuarios (VLAN = rol×100)', '10.10 / 10.20 / 10.30 / 10.40 / 10.50 / 10.90.0.0/24 (gateway .1 en Core-1)', 'Tráfico de usuarios entre R-SW1 y Core-1'],
        ['Servicios', 'g02 10.100.0.16/28 (LDAP/RADIUS), g11 10.100.1.128/28 (DNS/DHCP), srv (recursos)', 'Segmentos VLAN 112, 111 y 113 hacia DC-DIST'],
    ], [3.4 * cm, 6.8 * cm, 6.8 * cm]))
    story.append(Spacer(1, 6))
    story += lista([
        'Cada switch tiene dos controladores (10.100.0.2 y 10.100.0.9). Los enlaces redundantes llevan BFD (100 ms) y '
        'grupos Fast Failover: la caída de un enlace o de Core-1 no corta ninguna sesión OpenFlow.',
        'R-SW1 es el switch de acceso: puerto 4 = usuarios (VM Alumno, 6 equipos en namespaces), 3 = IDS, 1/2 = Core-1/Core-2.',
        'El VNRT no entrega al IDS las tramas unicast ajenas por el enlace directo, por eso el espejo de R-SW1 viaja en GRE '
        '(key 4735) por la red de gestión.',
    ])
    story.append(PageBreak())


def seccion_3_4(story):
    story.append(P('3. Definición de roles y recursos', 'h1'))
    filas = [['Rol', 'Nombre', 'VLAN', 'Subred', 'Grupo LDAP', 'Usuario de prueba']]
    grupos = {5: 'net-admin', 4: 'net-administrativo', 3: 'net-docente', 2: 'net-alumno', 1: '(invitado, sin 802.1X)', 9: '(reincidencia R3)'}
    usuarios = {5: 'admin01, multi01', 4: 'adm01', 3: 'doc01, multi01', 2: 'alu01, prueba01', 1: 'invitado', 9: '—'}
    for r in ROLES:
        filas.append([str(r), NOMBRE_ROL[r], str(r * 100), r2ctl.subred_rol(r), grupos.get(r, ''), usuarios.get(r, '')])
    story.append(tabla(filas, [1.1 * cm, 2.8 * cm, 1.3 * cm, 2.8 * cm, 4 * cm, 5 * cm]))
    story.append(P('sing01 existe en LDAP pero no tiene grupo de red: se rechaza. Los usuarios se almacenan en OpenLDAP '
                   '(ou=people) y su credencial es un certificado X.509 de la CA del campus.', 'n'))
    filas = [['Id', 'Recurso', 'Clasificación', 'Prefijo', 'Servicios']]
    clasif = {'critico': 'Crítico (privilegiado)', 'intermedio': 'Intermedio (privilegiado)', 'general': 'General'}
    for g, rec in pol['recursos'].items():
        filas.append([g, rec['nombre'], clasif[rec['nivel']], rec['prefijo'], ', '.join(rec.get('servicios', [])) or 'todos'])
    story.append(tabla(filas, [1.2 * cm, 3 * cm, 4 * cm, 3.6 * cm, 5.2 * cm]))
    story.append(P(f"El bloque crítico {pol['bloque_critico']} (G01–G05) se descarta con muestreo al controlador "
                   '(meter de 10 pps). G01 (ONOS) queda fuera de la matriz: el plano de control no acepta tráfico de usuarios.', 'n'))

    story.append(P('4. Políticas de acceso a recursos', 'h1'))
    story.append(P('Matriz generada desde policy.yaml con r2ctl.evaluate_access (P = permitido, — = denegado; '
                   '* = solo los servicios del recurso; † = permitido en el switch por el permiso total, pero el firewall '
                   'de Core-1 descarta todo tráfico de usuarios hacia el plano de control).', 'n'))
    gs = list(pol['recursos'])
    filas = [['Rol'] + gs + ['Internet']]
    est = []
    for i, r in enumerate(ROLES, start=1):
        fila = [f'{r} {NOMBRE_ROL[r]}']
        for j, g in enumerate(gs, start=1):
            d, _ = r2ctl.evaluate_access(pol, r, g)
            serv = pol['recursos'][g].get('servicios') and pol['roles'][r]['permite'] != 'todo'
            if g == 'G01' and d == 'PERMIT':          # plano de control: lo corta Core-1
                fila.append('P†')
                est.append(('BACKGROUND', (j, i), (j, i), colors.HexColor('#FDF3E1')))
                continue
            fila.append('P*' if d == 'PERMIT' and serv else ('P' if d == 'PERMIT' else '—'))
            est.append(('BACKGROUND', (j, i), (j, i), colors.HexColor('#E7F5EC') if d == 'PERMIT' else colors.HexColor('#FBEAEA')))
        inet = pol['roles'][r].get('internet')
        fila.append('P' if inet else '—')
        est.append(('BACKGROUND', (len(gs) + 1, i), (len(gs) + 1, i), colors.HexColor('#E7F5EC') if inet else colors.HexColor('#FBEAEA')))
        filas.append(fila)
    story.append(tabla(filas, [2.9 * cm] + [1.03 * cm] * len(gs) + [1.4 * cm], estilo_extra=est))
    story.append(Spacer(1, 6))
    story.append(P('Precedencia y multirol', 'h2'))
    story += lista([
        '<b>Multirol:</b> un usuario puede pertenecer a varios grupos LDAP; FreeRADIUS asigna el de mayor privilegio '
        '(admin > administrativo > docente > alumno). multi01 (docente y admin) recibe la VLAN 500.',
        '<b>Por defecto se deniega:</b> todo rol o recurso no registrado es DENY.',
        '<b>DENY prevalece sobre PERMIT:</b> una denegación explícita del rol (deniega: [G..]) se instala en T4 con '
        'prioridad 29950, por encima de cualquier permiso, incluido el permiso total del admin (29900).',
        '<b>Admin:</b> permiso total en el switch; el acceso a la gestión, al plano de control y al propio Core-1 lo corta '
        'el firewall nftables de Core-1.',
        '<b>Cambio en caliente:</b> se edita policy.yaml y se aplica con r2ctl apply (o la reconcilia identity); OVS tiene '
        'las reglas en menos de 1 s.',
    ])
    story.append(tabla([
        ['Tabla', 'Función', 'Prioridades'],
        ['T0', 'Ingreso: LLDP/EAPOL al controlador; ventana DHCP con la VLAN del rol; usuarios a T1', '65100 · 65000 · 64000 · 60000'],
        ['T1', 'Anti-spoofing: puerto + MAC + IP; sensor de IP ajena (R3)', '50000 · 45000'],
        ['T2', 'Mitigación: bloqueo de R3 (descarte) y límite de R4 (meter)', '40000 · 39000 · 1'],
        ['T3', 'Identidad: MAC → push VLAN del rol', '35000'],
        ['T4', 'Política por rol: deniega · total · ARP · permisos · crítico (meter + controlador) · intranet · Internet', '29950 · 29900 · 29800 · 25000 · 23000 · 22000 · 21000'],
        ['T5', 'Salida a Core-1 con la VLAN del rol y entrega a cada usuario por MAC', '10100 · 10050 · 10000'],
    ], [1.3 * cm, 10.4 * cm, 5.3 * cm]))
    story.append(PageBreak())


def seccion_5(story):
    story.append(P('5. Diseño del módulo del requerimiento específico (R3)', 'h1'))
    story.append(P('Objetivo: detectar y mitigar ataques encubiertos desde usuarios ya autenticados de la intranet '
                   '(reconocimiento, suplantación y abuso de servicios), bloqueando solo al atacante y registrando el '
                   'incidente, sin afectar al tráfico legítimo.', 'n'))
    story.append(tabla([
        ['Amenaza', 'Mecanismo de detección', 'Umbral (medido)'],
        ['Escaneo de puertos', 'Suricata sid 1000001: SYN a puertos no ofrecidos (≠ 22, 53, 80, 443)', '11 SYN en 5 s (10 no alertan)'],
        ['Escaneo de red (ICMP)', 'sid 1000002: echo request desde un usuario', '16 en 5 s'],
        ['Escaneo de red (TCP)', 'sid 1000003: SYN a destinos fuera de los servicios', '11 en 5 s'],
        ['IP spoofing externo', 'sid 1000004: origen fuera de las subredes del campus', '1 paquete'],
        ['IP spoofing interno', 'Sensor en el switch: regla T1 «IP de origen ajena» por usuario', '3 paquetes en 10 s'],
        ['SQLi / XSS / traversal / herramientas', 'sid 1000010–1000013 sobre la URI cruda y el User-Agent', '1 request'],
        ['Todos contra uno (bot)', 'sid 1000020: GET HTTP por origen', '41 en 10 s'],
        ['Inundación de conexiones', 'sid 1000021: SYN a 80/443', '101 en 10 s'],
    ], [3.8 * cm, 8.4 * cm, 4.8 * cm]))
    story.append(Spacer(1, 6))
    pasos = [('Tráfico del puerto de usuarios de R-SW1 (ens7)', '#FFF7E6'),
             ('Espejo OVSDB → túnel GRE (key 4735) → IDS', '#F9FAFB'),
             ('Suricata 7: firmas de R3 y R2 (AF_PACKET sobre ids-gre)', '#EEF4FB'),
             ('eve.json (con MAC) → ids-agent → POST /identity/alert', '#F9FAFB'),
             ('identity: sesión 802.1X del origen (MAC o IP)', '#F1F8F1'),
             ('BLOQUEO: regla T2 descarte (40000) por ONOS, TTL 300 s', '#FBEAEA'),
             ('Registro: ALERTA_IDS + BLOQUEO + MITIGACION_APLICADA', '#F9FAFB'),
             ('Vence el TTL → BLOQUEO_VENCIDO, regla retirada', '#E7F5EC')]
    ramas = [(2, 'sid 2xxxxxx', 'R2: ACCESO_PERMITIDO /\nINTENTO_DENEGADO (sin bloqueo)', '#F9FAFB'),
             (4, 'sin sesión', 'ALERTA_SIN_ORIGEN\n(solo registro)', '#F9FAFB'),
             (5, '3.ª alerta en 10 min', 'CUARENTENA: rol 9, VLAN 900\nsolo DNS y Mesa de ayuda', '#FFF7E6'),
             (0, 'IP ajena (T1)', 'Sensor de identity: 3 paquetes\nen 10 s → mismo BLOQUEO', '#FBEAEA')]
    story += [diagrama_flujo(pasos, ramas, titulo='Flujo de detección y mitigación de R3'),
              P('Figura 3. Flujo del módulo R3.', 'cap')]
    story.append(P('Funciones y limitaciones', 'h2'))
    story += lista([
        '<b>Funciones:</b> on_alert (clasifica por sid), do_block / vencer (bloqueo y expiración), do_quarantine '
        '(reincidencia), watch_spoofing (sensor), log (registro persistente), r2ctl.compile_all (T1/T2).',
        '<b>Mitigación selectiva:</b> se bloquea la MAC autenticada (no la IP, que puede ser falsa) en el puerto del '
        'atacante; los demás usuarios del mismo puerto siguen operando.',
        '<b>Limitaciones:</b> el espejo cubre el puerto de usuarios de R-SW1; Suricata ve lo que copia el GRE por la red de '
        'gestión; el sensor de spoofing depende del sondeo de estadísticas de ONOS (5 s); el IDS no descifra TLS.',
    ])
    story.append(P('Diseño de R4 (adicional): DDoS por consumo de ancho de banda', 'h2'))
    pasos4 = [('Contadores de ONOS cada 2,5 s: T3 (envía), T5 (recibe), T4 (por recurso)', '#EEF4FB'),
              ('ddos.Detector: bit/s y paquetes/s por usuario y por recurso', '#F9FAFB'),
              ('¿Criterio A o B, 2 lecturas seguidas, y envía más de lo que recibe?', '#FFF7E6'),
              ('Meter propio de 2 Mbit/s + regla T2 (39000) para la fuente', '#FBEAEA'),
              ('Registro DDOS_DETECTADO (usuario, rol, MAC, tasas, meter)', '#F9FAFB'),
              ('Oferta < 5 Mbit/s durante 30 s → LIMITE_LEVANTADO', '#E7F5EC')]
    ramas4 = [(1, 'criterio A', 'Volumétrico: un usuario envía\n> 50 Mbit/s o > 15 000 pps', '#F9FAFB'),
              (2, 'criterio B', 'Distribuido: un recurso recibe > 80 Mbit/s;\nfuentes: quienes aporten > 10 Mbit/s', '#F9FAFB')]
    story += [diagrama_flujo(pasos4, ramas4, titulo='Flujo de R4'), P('Figura 4. Flujo del módulo R4.', 'cap')]
    story.append(PageBreak())


def ficha(f):
    caso, cod, tit, tipo, obj, pre, proc, esp, tests, evid, com = f
    est = estado(tests)
    col = {'PASS': VERDE, 'FAIL': ROJO, 'NT': AMBAR}[est]
    nombres = '<br/>'.join(f"<font name='Mono' size='6.6'>{t}</font>" for t in tests)
    filas = [['Número de caso', f'<b>{caso}</b> · {cod}'], ['Tipo de prueba', tipo], ['Objetivos', obj],
             ['Prerrequisitos', pre], ['Procedimiento', proc], ['Resultados esperados', esp],
             ['Resultado obtenido', f'<font color="{col.hexval()}"><b>{est}</b></font> — '
                                    + ('los resultados obtenidos son iguales a los esperados.' if est == 'PASS' else
                                       'ver evidencia de pytest.' if est == 'FAIL' else 'no ejecutada en esta corrida.')],
             ['Evidencias', f'{evid}<br/>{nombres}'], ['Comentarios y observaciones', com]]
    t = tabla(filas, [3.4 * cm, 13.6 * cm], cab=False,
              estilo_extra=[('BACKGROUND', (0, 0), (0, -1), AZUL_C), ('FONTNAME', (0, 0), (0, -1), 'Arial-B')])
    return KeepTogether([P(f'{caso} {tit}', 'h3'), t, Spacer(1, 6)])


def seccion_6(story):
    story.append(P('6. Plan de pruebas validado', 'h1'))
    story.append(P('Las pruebas se organizan por módulo con la nomenclatura X.Y.Z (X = módulo: 1 R1, 2 R2, 3 R3). Las '
                   'funciones del informe previo son referenciales y se mapean a las funciones reales. Las pruebas que '
                   'necesitan el FreeRADIUS o el Suricata reales prueban cada módulo aislado (eapol_test sin AAA ni ONOS; '
                   'suricata -r sobre capturas sintéticas); el resto corre sin red. El resultado obtenido de cada ficha '
                   f'sale de la corrida de pytest -v: <b>{resumen_pytest()}</b>.', 'n'))
    filas = [['Caso', 'Código', 'Prueba', 'Resultado']]
    est_t = []
    for i, f in enumerate(FICHAS, start=1):
        e = estado(f[8])
        filas.append([f[0], f[1], f[2], e])
        est_t.append(('TEXTCOLOR', (3, i), (3, i), {'PASS': VERDE, 'FAIL': ROJO, 'NT': AMBAR}[e]))
    story.append(tabla(filas, [1.4 * cm, 1.6 * cm, 11.6 * cm, 2.4 * cm], estilo_extra=est_t))
    story.append(Spacer(1, 8))
    for f in FICHAS:
        story.append(ficha(f))
    story.append(P('Pruebas adicionales', 'h2'))
    story.append(tabla([
        ['Suite', 'Pruebas', 'Qué valida'],
        ['test_r2ctl.py', '17', 'Simulador del pipeline: las 216 combinaciones de la matriz, anti-spoofing, cuarentena, DHCP, retorno, 7 reglas por sesión, firmas'],
        ['test_identity.py', '27', 'Unión RADIUS + AAA y rechazos, DHCP por subred del rol, reautenticación, cuarentena, control de origen de la API'],
        ['test_ddos.py', '12', 'R4: picos aislados, descarga legítima de 1,3 Gbit/s, flood por bps y pps, distribuido, enfriamiento, regla con meter'],
        ['test_redundancia.py', '25', 'Control in-band hacia ONOS-1 y ONOS-2 con cada enlace caído y con Core-1 caído (encontró un fallo de R-SW2, corregido)'],
        ['test_lab7*.py', '44', 'Las fichas anteriores (incluye parametrizaciones)'],
    ], [3.4 * cm, 1.6 * cm, 12 * cm]))
    story.append(PageBreak())


def seccion_7(story):
    story.append(P('7. Métricas del requerimiento específico (R3) y de R4', 'h1'))
    story.append(P('R3: ataques desde un usuario autenticado (prueba-r3.sh, corrida del 24/11/2026)', 'h2'))
    story.append(tabla([
        ['Ataque', 'Detecta', 'Atacante bloqueado a los'],
        ['Escaneo de puertos (nmap SYN, 101 puertos)', 'IDS sid 1000001', '0,8 s'],
        ['Barrido ICMP (40 hosts)', 'IDS sid 1000002', '1,1 s'],
        ['Escaneo de red TCP (nmap -sn -PS80, 64 hosts)', 'IDS sid 1000003', '0,8 s'],
        ['IP spoofing externo (198.51.100.7)', 'IDS sid 1000004', '0,3 s'],
        ['IP spoofing interno (misma subred)', 'Sensor del switch', '4,5 s (hping3 -c 3: ~6 s)'],
        ['Inyección SQL', 'IDS sid 1000010', '0,5 s'],
        ['Path traversal', 'IDS sid 1000012', '0,3 s'],
        ['Bot: 60 requests HTTP en ráfaga', 'IDS sid 1000020', '0,8 s'],
    ], [8 * cm, 4 * cm, 5 * cm]))
    story += lista([
        '<b>Tasa de detección:</b> 8/8 (100 %). <b>Falsos positivos:</b> 0 en 60 s de tráfico legítimo (Portal, Mesa de '
        'ayuda, DNS y accesos denegados por R2). El testigo (invitado en el mismo puerto) nunca perdió el servicio.',
        '<b>Tiempo de mitigación:</b> el agente reenvía la alerta en 8–102 ms y ONOS acepta la regla en 144–166 ms '
        '(MITIGACION_APLICADA): menos de 1 s desde la alerta. El resto es lo que tarda cada firma en reunir su umbral.',
        '<b>Recuperación:</b> el bloqueo vence a los 300 s (regla retirada); a la 3.ª alerta en 10 min, cuarentena.',
    ])
    story.append(P('Carga del IDS: sesiones maliciosas por segundo sin degradación (carga-ids.sh)', 'h3'))
    story.append(tabla([
        ['Sesiones/s', 'Sesiones', 'Alertas', 'Detección', 'Paquetes', 'Pérdidas', 'CPU Suricata'],
        ['10', '199', '199', '100 %', '2 057', '0', '1,3 %'], ['50', '999', '999', '100 %', '10 056', '0', '2,9 %'],
        ['100', '1 999', '1 999', '100 %', '20 073', '0', '4,0 %'], ['200', '3 999', '3 999', '100 %', '40 115', '0', '6,4 %'],
        ['400', '7 999', '7 999', '100 %', '80 590', '0', '10,5 %'],
    ], [2.2 * cm, 2.2 * cm, 2.2 * cm, 2.2 * cm, 2.6 * cm, 2.2 * cm, 3.4 * cm]))
    story.append(P('400 sesiones/s (~4 000 paquetes/s) usan el 10,5 % de CPU de 2 vCPU, sin pérdidas: el límite fue el '
                   'generador, no el IDS. La CPU crece de forma casi lineal (~2,4 % por cada 100 sesiones/s).', 'n'))
    story.append(P('R4: DDoS (prueba-r4.sh)', 'h2'))
    story.append(tabla([
        ['', 'Una fuente (alu01)', 'Distribuido (alu01 + 2 invitados)'],
        ['Recibe la víctima con el ataque', '74,8 Mbit/s · 7 456 pps', '124,7 Mbit/s · 12 434 pps (~43 Mbit/s por fuente)'],
        ['Fuentes identificadas / tiempo', '1/1 · 13,6 s (11,3 s en otra corrida)', '3/3 · 13,8 s'],
        ['Recibe la víctima con el límite', '2,0 Mbit/s', '6,0 Mbit/s (3 × 2)'],
        ['Testigo legítimo durante el ataque', '921 Mbit/s, sin limitar', '1 133 Mbit/s, sin limitar'],
        ['Retiro del límite tras el ataque', '40,8 s', '41,5 s'],
    ], [5.2 * cm, 5.4 * cm, 6.4 * cm]))
    story.append(P('0 falsos positivos con descargas legítimas a 1,3 Gbit/s (55 000 ACK/s de subida): no son fuente porque '
                   'reciben mucho más de lo que envían.', 'n'))
    story.append(P('Recursos de los switches y del controlador (prueba-r2-escala.sh)', 'h2'))
    story.append(tabla([
        ['Sesiones activas', 'Reglas de R2', 'Entradas en OVS (R-SW1)', 'Reglas en OVS tras', 'CPU OVS', 'RAM OVS', 'CPU ONOS', 'RAM ONOS'],
        ['0', '72', '92', '0,5 s', '1,0 %', '50 MB', '3,6 %', '888 MB'],
        ['50', '433', '453', '1,0 s', '1,0 %', '50 MB', '2,6 %', '888 MB'],
        ['100', '783', '803', '1,2 s', '1,0 %', '50 MB', '2,6 %', '888 MB'],
        ['200', '1 483', '1 503', '1,7 s', '1,2 %', '50 MB', '2,6 %', '888 MB'],
    ], [2.4 * cm, 1.9 * cm, 2.9 * cm, 2.3 * cm, 1.7 * cm, 1.8 * cm, 1.9 * cm, 2.1 * cm]))
    story += lista([
        '<b>Entradas de tabla (TCAM en hardware):</b> 72 fijas + 7 por usuario; un bloqueo de R3 o un límite de R4 suma una '
        'entrada por atacante. 1 000 usuarios ≈ 7 000 entradas por switch de acceso.',
        '<b>R1:</b> 21/21 accesos inválidos bloqueados; EAP-TLS en 82 ms (mediana); ~33 autenticaciones/s sin fallos. '
        '<b>R2:</b> 216 pruebas, 0 discrepancias, 142/142 bloqueados; 53/53 intentos registrados con su usuario.',
    ])
    story.append(PageBreak())


def seccion_8_9(story):
    story.append(P('8. Conclusiones', 'h1'))
    story += lista([
        '<b>La plataforma condiciona el diseño.</b> El VNRT no propaga la caída de portadora (de ahí BFD en todos los '
        'enlaces) y no entrega al IDS el unicast ajeno (de ahí el espejo en GRE). Ambos se descubrieron midiendo, no '
        'suponiendo, y cambiaron la arquitectura.',
        '<b>El sondeo de estadísticas de ONOS fija los tiempos de los detectores por contadores.</b> El spoofing interno '
        '(4,5–6 s) y R4 (~14 s) dependen de flowPollFrequency = 5 s; las firmas del IDS (0,3–1,1 s) no. Bajarlo a 2 s '
        'acortaría esos tiempos a cambio de carga en el controlador.',
        '<b>Mitigar por la identidad autenticada, no por la IP,</b> es lo que permite bloquear o limitar solo al atacante: '
        'la IP puede falsificarse, la MAC ligada a la sesión 802.1X y al puerto no pasa el anti-spoofing.',
        '<b>Las pruebas encontraron defectos reales,</b> que se corrigieron: enumeración de cuentas por respuestas de '
        'rechazo distintas (R1-02), pérdida del camino de ONOS-2 hacia Core-2 con el enlace entre cores caído (simulador '
        'de redundancia), spoofing de 3 paquetes no detectado (R3-03) y peticiones HTTP que el IDS veía 70 s tarde porque '
        'el servidor no las confirmaba.',
        '<b>Escalabilidad:</b> OVS no nota 1 500 reglas (1 % de CPU). El límite actual es la reconciliación completa de '
        'identity (O(sesiones)): un alta tarda 0,6–1,3 s y las ráfagas se agrupan (30–54 sesiones/s). La mejora es '
        'reconciliar solo la sesión que cambia.',
        '<b>Limitaciones abiertas:</b> la app AAA admite un supplicant autenticado por puerto; el espejo del IDS comparte '
        'la red de gestión con la sincronización del clúster (en producción iría por una red propia); un bloqueo por '
        'intentos fallidos puede usarse para bloquear una cuenta ajena (riesgo inherente a cualquier lockout).',
    ])
    story.append(P('9. Repositorio', 'h1'))
    story.append(P(f'Código, scripts de despliegue y pruebas: <link href="{REPO}"><font color="#1F3A5F"><b>{REPO}</b></font></link>', 'n'))
    story += lista(['politica/: identity, r2ctl, ddos, aaa-agent, policy.yaml, topology.yaml',
                    'infraestructura/: Ansible del slice, bootstrap in-band, redundancia, R1 (r1-identidad.sh, g05-bloqueo.py), IDS',
                    'pruebas/: pruebas funcionales y de carga (prueba-r1/r2/r3/r4, escala, carga-ids) y pruebas/unitarias (pytest)',
                    'documentacion/: este informe (generar_informe.py) y su evidencia'])
    story.append(PageBreak())


def anexos(story):
    story.append(P('Anexo A. Evidencia del plano de control', 'h1'))
    story.append(P('Clúster ONOS (REST /cluster y /devices): dos nodos READY, seis switches OpenFlow 1.3 por sus IPs in-band.', 'n'))
    story.append(codigo(leer('onos.txt')))
    story.append(P('Anexo B. Evidencia de R1, R2, R3 y R4 en el slice', 'h1'))
    story.append(P('Reglas instaladas en R-SW1 (ovs-ofctl): bloqueo de R3, meter y límite de R4 y política T4 del alumno.', 'n'))
    story.append(codigo(leer('ovs.txt')))
    story.append(Spacer(1, 6))
    story.append(P('FreeRADIUS (radius.log) y bloqueo de cuentas (g05-bloqueo): cada intento con su motivo.', 'n'))
    story.append(codigo(leer('r1.txt')))
    inc = leer('incidentes-r3.txt')
    if inc:
        story.append(Spacer(1, 6))
        story.append(P('Registro consolidado de incidentes de R3 (pruebas/incidentes.sh) tras la corrida de prueba-r3.sh.', 'n'))
        story.append(codigo(inc, maxl=24))
    r3 = leer('r3.txt')
    if r3:
        story.append(P('Salida de prueba-r3.sh (resumen).', 'n'))
        resumen = r3[r3.find('=== Resumen'):] if '=== Resumen' in r3 else r3[-1500:]
        story.append(codigo(resumen))
    story.append(P('Anexo C. Salida de pytest -v', 'h1'))
    py = leer('pytest.txt')
    lineas = [l for l in py.splitlines() if '::' in l or 'passed' in l or 'failed' in l]
    story.append(codigo('\n'.join(re.sub(r'^pruebas/unitarias/', '', l) for l in lineas)))


def pie(c, doc):
    c.saveState()
    c.setFont('Arial', 7.5)
    c.setFillColor(colors.HexColor('#6B7280'))
    c.drawString(2 * cm, 1.2 * cm, 'TEL354 · Lab 7 · Grupo 5 · EXP_TEL354_LAB7_G5')
    c.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f'Página {doc.page}')
    c.restoreState()


def main():
    story = []
    portada(story)
    seccion_1(story)
    seccion_2(story)
    seccion_3_4(story)
    seccion_5(story)
    seccion_6(story)
    seccion_7(story)
    seccion_8_9(story)
    anexos(story)
    doc = SimpleDocTemplate(str(SALIDA), pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.8 * cm,
                            bottomMargin=1.8 * cm, title='EXP_TEL354_LAB7_G5', author='Grupo 5 · TEL354',
                            subject='Lab 7: diseño, implementación y unit testing')
    doc.build(story, onFirstPage=lambda c, d: None, onLaterPages=pie)
    print(SALIDA, 'generado;', resumen_pytest())


if __name__ == '__main__':
    main()
