"""Configuración común de las pruebas unitarias (G05).

Las pruebas no usan la red ni el slice: importan el código de politica/ y de
infraestructura/files/ y lo ejercitan con datos sintéticos. Se corren desde la raíz:

    ../Proyecto-R2/.venv/bin/python -m pytest pruebas/unitarias -q
"""
import importlib.util
import os
import sys
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parents[2]
POLITICA = RAIZ / 'politica'
FILES = RAIZ / 'infraestructura' / 'files'
sys.path.insert(0, str(POLITICA))


def cargar(nombre, ruta):
    """Importa un archivo que no es un módulo válido por nombre (p. ej. con guiones)."""
    spec = importlib.util.spec_from_file_location(nombre, ruta)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope='session')
def r2ctl():
    os.environ.setdefault('R2_LOCAL', '1')
    import r2ctl as m
    return m


@pytest.fixture(scope='session')
def politica(r2ctl):
    return r2ctl.load()
