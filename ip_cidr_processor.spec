# -*- mode: python -*-
import sys
import os
from os.path import join, abspath
import platform

block_cipher = None

# Определяем корневую директорию проекта
root_dir = os.getcwd()

# Обнаружение OS для правильного именования
os_name = 'windows-latest' if platform.system() == 'Windows' else 'ubuntu-latest'

# Определение имени исполняемого файла на основе ОС
if platform.system() == 'Windows':
    exe_name = f'ip_cidr_processor_{os_name}.exe'
else:
    exe_name = f'ip_cidr_processor_{os_name}'

a = Analysis(
    [join(root_dir, 'src', 'ip_cidr_processor.py')],
    pathex=[root_dir],
    binaries=[],
    datas=[],
    hiddenimports=['yaml', 'requests', 'psutil'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher
)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name=exe_name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    windowed=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    onefile=True,
    icon='resources/icon.ico'
)
