# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec file for LACP Daemon
#
# Copyright (C) 2025 LACP Daemon Team
# SPDX-License-Identifier: GPL-3.0-or-later

block_cipher = None

a = Analysis(
    ['src/lacpd/main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'lacpd.actor',
        'lacpd.packet',
        'lacpd.utils',
        'fcntl',
        'struct',
        'socket',
        'threading',
        'json',
        'logging',
        'argparse',
        'time',
        'sys',
        'os',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='lacpd',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,  # Let PyInstaller auto-detect from the runner
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
    version_file=None,
)