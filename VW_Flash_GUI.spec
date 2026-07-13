# -*- mode: python ; coding: utf-8 -*-

import sys


lzss_binary = 'lib/lzss/lzss.exe' if sys.platform == 'win32' else 'lib/lzss/lzss'
is_macos = sys.platform == 'darwin'


a = Analysis(
    ['VW_Flash_GUI.py'],
    pathex=[],
    binaries=[(lzss_binary, 'lzss/')],
    datas=[('data', 'data'), ('logging.conf', '.'), ('logs', 'logs'), ('docs', 'docs')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [] if is_macos else a.binaries,
    [] if is_macos else a.datas,
    [],
    name='VW_Flash_GUI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    exclude_binaries=is_macos,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

if is_macos:
    coll = COLLECT(
        exe,
        a.binaries,
        a.datas,
        strip=False,
        upx=True,
        upx_exclude=[],
        name='VW_Flash_GUI',
    )

    app = BUNDLE(
        coll,
        name='VW_Flash_GUI.app',
        icon=None,
        bundle_identifier='com.vwflash.gui',
        info_plist={
            'NSHighResolutionCapable': 'True',
        },
    )
