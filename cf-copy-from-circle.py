# Temporary file: copies Dilithium from Cloudflare's circl library into crypto.

import os
import sys
import tempfile
import subprocess

base = os.path.dirname(os.path.abspath(sys.argv[0]))

REPO = 'https://github.com/cloudflare/circl'
BRANCH = 'master'

circl = os.path.join(base, 'src/circl')

if os.path.exists(circl):
    print("Removing old circl ...")
    subprocess.check_call(['rm', '-r', '-f', circl])

with tempfile.TemporaryDirectory() as d:
    print(f"Cloning {REPO} branch {BRANCH} ...")
    subprocess.check_call(['git', 'clone', REPO, '--branch', BRANCH],
                cwd=d)

    print("Copying ...")
    subprocess.check_call(['cp', '-r',
        os.path.join(d, 'circl'),
        circl,
    ])

print("Removing avo sourcecode (for now) ...")
# XXX figure out a way to prevent ./src/all.sh from trying to build the
#     asm folders that require avo.
subprocess.check_call(['rm', '-r',
    os.path.join(circl, 'simd/keccakf1600/internal/asm'),
    os.path.join(circl, 'sign/dilithium/internal/common/asm'),
])

print("Removing templates (for now)  ...")
# XXX figure out a way to prevent build/deps_test.go from trying to pase
#     the templates.
subprocess.check_call(['rm', '-r',
    os.path.join(circl, 'sign/dilithium/templates'),
    os.path.join(circl, 'sign/dilithium/gen.go'),
])

print("Removing misc cruft ...")
subprocess.check_call(['rm', '-r', '-f',
    os.path.join(circl, '.git'),
    os.path.join(circl, 'go.mod'),
    os.path.join(circl, 'go.sum'),
    os.path.join(circl, '.etc'),
    os.path.join(circl, 'Makefile'),
    os.path.join(circl, 'codecov.yml'),
])

print("Correcting import paths ...")

def correct(fn):
    with open(fn, 'rb') as f:
        s = f.read()
    s = s.replace(
        b'github.com/cloudflare/circl',
        b'circl',
    ).replace(
        b'golang.org/x/sys/cpu',
        b'internal/cpu',
    )
    with open(fn, 'wb') as f:
        f.write(s)

for subdir, _, files in os.walk(circl):
    for fn in files:
        correct(os.path.join(subdir, fn))


print("Formatting ....")
subprocess.check_call(['go', 'fmt', './...'], cwd=circl)
