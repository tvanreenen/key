"""Independent public-vector checks for the temporary CI investigation."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys

P = int('FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF', 16)
N = int('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551', 16)
B = int('5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B', 16)
G = (int('6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296', 16),
     int('4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5', 16))


def add(a, b):
    if a is None: return b
    if b is None: return a
    x, y = a; u, v = b
    if x == u and (y + v) % P == 0: return None
    slope = ((3*x*x - 3) * pow(2*y, -1, P) if a == b
             else (v-y) * pow(u-x, -1, P)) % P
    out_x = (slope*slope-x-u) % P
    return out_x, (slope*(x-out_x)-y) % P


def multiply(k, point):
    result = None
    while k:
        if k & 1: result = add(result, point)
        point = add(point, point); k >>= 1
    return result


def math_verify(key, signature, message):
    if len(key) != 65 or key[0] != 4 or len(signature) != 64: return False
    q = (int.from_bytes(key[1:33], 'big'), int.from_bytes(key[33:], 'big'))
    x, y = q
    if not (0 <= x < P and 0 <= y < P) or (y*y-x*x*x+3*x-B) % P: return False
    r = int.from_bytes(signature[:32], 'big'); s = int.from_bytes(signature[32:], 'big')
    if not (0 < r < N and 0 < s < N): return False
    z = int.from_bytes(hashlib.sha256(message).digest(), 'big'); w = pow(s, -1, N)
    point = add(multiply(z*w % N, G), multiply(r*w % N, q))
    return point is not None and point[0] % N == r


def der_integer(value):
    value = value.lstrip(b'\0') or b'\0'
    if value[0] & 128: value = b'\0' + value
    return b'\x02' + bytes([len(value)]) + value


def main():
    source, out = Path(sys.argv[1]), Path(sys.argv[2]); out.mkdir(parents=True, exist_ok=True)
    entries = json.loads(source.read_text()); assert len(entries) == 1
    entry = entries[0]
    def decode(name): return base64.b64decode(entry[name], validate=True)
    key, raw, message = decode('verifiedPublicKey'), decode('verifiedSignature'), decode('verifiedInput')
    changed = bytes([message[0] ^ 1]) + message[1:]
    altered_signature = bytes([raw[0] ^ 1]) + raw[1:]
    values = der_integer(raw[:32]) + der_integer(raw[32:])
    der = b'\x30' + bytes([len(values)]) + values
    spki = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200') + key
    (out/'public.der').write_bytes(spki); (out/'signature.der').write_bytes(der)
    (out/'input.bin').write_bytes(message); (out/'changed.bin').write_bytes(changed)
    subprocess.run(['openssl', 'pkey', '-pubin', '-inform', 'DER', '-in', str(out/'public.der'), '-out', str(out/'public.pem')], check=True, capture_output=True)
    def openssl_verify(path):
        r = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(out/'public.pem'), '-signature', str(out/'signature.der'), str(path)], capture_output=True, text=True)
        if r.returncode not in (0, 1): raise RuntimeError(r.stderr)
        return r.returncode == 0
    checks = {'math_accepts_captured_signature': math_verify(key, raw, message),
              'math_rejects_changed_message': not math_verify(key, raw, changed),
              'math_rejects_changed_signature': not math_verify(key, altered_signature, message),
              'openssl_accepts_captured_signature': openssl_verify(out/'input.bin'),
              'openssl_rejects_changed_message': not openssl_verify(out/'changed.bin')}
    expected = {'publicKey': base64.b64encode(key).decode(), 'signatureRaw': base64.b64encode(raw).decode(),
                'input': base64.b64encode(message).decode(), 'sha256Hex': hashlib.sha256(message).hexdigest(),
                'signatureDER': base64.b64encode(der).decode()}
    (out/'expected.json').write_text(json.dumps(expected, indent=2) + '\n')
    report = {'checks': checks, 'sha256Hex': expected['sha256Hex'], 'independentDER': expected['signatureDER'],
              'opensslVersion': subprocess.check_output(['openssl', 'version'], text=True).strip()}
    (out/'reference.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    if not all(checks.values()): raise SystemExit(1)


if __name__ == '__main__': main()
