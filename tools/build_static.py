#!/usr/bin/env python3
"""Builds the static copy of the report site (GitHub Pages) from the artifact page and the report records.

The student data never goes to the repository as plain text. Each student gets one file in data/,
named and encrypted from the personal link code (PBKDF2-SHA256 -> AES-256-GCM). The page derives the
same key in the browser from the code after the "#" in the link, so only that link opens the report.

usage:
  build_static.py --page ARTIFACT_INDEX_HTML --seed DIR_WITH_RECORDS --codes CODES_JSON --out REPO_DIR

CODES_JSON stays outside the repository. Format:
  { "<record code>": { "static": "<code used in the Pages link>", "files": ["<record>.json", ...] } }
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITER = 200000
SALT = b'english-for-work-reports-v1'


def derive(code):
    raw = hashlib.pbkdf2_hmac('sha256', code.encode('utf-8'), SALT, ITER, dklen=48)
    return raw[:32], raw[32:48].hex()  # AES key, file id


def pack(code, docs):
    key, fid = derive(code)
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, json.dumps(docs, ensure_ascii=False, separators=(',', ':')).encode('utf-8'), None)
    return fid, {'v': 1, 'iv': base64.b64encode(iv).decode(), 'ct': base64.b64encode(ct).decode()}


DATA_JS = r"""  /* ---------- data: one encrypted file per student ---------- */
  var ENC = new TextEncoder(), DEC = new TextDecoder(), ITER = 200000, SALT = 'english-for-work-reports-v1';
  function unb64(s) { var b = atob(s), a = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a; }
  function hex(u8) { return Array.prototype.map.call(u8, function (x) { return ('0' + x.toString(16)).slice(-2); }).join(''); }
  async function openReport(code) {
    var base = await crypto.subtle.importKey('raw', ENC.encode(code), 'PBKDF2', false, ['deriveBits']);
    var bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: ENC.encode(SALT), iterations: ITER, hash: 'SHA-256' }, base, 384));
    var res = await fetch('data/' + hex(bits.slice(32, 48)) + '.json', { cache: 'no-cache' });
    if (!res.ok) throw new Error('missing');
    var pk = await res.json();
    var key = await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['decrypt']);
    var plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(pk.iv) }, key, unb64(pk.ct));
    return JSON.parse(DEC.decode(plain));
  }
  function route() {
    var code = (location.hash || '').replace(/^#/, '');
    $('all-students').hidden = true;
    S.docs = []; S.ready = false; S.cycle = null; S.mode = 'student';
    if (!/^[a-z0-9][a-z0-9-]{9,60}$/i.test(code)) {
      message('Open your personal link', 'Your teacher sent you a link that ends in your own code. Use that link to see your report.');
      return;
    }
    if (!(window.crypto && window.crypto.subtle)) {
      message('This browser cannot open the report', 'Try again in an up-to-date browser, using the https link.');
      return;
    }
    message('Loading your report', 'This takes a few seconds.');
    openReport(code).then(function (docs) {
      if (code !== (location.hash || '').replace(/^#/, '')) return;
      S.docs = docs.map(function (d) { return Object.assign({}, d, { _id: d.student + '_c' + d.cycle }); });
      S.ready = true;
      paintReport();
    }, function () {
      message('We could not open this report', 'Check that you opened the full link your teacher sent you. If it keeps happening, tell your teacher.');
    });
  }

"""


def between(s, a, b, keep_b=True):
    i = s.index(a)
    j = s.index(b, i)
    return i, j


def make_page(src):
    head_end = src.index('</style>') + len('</style>')
    head, body = src[:head_end], src[head_end:]
    head = re.sub(r'<meta name="claude:viewport-fit-sides"[^>]*>\n?', '', head)

    # no teacher index on the public copy
    i = body.index('  function paintIndex() {')
    j = body.index('  /* ---------- data ---------- */')
    body = body[:i] + body[j:]
    # data loading
    i = body.index('  /* ---------- data ---------- */')
    j = body.index('  /* ---------- events ---------- */')
    body = body[:i] + DATA_JS + body[j:]
    # index copy button
    i = body.index("  $('index').addEventListener('click'")
    j = body.index("  window.addEventListener('hashchange', route);")
    body = body[:i] + body[j:]
    # start
    i = body.index('  /* ---------- start ---------- */')
    j = body.rindex('})();\n</script>')
    body = body[:i] + '  /* ---------- start ---------- */\n  route();\n' + body[j:]

    return ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
            '<meta name="robots" content="noindex, nofollow">\n<link rel="icon" href="data:,">\n'
            + head + '\n</head>\n<body>\n' + body.strip() + '\n</body>\n</html>\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--page', required=True)
    ap.add_argument('--seed', required=True)
    ap.add_argument('--codes', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()

    page = make_page(open(a.page, encoding='utf-8').read())
    open(os.path.join(a.out, 'index.html'), 'w', encoding='utf-8').write(page)
    open(os.path.join(a.out, '.nojekyll'), 'w').write('')

    data_dir = os.path.join(a.out, 'data')
    os.makedirs(data_dir, exist_ok=True)
    codes = json.load(open(a.codes, encoding='utf-8'))
    keep = set()
    for rec_code, info in codes.items():
        docs = [json.load(open(os.path.join(a.seed, f), encoding='utf-8')) for f in info['files']]
        docs.sort(key=lambda d: d['cycle'])
        fid, pk = pack(info['static'], docs)
        keep.add(fid + '.json')
        json.dump(pk, open(os.path.join(data_dir, fid + '.json'), 'w'))
        print('wrote data/%s.json  (%d cycle(s), %s)' % (fid, len(docs), rec_code))
    for f in os.listdir(data_dir):  # drop files of students that were removed
        if f.endswith('.json') and f not in keep:
            os.remove(os.path.join(data_dir, f))
            print('removed data/' + f)


if __name__ == '__main__':
    sys.exit(main())
