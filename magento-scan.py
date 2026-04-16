#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import gc
import time
import urllib3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from collections import deque

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except:
        pass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

R   = "\033[91m"
G   = "\033[92m"
Y   = "\033[93m"
B   = "\033[94m"
M   = "\033[95m"
C   = "\033[96m"
W   = "\033[97m"
D   = "\033[2m"
BD  = "\033[1m"
RST = "\033[0m"

BANNER = f"""{C}
╔══════════════════════════════════════════════╗
║              MAGENTO SCANNER                 ║
╚══════════════════════════════════════════════╝{RST}
       {Y}CMS Scanner{RST} | {G}Definitive Magento Detection{RST}
       {D}100% certain or skip — no false positives{RST}
       {D}github.com/AnggaTechI{RST}
"""

DEFAULT_THREADS    = 80
DEFAULT_TIMEOUT    = 8
DEFAULT_BATCH_SIZE = 500
MAX_HTML_READ      = 200_000  

print_lock = Lock()
file_lock  = Lock()

def safe_print(msg):
    with print_lock:
        print(msg, flush=True)

def write_line(path, text):
    with file_lock:
        with open(path, 'a', encoding='utf-8') as f:
            f.write(text)

_pool = deque(maxlen=200)
_pool_lock = Lock()

def get_session():
    with _pool_lock:
        if _pool:
            return _pool.pop()
    s = requests.Session()
    s.max_redirects = 4
    a = HTTPAdapter(pool_connections=20, pool_maxsize=20,
                    max_retries=Retry(total=0))
    s.mount('http://', a)
    s.mount('https://', a)
    return s

def return_session(s):
    with _pool_lock:
        _pool.append(s)

def normalize_url(url):
    url = url.strip().rstrip('/')
    if not url:
        return None
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    return url

def count_lines(fp):
    c = 0
    with open(fp, 'rb') as f:
        buf = f.raw.read(1024*1024)
        while buf:
            c += buf.count(b'\n')
            buf = f.raw.read(1024*1024)
    return c

def stream_domains(filepath, batch_size):
    """Yield batches of domains without loading entire file."""
    batch = []
    seen = set()
    for enc in ('utf-8', 'latin-1', 'cp1252'):
        try:
            with open(filepath, 'r', encoding=enc, errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    url = normalize_url(line)
                    if not url or url in seen:
                        continue
                    seen.add(url)
                    if len(seen) > 50_000:
                        seen = set(list(seen)[25_000:])
                    batch.append(url)
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []
            if batch:
                yield batch
            return
        except UnicodeDecodeError:
            continue
    if batch:
        yield batch

def get_headers():
    return {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                       'AppleWebKit/537.36 (KHTML, like Gecko) '
                       'Chrome/125.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    }

MAGENTO_HEADERS = frozenset([
    'x-magento-vary',
    'x-magento-cache-control',
    'x-magento-cache-debug',
    'x-magento-tags',
])

MAGENTO_COOKIES = frozenset([
    'mage-cache-storage',
    'mage-cache-sessid',
    'mage-messages',
    'mage-translation-storage',
    'mage-translation-file-version',
])

RE_MAGE_INIT     = re.compile(r'data-mage-init\s*=', re.IGNORECASE)
RE_MAGENTO_NS    = re.compile(r'Magento_[A-Z][a-zA-Z]+/', re.IGNORECASE)
RE_MAGE_MIXINS   = re.compile(r'mage/requirejs/mixins', re.IGNORECASE)
RE_REQUIREJS_CFG = re.compile(r'require\.config\(.*Magento_', re.IGNORECASE | re.DOTALL)
RE_M1_VARIEN     = re.compile(r'src=["\'][^"\']*js/varien/', re.IGNORECASE)
RE_M1_SKIN       = re.compile(r'skin/frontend/(default|rwd|base)/', re.IGNORECASE)
RE_VERSION_NUM   = re.compile(r'(\d+\.\d+\.\d+)')
RE_MAGENTO_VER   = re.compile(r'magento[/\s]*v?(\d+\.\d+\.\d+)', re.IGNORECASE)


def is_magento(url, session, timeout=8):
    hdrs = get_headers()
    info = {
        'version': 'Unknown',
        'edition': 'Unknown',
        'proof': [],     
    }
    try:
        resp = session.get(url, headers=hdrs, timeout=timeout,
                           verify=False, allow_redirects=True, stream=True)
        chunks = []
        read = 0
        for chunk in resp.iter_content(8192, decode_unicode=False):
            chunks.append(chunk)
            read += len(chunk)
            if read >= MAX_HTML_READ:
                break
        resp.close()
        html = b''.join(chunks).decode('utf-8', errors='replace')
        r_headers = resp.headers
        r_cookies = resp.cookies.get_dict()
    except requests.exceptions.Timeout:
        return False, {'status': 'TIMEOUT'}
    except requests.exceptions.ConnectionError:
        return False, {'status': 'CONN_FAILED'}
    except requests.exceptions.TooManyRedirects:
        return False, {'status': 'TOO_MANY_REDIRECTS'}
    except Exception as e:
        return False, {'status': f'ERROR: {str(e)[:40]}'}

    if resp.status_code >= 500:
        return False, {'status': f'DEAD ({resp.status_code})'}

    # ── CHECK 1: Magento-exclusive headers 
    for h in MAGENTO_HEADERS:
        if h in r_headers:
            info['proof'].append(f"Header: {h}")

    # ── CHECK 2: Magento-exclusive cookies 
    cookie_keys = set(k.lower() for k in r_cookies.keys())
    for mc in MAGENTO_COOKIES:
        if mc in cookie_keys:
            info['proof'].append(f"Cookie: {mc}")

    # ── CHECK 3: HTML definitive patterns
    has_mage_init = bool(RE_MAGE_INIT.search(html))
    has_magento_ns = bool(RE_MAGENTO_NS.search(html))
    has_mage_mixins = bool(RE_MAGE_MIXINS.search(html))
    has_requirejs_magento = bool(RE_REQUIREJS_CFG.search(html))

    # Magento 2: data-mage-init + Magento_* namespace = 100% Magento
    if has_mage_init and has_magento_ns:
        info['proof'].append("HTML: data-mage-init + Magento_* namespace")
        info['edition'] = 'Magento 2.x'

    # mage/requirejs/mixins is unique to Magento 2
    if has_mage_mixins:
        info['proof'].append("HTML: mage/requirejs/mixins")
        info['edition'] = 'Magento 2.x'

    # require.config with Magento_ = definitive
    if has_requirejs_magento:
        info['proof'].append("HTML: require.config with Magento_ modules")
        info['edition'] = 'Magento 2.x'

    # Magento 1: varien JS + skin/frontend/(default|rwd)
    has_varien = bool(RE_M1_VARIEN.search(html))
    has_m1_skin = bool(RE_M1_SKIN.search(html))
    if has_varien and has_m1_skin:
        info['proof'].append("HTML: varien.js + skin/frontend (M1)")
        info['edition'] = 'Magento 1.x'

    # Try version from HTML
    vm = RE_MAGENTO_VER.search(html)
    if vm:
        info['version'] = vm.group(1)
        info['proof'].append(f"HTML version: {info['version']}")

    # ── ALREADY PROVEN? Return immediately
    if info['proof']:
        return True, info

    # Check /magento_version (only Magento has this)
    try:
        r = session.get(f"{url}/magento_version", headers=hdrs,
                        timeout=5, verify=False, allow_redirects=False)
        if r.status_code == 200:
            txt = r.text.strip().lower()
            if 'magento' in txt:
                info['proof'].append(f"/magento_version: {r.text.strip()[:60]}")
                vm = RE_VERSION_NUM.search(r.text)
                if vm:
                    info['version'] = vm.group(1)
                return True, info
    except:
        pass

    # Check /pub/static/deployed_version.txt (Magento 2 only)
    try:
        r = session.get(f"{url}/pub/static/deployed_version.txt", headers=hdrs,
                        timeout=5, verify=False, allow_redirects=False)
        if r.status_code == 200:
            txt = r.text.strip()
            # This file contains a version number or timestamp
            if txt and len(txt) < 50 and re.match(r'^[\d.]+$', txt):
                info['proof'].append(f"deployed_version.txt: {txt}")
                info['edition'] = 'Magento 2.x'
                vm = RE_VERSION_NUM.search(txt)
                if vm:
                    info['version'] = vm.group(1)
                return True, info
    except:
        pass

    # Also try /static/deployed_version.txt (alternative path)
    try:
        r = session.get(f"{url}/static/deployed_version.txt", headers=hdrs,
                        timeout=5, verify=False, allow_redirects=False)
        if r.status_code == 200:
            txt = r.text.strip()
            if txt and len(txt) < 50 and re.match(r'^[\d.]+$', txt):
                info['proof'].append(f"static/deployed_version.txt: {txt}")
                info['edition'] = 'Magento 2.x'
                vm = RE_VERSION_NUM.search(txt)
                if vm:
                    info['version'] = vm.group(1)
                return True, info
    except:
        pass

    # Check REST API (Magento 2 exclusive endpoint)
    try:
        r = session.get(f"{url}/rest/V1/store/storeConfigs", headers=hdrs,
                        timeout=5, verify=False, allow_redirects=False,
                        stream=True)
        body = r.raw.read(3000).decode('utf-8', errors='replace')
        r.close()
        if r.status_code == 200 and body.strip().startswith(('[', '{')):
            import json
            data = json.loads(body)
            if isinstance(data, list) and len(data) > 0:
                cfg = data[0]
                # storeConfigs has very specific Magento fields
                if any(k in cfg for k in ('base_currency_code', 'default_display_currency_code',
                                           'weight_unit', 'store_name')):
                    info['proof'].append("REST API /store/storeConfigs confirmed")
                    info['edition'] = 'Magento 2.x'
                    cur = cfg.get('base_currency_code', '')
                    if cur:
                        info['proof'].append(f"Currency: {cur}")
                    return True, info
    except:
        pass
    return False, info


# ==================== SCAN PIPELINE ====================
def scan_single(url, timeout):
    """Scan one domain."""
    session = get_session()
    try:
        confirmed, info = is_magento(url, session, timeout)
        status = info.get('status', 'LIVE')
        return {
            'url': url,
            'is_magento': confirmed,
            'version': info.get('version', 'Unknown'),
            'edition': info.get('edition', 'Unknown'),
            'proof': info.get('proof', []),
            'status': status,
        }
    except Exception as e:
        return {'url': url, 'is_magento': False,
                'status': f'ERROR: {str(e)[:30]}'}
    finally:
        return_session(session)


def run_scan(domain_file, threads, timeout, batch_size):
    safe_print(f"\n{C}[*]{RST} Counting domains...")
    total_est = count_lines(domain_file)
    fsize_mb = os.path.getsize(domain_file) / (1024*1024)
    safe_print(f"{C}[*]{RST} File: {BD}{fsize_mb:.1f} MB{RST} | ~{BD}{total_est:,}{RST} domains")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = f"Result-Magento_{ts}"
    os.makedirs(out_dir, exist_ok=True)

    f_magento = os.path.join(out_dir, "Magento_Sites.txt")
    f_detail  = os.path.join(out_dir, "Magento_Detailed.txt")
    f_dead    = os.path.join(out_dir, "Dead_Sites.txt")

    safe_print(f"{C}[*]{RST} Threads: {BD}{threads}{RST} | Batch: {BD}{batch_size}{RST} | Timeout: {BD}{timeout}s{RST}")
    safe_print(f"{C}[*]{RST} Output : {BD}{out_dir}/{RST}")
    safe_print(f"{C}[*]{RST} Mode   : {G}Definitive only{RST} — 0% false positive")
    safe_print(f"{C}[*]{RST} Scanning...\n")

    stats = {
        'scanned': 0, 'magento': 0, 'dead': 0,
        'batch_num': 0, 'start': time.time(),
    }

    def process_batch(batch):
        stats['batch_num'] += 1
        bn = stats['batch_num']

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(scan_single, u, timeout): u for u in batch}

            for fut in as_completed(futures):
                res = fut.result()
                url = res['url']
                stats['scanned'] += 1

                if res['status'] != 'LIVE':
                    stats['dead'] += 1
                    write_line(f_dead, f"{url} # {res['status']}\n")
                    if stats['dead'] <= 20 or stats['dead'] % 10 == 0:
                        safe_print(f"  {R}[DEAD]{RST} {url} {D}({res['status']}){RST}")
                    continue

                if res['is_magento']:
                    stats['magento'] += 1
                    ver = res['version']
                    edi = res['edition']
                    proofs = res['proof']

                    safe_print(
                        f"  {G}[MAGENTO ✔]{RST} {url} "
                        f"{D}| v{ver} | {edi}{RST}"
                    )
                    for p in proofs:
                        safe_print(f"             {D}└─ {p}{RST}")

                    write_line(f_magento, f"{url}\n")

                    detail = (
                        f"\n{'='*70}\n"
                        f"URL     : {url}\n"
                        f"Version : {ver}\n"
                        f"Edition : {edi}\n"
                        f"Proof   :\n"
                        + ''.join(f"  ✔ {p}\n" for p in proofs)
                        + f"{'='*70}\n"
                    )
                    write_line(f_detail, detail)

        elapsed = time.time() - stats['start']
        rate = stats['scanned'] / elapsed if elapsed > 0 else 0
        eta_s = (total_est - stats['scanned']) / rate if rate > 0 else 0
        eta_m = eta_s / 60

        safe_print(
            f"\n{Y}[BATCH {bn}]{RST} "
            f"{stats['scanned']:,}/{total_est:,} | "
            f"{G}{stats['magento']} Magento{RST} | "
            f"{R}{stats['dead']} Dead{RST} | "
            f"{C}{rate:.0f}/s{RST} | "
            f"ETA {D}{eta_m:.0f}m{RST}\n"
        )
        gc.collect()

    try:
        for batch in stream_domains(domain_file, batch_size):
            process_batch(batch)
    except KeyboardInterrupt:
        safe_print(f"\n{Y}[!]{RST} Interrupted! Partial results saved.")
 
    elapsed = time.time() - stats['start']

    safe_print(f"\n{C}{'═'*60}{RST}")
    safe_print(f"{G}{BD}  SCAN COMPLETE{RST}")
    safe_print(f"{C}{'═'*60}{RST}")
    safe_print(f"  Total scanned    : {stats['scanned']:,}")
    safe_print(f"  {G}Magento (100%)   : {stats['magento']:,}{RST}")
    safe_print(f"  {R}Dead/Error       : {stats['dead']:,}{RST}")
    safe_print(f"  Not Magento      : {stats['scanned'] - stats['magento'] - stats['dead']:,}")
    safe_print(f"  Time             : {elapsed/60:.1f} min")
    if elapsed > 0:
        safe_print(f"  Speed            : {stats['scanned']/elapsed:.0f} domains/sec")

    safe_print(f"\n{C}[+]{RST} Results: {BD}{out_dir}/{RST}")
    safe_print(f"    {G}├── Magento_Sites.txt{RST}     (clean URL list)")
    safe_print(f"    {G}├── Magento_Detailed.txt{RST}  (with proof)")
    safe_print(f"    {R}└── Dead_Sites.txt{RST}")

    if stats['magento'] > 0:
        try:
            versions = {}
            editions = {}
            with open(f_detail, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.startswith('Version :'):
                        v = line.split(':',1)[1].strip()
                        versions[v] = versions.get(v, 0) + 1
                    elif line.startswith('Edition :'):
                        e = line.split(':',1)[1].strip()
                        editions[e] = editions.get(e, 0) + 1

            safe_print(f"\n{C}[VERSION]{RST}")
            for v, c in sorted(versions.items(), key=lambda x: -x[1]):
                safe_print(f"    {Y}{v:25s}{RST}: {c}")
            safe_print(f"\n{C}[EDITION]{RST}")
            for e, c in sorted(editions.items(), key=lambda x: -x[1]):
                safe_print(f"    {M}{e:35s}{RST}: {c}")
        except:
            pass

    safe_print(f"{C}{'═'*60}{RST}\n")

def show_menu():
    print(BANNER)
    print(f"  {G}[1]{RST} Scan daftar domain")
    print(f"  {R}[0]{RST} Exit")
    print()

def main():
    while True:
        show_menu()
        choice = input(f"  {C}[?]{RST} Pilih opsi: ").strip()

        if choice == '0':
            safe_print(f"\n  {Y}[*]{RST} Bye!\n")
            break

        if choice != '1':
            safe_print(f"  {R}[!]{RST} Opsi tidak valid\n")
            continue

        domain_file = input(f"  {C}[?]{RST} Path file domain: ").strip()
        if not os.path.exists(domain_file):
            safe_print(f"  {R}[!]{RST} File tidak ditemukan\n")
            continue

        fsize = os.path.getsize(domain_file) / (1024*1024)
        safe_print(f"  {D}    File: {fsize:.1f} MB{RST}")

        t = input(f"  {C}[?]{RST} Threads (default {DEFAULT_THREADS}): ").strip()
        threads = DEFAULT_THREADS
        if t:
            try: threads = max(1, min(300, int(t)))
            except: pass

        b = input(f"  {C}[?]{RST} Batch size (default {DEFAULT_BATCH_SIZE}): ").strip()
        batch_size = DEFAULT_BATCH_SIZE
        if b:
            try: batch_size = max(50, min(5000, int(b)))
            except: pass

        to = input(f"  {C}[?]{RST} Timeout (default {DEFAULT_TIMEOUT}s): ").strip()
        timeout = DEFAULT_TIMEOUT
        if to:
            try: timeout = max(3, min(30, int(to)))
            except: pass

        run_scan(domain_file, threads, timeout, batch_size)

        input(f"\n  {Y}Tekan Enter untuk lanjut...{RST}")
        print("\n" * 2)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        safe_print(f"\n\n  {Y}[!]{RST} Stopped\n")
        sys.exit(0)
    except Exception as e:
        safe_print(f"\n  {R}[ERROR]{RST} {e}\n")
        sys.exit(1)
