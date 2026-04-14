import urllib.request
import re
import os
import time
import sys
from concurrent.futures import ThreadPoolExecutor
import tldextract

# ===================== 설정 =====================

BASE_URLS = [
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_49.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_33.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_39.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_46.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_47.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_61.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_63.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_60.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_57.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_62.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_15.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_55.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_54.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_56.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_67.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_66.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_65.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_71.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_69.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_25.txt"
]

XTRA_URL = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_70.txt"

WHITELIST_FILE = "my_whitelist.txt"
BASE_OUTPUT = "my_base_filter.txt"
XTRA_OUTPUT = "my_1hosts_xtra_only.txt"

SHORT_RETRIES = 3
SHORT_DELAY = 10
LONG_RETRIES = 2
LONG_DELAY = 600

MIN_BASE_RULES = 500000
MIN_XTRA_RULES = 10000

# ===================== 상태 =====================

failed_urls = set()

# ===================== tldextract =====================

extractor = tldextract.TLDExtract(suffix_list_urls=None)

def get_etld1(domain):
    ext = extractor(domain)
    if not ext.domain or not ext.suffix:
        return domain
    return f"{ext.domain}.{ext.suffix}"

# ===================== 유틸 =====================

def normalize_line(line):
    line = line.strip()
    if not line or line.startswith(('!', '#')):
        return None

    if line.startswith('@@'):
        return line

    hosts_match = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)$', line)
    if hosts_match:
        return f"||{hosts_match.group(1)}^"

    if re.match(r'^[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+$', line):
        return f"||{line}^"

    return line

def extract_pure_domain(rule):
    m = re.search(r'^\|\|([a-zA-Z0-9.-]+)\^', rule)
    return m.group(1) if m else None

def extract_option(rule):
    return rule.split('$', 1)[1] if '$' in rule else None

# ===================== whitelist =====================

def expand_whitelist_domains(whitelist_rules):
    domains = set()
    for w in whitelist_rules:
        m = re.search(r'@@\|\|([a-zA-Z0-9.-]+)\^', w)
        if m:
            domains.add(m.group(1))
    return domains

def is_whitelisted(domain, whitelist_domains):
    for w in whitelist_domains:
        if domain == w or domain.endswith("." + w):
            return True
    return False

# ===================== dedup =====================

def dedup_rules(rules):
    domain_map = {}

    for r in rules:
        d = extract_pure_domain(r)
        if not d:
            continue

        opt = extract_option(r)
        domain_map.setdefault(d, []).append((r, opt))

    result = set()

    for d, entries in domain_map.items():
        has_option = any(opt is not None for _, opt in entries)

        for r, opt in entries:
            if has_option:
                if opt is not None:
                    result.add(r)
            else:
                result.add(r)

    return result

# ===================== pruning =====================

def prune_subdomains(block_rules, whitelist_domains):
    print("  -> pruning (whitelist 보호)")

    domain_to_rule = {}
    for r in block_rules:
        d = extract_pure_domain(r)
        if d:
            domain_to_rule[d] = r

    domains = set(domain_to_rule.keys())
    redundant = set()

    for domain in domains:
        if is_whitelisted(domain, whitelist_domains):
            continue

        etld1 = get_etld1(domain)
        parts = domain.split('.')

        if domain != etld1 and len(parts) > 2:
            for i in range(1, len(parts)):
                parent = ".".join(parts[i:])

                if parent in domains and not is_whitelisted(parent, whitelist_domains):
                    redundant.add(domain_to_rule[domain])
                    break

                if parent == etld1:
                    break

    return block_rules - redundant

# ===================== 다운로드 =====================

def fetch_url_with_retry(url):
    rules = set()

    for attempt in range(SHORT_RETRIES):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=60) as res:
                for line in res.read().decode('utf-8', errors='ignore').splitlines():
                    norm = normalize_line(line)
                    if norm:
                        rules.add(norm)

            print(f"OK: {url.split('/')[-1]}")
            return rules

        except Exception as e:
            print(f"⚠️ retry {attempt+1}: {url} → {e}")
            if attempt < SHORT_RETRIES - 1:
                time.sleep(SHORT_DELAY)

    print(f"❌ 실패: {url}")
    failed_urls.add(url)
    return set()

def fetch_all(urls):
    rules = set()
    with ThreadPoolExecutor(max_workers=min(32, os.cpu_count() * 5)) as executor:
        for r in executor.map(fetch_url_with_retry, urls):
            rules.update(r)
    return rules

def fetch_all_with_retry(urls, min_rules, name):
    global failed_urls

    for attempt in range(LONG_RETRIES):
        failed_urls.clear()

        print(f"\n▶ {name} 다운로드 {attempt+1}/{LONG_RETRIES}")
        rules = fetch_all(urls)

        if failed_urls:
            print("\n❌ 일부 URL 실패:")
            for u in failed_urls:
                print(f" - {u}")

            if attempt < LONG_RETRIES - 1:
                print(f"⏳ {LONG_DELAY//60}분 후 재시도")
                time.sleep(LONG_DELAY)
                continue
            else:
                print("❌ 최종 실패")
                sys.exit(1)

        if len(rules) >= min_rules:
            print(f"✔ {name}: {len(rules):,}")
            return rules

        if attempt < LONG_RETRIES - 1:
            print("⚠️ 룰 부족 → 재시도")
            time.sleep(LONG_DELAY)

    print(f"❌ {name} 실패")
    sys.exit(1)

# ===================== 메인 =====================

def main():
    print("[1] Base 다운로드")
    base_raw = fetch_all_with_retry(BASE_URLS, MIN_BASE_RULES, "Base")

    print("[2] Xtra 다운로드")
    xtra_raw = fetch_all_with_retry([XTRA_URL], MIN_XTRA_RULES, "Xtra")

    print("[3] Whitelist 로드 및 적용")
    whitelist_rules = set()
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                norm = normalize_line(line)
                if norm and norm.startswith('@@'):
                    whitelist_rules.add(norm)

    whitelist_domains = expand_whitelist_domains(whitelist_rules)

    base_raw = {
        r for r in base_raw
        if not is_whitelisted(extract_pure_domain(r) or "", whitelist_domains)
    }

    xtra_raw = {
        r for r in xtra_raw
        if not is_whitelisted(extract_pure_domain(r) or "", whitelist_domains)
    }

    print("[4] dedup")
    base_raw = dedup_rules(base_raw)
    xtra_raw = dedup_rules(xtra_raw)

    print("[5] pruning")
    base_rules = prune_subdomains(base_raw, whitelist_domains)
    xtra_rules = prune_subdomains(xtra_raw, whitelist_domains)

    print("[6] Xtra 교차 pruning (whitelist 보호 포함)")
    base_domains = {extract_pure_domain(r) for r in base_rules if extract_pure_domain(r)}

    final_xtra = set()
    for r in xtra_rules:
        d = extract_pure_domain(r)
        if not d:
            continue

        if d in base_domains:
            continue

        is_redundant = False
        etld1 = get_etld1(d)
        parts = d.split('.')

        if d != etld1 and len(parts) > 2:
            for i in range(1, len(parts)):
                parent = ".".join(parts[i:])

                if parent in base_domains and not is_whitelisted(d, whitelist_domains):
                    is_redundant = True
                    break

                if parent == etld1:
                    break

        if not is_redundant:
            final_xtra.add(r)

    print("[7] 저장")

    def sort_key(rule):
        d = extract_pure_domain(rule) or ""
        return (d.count('.'), len(d), d)

    now = time.strftime('%Y-%m-%d %H:%M:%S')

    with open(BASE_OUTPUT, 'w', encoding='utf-8') as f:
        f.write(f"! Title: My Base Filter\n")
        f.write(f"! Description: Safely pruned merged filter\n")
        f.write(f"! Last updated: {now}\n")
        f.write(f"! Rules: {len(base_rules) + len(whitelist_rules)}\n\n")

        for r in sorted(whitelist_rules, key=sort_key):
            f.write(r + "\n")
        for r in sorted(base_rules, key=sort_key):
            f.write(r + "\n")

    with open(XTRA_OUTPUT, 'w', encoding='utf-8') as f:
        f.write(f"! Title: 1Hosts Xtra (Delta Unique)\n")
        f.write(f"! Description: Deep cross-pruned against Base\n")
        f.write(f"! Last updated: {now}\n")
        f.write(f"! Rules: {len(final_xtra)}\n\n")

        for r in sorted(final_xtra, key=sort_key):
            f.write(r + "\n")

    print("\n✅ 완료")
    print(f" -> Base: {len(base_rules) + len(whitelist_rules):,}")
    print(f" -> Xtra: {len(final_xtra):,}")

if __name__ == "__main__":
    main()
