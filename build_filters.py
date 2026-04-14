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

# ===================== 핵심 로직 (DNS 문법 초경량화) =====================

def normalize_line(line):
    line = line.strip()
    if not line or line.startswith(('!', '#')):
        return None

    if line.startswith('@@'):
        return line

    # 1. Hosts IP 형식 변환 (내부망 언더스코어 허용)
    hosts_match = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9._-]+)$', line)
    if hosts_match:
        line = f"||{hosts_match.group(1)}^"
    # 단순 도메인 Adblock 포맷 변환
    elif re.match(r'^[a-zA-Z0-9_-]+\.[a-zA-Z0-9._-]+$', line):
        line = f"||{line}^"

    # 2. 불필요한 와일드카드 평탄화 (||*.example.com^ -> ||example.com^)
    line = line.replace('||*.', '||')
    line = line.replace('@@||*.', '@@||')

    # 3. [핵심] 브라우저 전용 옵션 검사 및 원천 삭제 (메모리 절약 & 과차단 방지)
    if '$' in line:
        parts = line.split('$', 1)
        opts = parts[1].split(',')
        
        # 애드가드 홈(DNS 레벨)이 공식적으로 지원하는 옵션 목록
        valid_dns_opts = ('important', 'dnsrewrite', 'client', 'network', 'dnstype', 'badfilter', 'ctag')
        
        # 쉼표로 연결된 옵션들 중, 단 하나라도 위 목록에 없는 브라우저 전용 옵션($image, $media 등)이라면?
        has_invalid_opt = any(not any(o.startswith(v) for v in valid_dns_opts) for o in opts)
        
        if has_invalid_opt:
            # 애드가드 홈에서 어차피 무시될 규칙이므로, 평탄화하지 않고 아예 파일에서 삭제(Drop)합니다.
            return None

    # 4. 다국어 도메인(IDN) 퓨니코드 강제 통일 (중복 제거 효율 극대화)
    match = re.search(r'^(?:@@)?\|\|([a-zA-Z0-9._-]+)\^', line)
    if match:
        domain = match.group(1)
        if not domain.isascii():
            try:
                puny_domain = domain.encode('idna').decode('ascii')
                line = line.replace(domain, puny_domain)
            except Exception:
                pass

    return line

def extract_pure_domain(rule):
    m = re.search(r'^\|\|([a-zA-Z0-9._-]+)\^', rule)
    return m.group(1) if m else None

def extract_option(rule):
    return rule.split('$', 1)[1] if '$' in rule else None

# ===================== Whitelist =====================

def expand_whitelist_domains(whitelist_rules):
    domains = set()
    for w in whitelist_rules:
        m = re.search(r'@@\|\|([a-zA-Z0-9._-]+)\^', w)
        if m:
            domains.add(m.group(1))
    return domains

def is_whitelisted(domain, whitelist_domains):
    for w in whitelist_domains:
        if domain == w or domain.endswith("." + w):
            return True
    return False

# ===================== Dedup =====================

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

# ===================== Pruning =====================

def prune_subdomains(block_rules, whitelist_domains):
    print("  -> pruning (whitelist 터널링 완벽 보호 & eTLD+1 분석 적용)")
    domain_to_rule = {
        extract_pure_domain(r): r
        for r in block_rules if extract_pure_domain(r)
    }

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

# ===================== 다운로드 엔진 =====================

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

# ===================== 메인 실행 =====================

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

    print("[4] Dedup (중복 제거)")
    base_raw = dedup_rules(base_raw)
    xtra_raw = dedup_rules(xtra_raw)

    print("[5] Pruning (서브도메인 가지치기)")
    base_rules = prune_subdomains(base_raw, whitelist_domains)
    xtra_rules = prune_subdomains(xtra_raw, whitelist_domains)

    print("[6] Xtra 교차 Pruning (Base 규칙 종속성 제거)")
    base_domains = {extract_pure_domain(r) for r in base_rules if extract_pure_domain(r)}

    final_xtra = set()
    for r in xtra_rules:
        d = extract_pure_domain(r)
        if not d:
            continue

        # 1차: 완벽히 똑같은 도메인 제거
        if d in base_domains:
            continue

        # 2차: 부모 도메인이 Base에 존재하면 Xtra의 파생 규칙 제거 (Whitelist 보호)
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

    print("[7] 정렬 및 최종 파일 생성")
    def sort_key(rule):
        d = extract_pure_domain(rule) or ""
        return (d.count('.'), len(d), d)

    now = time.strftime('%Y-%m-%d %H:%M:%S')

    with open(BASE_OUTPUT, 'w', encoding='utf-8') as f:
        f.write(f"! Title: My Base Filter (DNS Optimized)\n")
        f.write(f"! Description: Merged 37 filters. Dropped browser-only dead rules.\n")
        f.write(f"! Last updated: {now}\n")
        f.write(f"! Rules: {len(base_rules) + len(whitelist_rules)}\n\n")

        for r in sorted(whitelist_rules, key=sort_key):
            f.write(r + "\n")
        for r in sorted(base_rules, key=sort_key):
            f.write(r + "\n")

    with open(XTRA_OUTPUT, 'w', encoding='utf-8') as f:
        f.write(f"! Title: 1Hosts Xtra (DNS Delta Unique)\n")
        f.write(f"! Description: Deep cross-pruned against Base to isolate false positives.\n")
        f.write(f"! Last updated: {now}\n")
        f.write(f"! Rules: {len(final_xtra)}\n\n")

        for r in sorted(final_xtra, key=sort_key):
            f.write(r + "\n")

    print("\n✅ 모든 작업 완료! (애드가드 홈 DNS 전용 최적화 적용)")
    print(f" -> 방어선(Base) 최종 규칙: {len(base_rules) + len(whitelist_rules):,} 개")
    print(f" -> 격리망(Xtra) 최종 규칙: {len(final_xtra):,} 개")

if __name__ == "__main__":
    main()
