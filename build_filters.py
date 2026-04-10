import urllib.request
import re
import os
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

# ===================== 유틸 =====================

def get_etld1(domain):
    ext = tldextract.extract(domain)
    if not ext.domain or not ext.suffix:
        return domain
    return f"{ext.domain}.{ext.suffix}"

def normalize_line(line):
    line = line.strip()
    if not line or line.startswith(('!', '#')):
        return None

    if line.startswith('@@'):
        return line

    # hosts 형식 변환 (IP 제거)
    hosts_match = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)$', line)
    if hosts_match:
        return f"||{hosts_match.group(1)}^"

    # 도메인 단독 변환
    if re.match(r'^[a-zA-Z0-9.-]+$', line):
        return f"||{line}^"

    # 옵션 제거 (애드가드 홈 DNS에서 무의미한 브라우저 확장용 옵션 제거. 단, dnsrewrite는 유지)
    if '$dnsrewrite' not in line:
        line = re.sub(r'\$.*$', '', line)

    return line

def extract_domain(rule):
    match = re.search(r'^(?:@@)?\|\|([a-zA-Z0-9.-]+)', rule)
    return match.group(1) if match else None

def is_whitelisted(domain, whitelist_domains):
    if not domain:
        return False
    parts = domain.split('.')
    for i in range(len(parts)):
        check = ".".join(parts[i:])
        if check in whitelist_domains:
            return True
    return False

# ===================== 병렬 다운로드 =====================

def fetch_one(url):
    rules = set()
    whitelist = set()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as res:
            for line in res.read().decode('utf-8', errors='ignore').splitlines():
                norm = normalize_line(line)
                if not norm: continue
                if norm.startswith('@@'): whitelist.add(norm)
                else: rules.add(norm)
        print(f"Downloaded: {url.split('/')[-1]}")
    except Exception as e:
        print(f"Error {url}: {e}")
    return rules, whitelist

def fetch_all(urls):
    all_rules = set()
    all_whitelist = set()
    # 10개 쓰레드로 동시 다운로드 (속도 대폭 향상)
    with ThreadPoolExecutor(max_workers=10) as ex:
        results = list(ex.map(fetch_one, urls))
    for r, w in results:
        all_rules |= r
        all_whitelist |= w
    return all_rules, all_whitelist

# ===================== 딥 최적화 =====================

def optimize_ruleset(rules, is_whitelist=False, parent_domains=None):
    pure_domains = set()
    pure_regex = r'^(?:@@)?\|\|([a-zA-Z0-9.-]+)\^$'

    for r in rules:
        match = re.search(pure_regex, r)
        if match: pure_domains.add(match.group(1))

    if parent_domains:
        pure_domains |= parent_domains

    optimized = set()

    for rule in rules:
        if '$dnsrewrite' in rule:
            optimized.add(rule)
            continue

        domain = extract_domain(rule)
        if not domain:
            optimized.add(rule)
            continue

        redundant = False

        # 1. 완벽한 동일 도메인 중복 제거 (불필요한 파생 옵션 규칙 방어)
        if domain in pure_domains and not re.match(pure_regex.replace('([a-zA-Z0-9.-]+)', re.escape(domain)), rule):
            redundant = True

        # 2. tldextract 기반 안전한 부모 도메인 검사 (과소 차단 버그 해결 로직)
        if not redundant:
            etld1 = get_etld1(domain)
            parts = domain.split('.')
            # 서브도메인을 하나씩 깎아가며 부모가 이미 차단되었는지 확인
            for i in range(1, len(parts)):
                parent = ".".join(parts[i:])
                if parent in pure_domains:
                    redundant = True
                    break
                # eTLD+1 (예: example.co.uk)에 도달하면 더 이상 상위(예: co.uk)로 쪼개지 않음!
                if parent == etld1:
                    break

        if not redundant:
            optimized.add(rule)

    return optimized, pure_domains

# ===================== 메인 실행 =====================

def main():
    print("[1] 38개 필터 병렬 다운로드 중...")
    base_rules_raw, base_whitelist_raw = fetch_all(BASE_URLS)
    xtra_rules_raw, xtra_whitelist_raw = fetch_all([XTRA_URL])

    whitelist_raw = base_whitelist_raw | xtra_whitelist_raw

    # 로컬 whitelist 적용
    if os.path.exists(WHITELIST_FILE):
        print("\n[2] 로컬 커스텀 화이트리스트 로드 중...")
        with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                norm = normalize_line(line)
                if norm and norm.startswith('@@'):
                    whitelist_raw.add(norm)

    print("\n[3] 화이트리스트 내부망 최적화...")
    whitelist, whitelist_domains = optimize_ruleset(whitelist_raw, is_whitelist=True)

    print("[4] 차단 목록에서 화이트리스트 도메인 구출 중...")
    def apply_whitelist(rules):
        return {r for r in rules if not is_whitelisted(extract_domain(r), whitelist_domains)}

    base_rules_clean = apply_whitelist(base_rules_raw)
    xtra_rules_clean = apply_whitelist(xtra_rules_raw)

    print("[5] Base 필터 독립 최적화...")
    base_rules, base_domains = optimize_ruleset(base_rules_clean)

    print("[6] 1Hosts(Xtra) 필터 오탐 격리 최적화 (Base와 겹치는 규칙 융단폭격)...")
    xtra_unique = xtra_rules_clean - base_rules
    xtra_rules, _ = optimize_ruleset(xtra_unique, parent_domains=base_domains)

    print("\n[7] 캐시 효율을 위한 정렬 및 저장 중...")
    # 애드가드 홈의 Radix Tree 구조에 최적화된 정렬: 뎁스(.) -> 길이 -> 알파벳순
    def sort_key(rule):
        d = extract_domain(rule) or ""
        return (d.count('.'), len(d), d)

    with open(BASE_OUTPUT, 'w', encoding='utf-8') as f:
        f.write(f"! Title: My Base Filter (Optimized for DNS)\n! Rules: {len(base_rules)}\n")
        f.write(f"! Description: Thread-fetched, eTLD+1 pruned, safe universally trusted rules.\n")
        for r in sorted(whitelist, key=sort_key): f.write(f"{r}\n")
        for r in sorted(base_rules, key=sort_key): f.write(f"{r}\n")

    with open(XTRA_OUTPUT, 'w', encoding='utf-8') as f:
        f.write(f"! Title: 1Hosts Xtra (Unique Aggressive Only)\n! Rules: {len(xtra_rules)}\n")
        f.write(f"! Description: False-positive isolation filter.\n")
        for r in sorted(xtra_rules, key=sort_key): f.write(f"{r}\n")

    print(f"\n✅ 완벽하게 최적화 되었습니다!")
    print(f"방어선(Base) 규칙 수: {len(base_rules):,} 개")
    print(f"격리된(Xtra) 규칙 수: {len(xtra_rules):,} 개")

if __name__ == "__main__":
    main()
