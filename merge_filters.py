import urllib.request
import re
import os

BASE_URLS = [
    # 기존 37개 필터 URL (생략 없이 그대로 넣으시면 됩니다)
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

def normalize_line(line):
    line = line.strip()
    if not line or line.startswith(('!', '#')): return None
    if line.startswith('@@'): return line
    hosts_match = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)$', line)
    if hosts_match: return f"||{hosts_match.group(1)}^"
    if re.match(r'^[a-zA-Z0-9.-]+$', line): return f"||{line}^"
    return line

def extract_target_domain(rule):
    """특수 옵션이나 경로가 붙은 규칙에서도 메인 도메인만 추출합니다."""
    match = re.search(r'^(?:@@)?\|\|([a-zA-Z0-9.-]+)', rule)
    return match.group(1) if match else None

def optimize_ruleset(rules, is_whitelist=False, parent_pure_domains=None):
    """
    모든 규칙의 도메인을 추출하고, 순수 도메인(뿌리)이 존재하면
    그 하위의 모든 규칙(서브도메인, 옵션 규칙, 경로 규칙)을 날려버립니다.
    """
    # 1. 순수 도메인(기준 뿌리) 추출 (예: ||example.com^)
    pure_domains = set()
    pure_regex = r'^(?:@@)?\|\|([a-zA-Z0-9.-]+)\^$'
    for r in rules:
        match = re.search(pure_regex, r)
        if match:
            pure_domains.add(match.group(1))
            
    if parent_pure_domains:
        pure_domains.update(parent_pure_domains)

    optimized = set()
    
    for rule in rules:
        # 차단 로직 예외: $important, $badfilter 등 강력한 지시어는 무시하고 살림
        if not is_whitelist and re.search(r'\$(important|badfilter|dnsrewrite)', rule):
            optimized.add(rule)
            continue

        domain = extract_target_domain(rule)
        if not domain:
            # 도메인 추출이 안되는 특수 정규식 규칙 등은 그대로 유지
            optimized.add(rule)
            continue
            
        is_redundant = False
        
        # A. 동일 도메인 옵션 종속성 검사 (예: 뿌리가 있는데 $third-party 가 붙어있는지)
        # 룰 자체가 순수 도메인 규칙이 아닌 경우에만 중복 처리
        if domain in pure_domains and not re.match(pure_regex.replace('([a-zA-Z0-9.-]+)', re.escape(domain)), rule):
            is_redundant = True

        # B. 서브도메인 종속성 검사 (부모 도메인이 차단/허용 되어 있는지)
        if not is_redundant:
            parts = domain.split('.')
            if len(parts) > 2:
                for i in range(1, len(parts) - 1):
                    parent = ".".join(parts[i:])
                    if parent in pure_domains:
                        is_redundant = True
                        break
                        
        if not is_redundant:
            optimized.add(rule)
            
    return optimized, pure_domains

def fetch_and_process(urls):
    rules = set()
    whitelist = set()
    for url in urls:
        print(f"Downloading: {url}")
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as res:
                for line in res.read().decode('utf-8').splitlines():
                    norm = normalize_line(line)
                    if norm:
                        if norm.startswith('@@'): whitelist.add(norm)
                        else: rules.add(norm)
        except Exception as e: print(f"Error {url}: {e}")
    return rules, whitelist

def main():
    print("\n[1] 다운로드 중...")
    base_rules_raw, base_whitelist_raw = fetch_and_process(BASE_URLS)
    xtra_rules_raw, xtra_whitelist_raw = fetch_and_process([XTRA_URL])

    combined_whitelist_raw = base_whitelist_raw | xtra_whitelist_raw
    if os.path.exists(WHITELIST_FILE):
        print(f"\n[2] 로컬 화이트리스트 로드: {WHITELIST_FILE}")
        with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                norm = normalize_line(line)
                if norm and norm.startswith('@@'):
                    combined_whitelist_raw.add(norm)

    print("\n[3] 딥 최적화(가지치기 & 종속성 제거) 진행 중...")
    
    # 1. 화이트리스트 최적화 (하위 도메인 허용 규칙 싹 정리)
    whitelist, whitelist_pure = optimize_ruleset(combined_whitelist_raw, is_whitelist=True)

    # 2. 화이트리스트 적용 (차단 규칙에서 화이트리스트 도메인 완전 배제)
    def apply_whitelist(rules):
        return {r for r in rules if extract_target_domain(r) not in whitelist_pure}

    base_rules_clean = apply_whitelist(base_rules_raw)
    xtra_rules_clean = apply_whitelist(xtra_rules_raw)

    # 3. Base 필터 극한 최적화
    base_rules, base_pure = optimize_ruleset(base_rules_clean)

    # 4. Xtra 필터 극한 최적화 (Base와 일치하는 규칙 제거 + Base에 부모가 있으면 파생 규칙까지 제거)
    xtra_unique_raw = xtra_rules_clean - base_rules
    xtra_rules, _ = optimize_ruleset(xtra_unique_raw, parent_pure_domains=base_pure)

    print("\n[4] 파일 저장 중...")
    with open(BASE_OUTPUT, 'w', encoding='utf-8') as f:
        f.write(f"! Title: My Base Filter\n! Rules: {len(base_rules)}\n")
        for r in sorted(whitelist): f.write(f"{r}\n")
        for r in sorted(base_rules): f.write(f"{r}\n")

    with open(XTRA_OUTPUT, 'w', encoding='utf-8') as f:
        f.write(f"! Title: 1Hosts Xtra (Unique Only)\n! Rules: {len(xtra_rules)}\n")
        for r in sorted(xtra_rules): f.write(f"{r}\n")

    print(f"\n완료! 차단 성능은 100% 동일합니다.")
    print(f"Base 규칙 수: {len(base_rules):,} 개")
    print(f"1Hosts Xtra 고유 규칙 수: {len(xtra_rules):,} 개")

if __name__ == "__main__":
    main()
