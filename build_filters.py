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

# ===================== 함수 =====================

def get_etld1(domain):
    ext = tldextract.extract(domain)
    if not ext.domain or not ext.suffix:
        return domain
    return f"{ext.domain}.{ext.suffix}"

def normalize_line(line):
    line = line.strip()
    # 1. 주석 및 빈 줄 제거
    if not line or line.startswith(('!', '#')):
        return None
    
    # 2. 예외 규칙(@@)은 옵션 손상 없이 무조건 1순위로 반환
    if line.startswith('@@'):
        return line

    # 3. Hosts 형식 변환
    hosts_match = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)$', line)
    if hosts_match:
        return f"||{hosts_match.group(1)}^"

    # 4. 단순 도메인 -> Adblock 형식 변환 (점 포함 필수)
    if re.match(r'^[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+$', line):
        return f"||{line}^"

    # 5. AdGuard Home에 불필요한 브라우저 옵션 제거 ($dnsrewrite 등은 보존)
    if '$dnsrewrite' not in line:
        line = re.sub(r'\$.*$', '', line)

    return line

def extract_pure_domain(rule):
    match = re.search(r'^\|\|([a-zA-Z0-9.-]+)\^$', rule)
    return match.group(1) if match else None

def prune_subdomains(block_rules):
    print("  -> 서브도메인 가지치기 진행 중...")
    domain_to_rule = {extract_pure_domain(r): r for r in block_rules if extract_pure_domain(r)}
    domains = set(domain_to_rule.keys())
    redundant = set()
    
    for domain in domains:
        parts = domain.split('.')
        if len(parts) > 2:
            for i in range(1, len(parts) - 1):
                parent = ".".join(parts[i:])
                if parent in domains:
                    redundant.add(domain_to_rule[domain])
                    break
    return block_rules - redundant

def fetch_url(url):
    rules = set()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as res:
            for line in res.read().decode('utf-8').splitlines():
                norm = normalize_line(line)
                if norm and not norm.startswith('@@'):  # 원격 파일의 예외규칙은 무시 (안전성)
                    rules.add(norm)
    except Exception as e:
        print(f"오류 {url}: {e}")
    return rules

def fetch_and_process_concurrently(urls):
    rules = set()
    # 멀티스레딩으로 다운로드 속도 10배 향상
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(fetch_url, urls)
        for res in results:
            rules.update(res)
    return rules

# ===================== 메인 실행 =====================

def main():
    print("[1/5] 기본 통합 필터(37개) 다운로드 중...")
    base_rules_raw = fetch_and_process_concurrently(BASE_URLS)
    
    print("[2/5] 1Hosts (Xtra) 전용 다운로드 중...")
    xtra_rules_raw = fetch_and_process_concurrently([XTRA_URL])

    # 내 커스텀 예외 규칙(Whitelist) 로드
    whitelist_rules = set()
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                norm = normalize_line(line)
                if norm and norm.startswith('@@'):
                    whitelist_rules.add(norm)

    # 화이트리스트에 있는 도메인을 차단 목록에서 아예 삭제 (충돌 방지)
    w_domains = {re.search(r'@@\|\|([a-zA-Z0-9.-]+)\^', w).group(1) for w in whitelist_rules if re.search(r'@@\|\|([a-zA-Z0-9.-]+)\^', w)}
    
    base_rules_raw = {r for r in base_rules_raw if extract_pure_domain(r) not in w_domains}
    xtra_rules_raw = {r for r in xtra_rules_raw if extract_pure_domain(r) not in w_domains}

    print("[3/5] 규칙 최적화(Pruning) 중...")
    base_rules = prune_subdomains(base_rules_raw)
    xtra_rules = prune_subdomains(xtra_rules_raw)

    print("[4/5] 1Hosts 차집합(Delta) 연산 중...")
    base_domains = {extract_pure_domain(r) for r in base_rules if extract_pure_domain(r)}
    final_xtra_rules = {r for r in xtra_rules if extract_pure_domain(r) and extract_pure_domain(r) not in base_domains}

    print("[5/5] 최종 파일 저장 중...")
    # Base 필터 저장 (커스텀 화이트리스트를 Base 맨 위에 포함)
    with open(BASE_OUTPUT, 'w', encoding='utf-8') as f:
        f.write(f"! Title: My Base Filter\n! Description: 37 merged lists with pruning\n! Rules: {len(base_rules) + len(whitelist_rules)}\n\n")
        for r in sorted(whitelist_rules): f.write(f"{r}\n")
        for r in sorted(base_rules): f.write(f"{r}\n")

    # Xtra 필터 저장
    with open(XTRA_OUTPUT, 'w', encoding='utf-8') as f:
        f.write(f"! Title: 1Hosts Xtra (Delta Unique Only)\n! Description: Aggressive domains not present in Base\n! Rules: {len(final_xtra_rules)}\n\n")
        for r in sorted(final_xtra_rules): f.write(f"{r}\n")

    print(f"\n✅ 완료되었습니다!")
    print(f" -> Base 규칙 수: {len(base_rules):,}개")
    print(f" -> 1Hosts 고유 규칙 수: {len(final_xtra_rules):,}개")

if __name__ == "__main__":
    main()
