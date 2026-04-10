import urllib.request
import re
import os

# 38개의 방대한 필터 목록
FILTER_URLS = [
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
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_70.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_67.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_66.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_65.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_71.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_69.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_25.txt"
]

WHITELIST_FILE = "my_whitelist.txt"
OUTPUT_FILE = "my_optimized_filter.txt"

def normalize_line(line):
    line = line.strip()
    if not line or line.startswith(('!', '#')):
        return None
    
    if line.startswith('@@'):
        return line

    hosts_match = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)$', line)
    if hosts_match:
        return f"||{hosts_match.group(1)}^"

    if re.match(r'^[a-zA-Z0-9.-]+$', line):
        return f"||{line}^"

    return line

def extract_domain_from_whitelist(rule):
    match = re.search(r'@@\|\|([a-zA-Z0-9.-]+)\^', rule)
    if match:
        return match.group(1)
    return None

def extract_pure_domain(rule):
    # ||example.com^ 형태의 순수 차단 도메인만 추출 (특수 옵션이 붙은 건 제외하여 안전성 확보)
    match = re.search(r'^\|\|([a-zA-Z0-9.-]+)\^$', rule)
    if match:
        return match.group(1)
    return None

def prune_subdomains(block_rules):
    print("\n[Optimization] Starting Subdomain Pruning...")
    
    # 1. 빠른 조회를 위해 순수 도메인 추출 및 매핑
    domain_to_rule = {}
    for rule in block_rules:
        domain = extract_pure_domain(rule)
        if domain:
            domain_to_rule[domain] = rule

    domains = set(domain_to_rule.keys())
    redundant_rules = set()

    # 2. 서브도메인의 상위(부모) 도메인이 존재하는지 검사
    for domain in domains:
        parts = domain.split('.')
        # 최소 3단계(sub.domain.com) 이상일 때만 상위 도메인 검사
        if len(parts) > 2:
            is_redundant = False
            for i in range(1, len(parts) - 1):
                parent_domain = ".".join(parts[i:])
                if parent_domain in domains:
                    is_redundant = True
                    break
            
            if is_redundant:
                redundant_rules.add(domain_to_rule[domain])

    print(f"[Optimization] Found and removed {len(redundant_rules):,} redundant subdomain rules.")
    return block_rules - redundant_rules

def main():
    block_rules = set()
    whitelist_rules = set()

    # 1. 원격 필터 다운로드
    for url in FILTER_URLS:
        print(f"Downloading: {url}")
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response:
                content = response.read().decode('utf-8').splitlines()
                for line in content:
                    normalized = normalize_line(line)
                    if normalized:
                        if normalized.startswith('@@'):
                            whitelist_rules.add(normalized)
                        else:
                            block_rules.add(normalized)
        except Exception as e:
            print(f"Error downloading {url}: {e}")

    # 2. 내 커스텀 예외 규칙 파일 불러오기
    if os.path.exists(WHITELIST_FILE):
        print(f"\nLoading local custom whitelist: {WHITELIST_FILE}")
        with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                normalized = normalize_line(line)
                if normalized and normalized.startswith('@@'):
                    whitelist_rules.add(normalized)

    # 3. 차단 규칙과 예외 규칙 충돌 방지 (예외 처리 도메인을 차단 목록에서 삭제)
    domains_to_whitelist = set()
    for w_rule in whitelist_rules:
        domain = extract_domain_from_whitelist(w_rule)
        if domain:
            domains_to_whitelist.add(domain)

    final_block_rules = set()
    for b_rule in block_rules:
        b_match = re.search(r'^\|\|([a-zA-Z0-9.-]+)\^', b_rule)
        if b_match:
            if b_match.group(1) not in domains_to_whitelist:
                final_block_rules.add(b_rule)
        else:
            final_block_rules.add(b_rule)

    # 4. 궁극의 최적화: 서브도메인 가지치기 적용
    optimized_block_rules = prune_subdomains(final_block_rules)

    # 5. 최종 파일 생성
    print("\nSaving final ultimate list...")
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("! Title: My Ultimate Custom Filter (Pruned)\n")
        f.write("! Description: All 38 filters merged, strictly deduplicated, and subdomain pruned.\n")
        f.write(f"! Total Block Rules: {len(optimized_block_rules)}\n")
        f.write(f"! Total Whitelist Rules: {len(whitelist_rules)}\n\n")
        
        for rule in sorted(whitelist_rules):
            f.write(f"{rule}\n")
        for rule in sorted(optimized_block_rules):
            f.write(f"{rule}\n")
            
    print(f"Done! Final Block: {len(optimized_block_rules):,}, Whitelist: {len(whitelist_rules):,}")

if __name__ == "__main__":
    main()
