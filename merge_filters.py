import urllib.request
import re
import os

# 1. 1Hosts를 제외한 기본 필터 37개 + 25번
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

# 2. 독립시킬 1Hosts (Xtra)
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

def extract_pure_domain(rule):
    match = re.search(r'^\|\|([a-zA-Z0-9.-]+)\^$', rule)
    return match.group(1) if match else None

def prune_subdomains(block_rules):
    domain_to_rule = {extract_pure_domain(r): r for r in block_rules if extract_pure_domain(r)}
    domains = set(domain_to_rule.keys())
    redundant = set()
    for domain in domains:
        parts = domain.split('.')
        if len(parts) > 2:
            for i in range(1, len(parts) - 1):
                if ".".join(parts[i:]) in domains:
                    redundant.add(domain_to_rule[domain])
                    break
    return block_rules - redundant

def fetch_and_process(urls):
    rules = set()
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as res:
                for line in res.read().decode('utf-8').splitlines():
                    norm = normalize_line(line)
                    if norm: rules.add(norm)
        except Exception as e: print(f"Error {url}: {e}")
    return rules

# 메인 실행 로직
base_rules_raw = fetch_and_process(BASE_URLS)
xtra_rules_raw = fetch_and_process([XTRA_URL])

# 1. 각각 서브도메인 가지치기(Pruning) 수행
base_rules = prune_subdomains(base_rules_raw)
xtra_rules = prune_subdomains(xtra_rules_raw)

# 2. 차집합 연산: 1Hosts에서 Base와 겹치는 도메인 제거
# 1Hosts만이 가진 순수 'Xtra' 도메인만 남깁니다.
base_domains = {extract_pure_domain(r) for r in base_rules if extract_pure_domain(r)}
final_xtra_rules = set()
for rule in xtra_rules:
    domain = extract_pure_domain(rule)
    if domain not in base_domains:
        final_xtra_rules.add(rule)

# 3. 결과 저장 (Base)
with open(BASE_OUTPUT, 'w', encoding='utf-8') as f:
    f.write(f"! Title: My Base Filter\n! Rules: {len(base_rules)}\n")
    for r in sorted(base_rules): f.write(f"{r}\n")

# 4. 결과 저장 (1Hosts Xtra Only)
with open(XTRA_OUTPUT, 'w', encoding='utf-8') as f:
    f.write(f"! Title: 1Hosts Xtra (Unique Only)\n! Rules: {len(final_xtra_rules)}\n")
    for r in sorted(final_xtra_rules): f.write(f"{r}\n")

print(f"Base: {len(base_rules)} | 1Hosts Unique: {len(final_xtra_rules)}")
