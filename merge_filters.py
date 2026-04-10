import urllib.request
import re
import os

# 처음에 주신 37개의 모든 필터 목록 + 추가 요청하신 25번 필터
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
    # 주석 및 빈 줄 제거
    if not line or line.startswith(('!', '#')):
        return None
    
    # 예외 규칙(@@)은 $important 같은 수식어가 있어도 그대로 유지
    if line.startswith('@@'):
        return line

    # Hosts 파일 형식 (0.0.0.0 domain.com) -> Adblock 형식 변환
    hosts_match = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)$', line)
    if hosts_match:
        return f"||{hosts_match.group(1)}^"

    # 단순 도메인 -> Adblock 형식 변환
    if re.match(r'^[a-zA-Z0-9.-]+$', line):
        return f"||{line}^"

    return line

def extract_domain_from_whitelist(rule):
    # @@||waterfox.com^$important 과 같은 규칙에서 순수 도메인(waterfox.com)만 추출
    match = re.search(r'@@\|\|([a-zA-Z0-9.-]+)\^', rule)
    if match:
        return match.group(1)
    return None

def main():
    block_rules = set()
    whitelist_rules = set()

    # 1. 원격 필터 38개 전부 다운로드
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

    # 2. 내 커스텀 예외 규칙 파일 (my_whitelist.txt) 불러오기
    if os.path.exists(WHITELIST_FILE):
        print(f"\nLoading local custom whitelist: {WHITELIST_FILE}")
        with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                normalized = normalize_line(line)
                if normalized and normalized.startswith('@@'):
                    whitelist_rules.add(normalized)

    # 3. 예외 규칙에 등록된 도메인 추출
    domains_to_whitelist = set()
    for w_rule in whitelist_rules:
        domain = extract_domain_from_whitelist(w_rule)
        if domain:
            domains_to_whitelist.add(domain)

    # 4. 차단 규칙(block_rules)에서 예외 처리할 도메인을 완전히 삭제 (충돌 방지)
    final_block_rules = set()
    for b_rule in block_rules:
        # ||domain.com^ 형태에서 도메인 추출
        b_match = re.search(r'^\|\|([a-zA-Z0-9.-]+)\^', b_rule)
        if b_match:
            # 예외 목록에 없는 도메인만 차단 목록에 남김
            if b_match.group(1) not in domains_to_whitelist:
                final_block_rules.add(b_rule)
        else:
            final_block_rules.add(b_rule)

    # 5. 최종 파일 생성
    print("\nSaving final optimized list...")
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("! Title: My Ultimate Custom Filter\n")
        f.write("! Description: All 38 filters merged and deduplicated, with strict whitelisting.\n")
        f.write(f"! Total Block Rules: {len(final_block_rules)}\n")
        f.write(f"! Total Whitelist Rules: {len(whitelist_rules)}\n\n")
        
        # 예외 규칙(@@)을 파일 상단에 우선 배치
        for rule in sorted(whitelist_rules):
            f.write(f"{rule}\n")
            
        # 그 아래에 차단 규칙 배치
        for rule in sorted(final_block_rules):
            f.write(f"{rule}\n")
            
    print(f"Done! Block: {len(final_block_rules):,}, Whitelist: {len(whitelist_rules):,}")

if __name__ == "__main__":
    main()
