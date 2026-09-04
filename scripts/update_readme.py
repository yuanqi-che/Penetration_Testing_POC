import feedparser
import os
import re
import requests # 引入 requests 库来处理网络请求

# ================= 配置区域 =================
RSS_URL = "https://mrxn.net/rss.php"
README_PATH = "README.md"
COMMIT_MSG_FILE = ".commit_titles.txt"
MAX_TITLES_IN_MSG = 5

# 伪装 User-Agent，防止被服务器屏蔽 GitHub Actions 的 IP
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

# 关键词列表
WEB_KEYWORDS = [
    'rce', 'sql', 'xss', 'csrf', 'upload', 'injection', 'web', 'cms', 
    '文件上传', '文件读取', 'sql注入', '信息泄露', '命令执行', 
    '目录遍历', '目录穿越', 'xxe', 'bypass', 'auth', '漏洞'
]

START_MARKER_REGEX = r'id="head4">Web APP</span>' 
END_MARKER_REGEX = r'id="head5">'                 
# ===========================================

def fetch_rss_entries():
    """获取 RSS 并返回解析后的数据列表"""
    print(f"Fetching RSS from {RSS_URL}...")
    try:
        # 使用 requests 获取内容，绕过简单的反爬
        response = requests.get(RSS_URL, headers=HEADERS, timeout=30)
        response.raise_for_status()
        
        # 将内容传给 feedparser
        feed = feedparser.parse(response.content)
        
        entries = []
        print(f"DEBUG: Fetched {len(feed.entries)} total items from RSS feed.")
        
        for entry in feed.entries:
            entries.append({
                "title": entry.title,
                "link": entry.link
            })
        return entries
    except Exception as e:
        print(f"Error fetching RSS: {e}")
        return []

def is_relevant(title):
    """关键词过滤"""
    title_lower = title.lower()
    if any(keyword in title_lower for keyword in WEB_KEYWORDS):
        return True
    return False

def get_existing_urls(content_lines):
    """提取现有链接用于去重"""
    urls = set()
    link_pattern = re.compile(r'\]\((http[s]?://.*?)\)')
    for line in content_lines:
        found = link_pattern.findall(line)
        for url in found:
            urls.add(url.strip())
    return urls

def update_readme():
    if not os.path.exists(README_PATH):
        print(f"Error: {README_PATH} not found.")
        return

    with open(README_PATH, 'r', encoding='utf-8') as f:
        content = f.read()
    
    lines = content.splitlines()
    
    # 1. 定位区块
    start_index = -1
    end_index = -1
    
    for i, line in enumerate(lines):
        if re.search(START_MARKER_REGEX, line):
            start_index = i
        elif start_index != -1 and re.search(END_MARKER_REGEX, line):
            end_index = i
            break
            
    if start_index == -1 or end_index == -1:
        print("Error: Markers not found in README.md")
        return

    # 2. 获取该区块内现有的 URL (去重)
    existing_urls = get_existing_urls(lines[start_index:end_index])
    print(f"Existing links count in target section: {len(existing_urls)}")

    # 3. 处理 RSS 数据
    rss_data = fetch_rss_entries()
    entries_to_add = []

    new_titles = []
    print("--- Start Filtering ---")
    for item in rss_data:
        title = item['title']
        link = item['link']

        # DEBUG: 打印处理过程
        if not is_relevant(title):
            # print(f"Skipping (Keyword mismatch): {title}") 
            continue

        if link.strip() in existing_urls:
            print(f"Skipping (Duplicate): {title}")
            continue
        
        print(f"Found NEW Entry: {title}")
        entries_to_add.append(f"- [{title}]({link})")
        new_titles.append(title)
    print("--- End Filtering ---")

    if not entries_to_add:
        print("Result: No new entries to write.")
        if os.path.exists(COMMIT_MSG_FILE):
            os.remove(COMMIT_MSG_FILE)
        return

    print(f"Action: Adding {len(entries_to_add)} new entries...")

    # 4. 插入位置
    insert_pos = end_index 
    while insert_pos > start_index and lines[insert_pos-1].strip() == "":
        insert_pos -= 1

    for entry in reversed(entries_to_add):
        lines.insert(insert_pos, entry)
    
    with open(README_PATH, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))
    print("UPDATE SUCCESSFUL: README.md has been modified.")

    # 生成 commit message 并写入临时文件
    n = len(new_titles)
    displayed = new_titles[:MAX_TITLES_IN_MSG]
    titles_str = " | ".join(displayed)
    if n > MAX_TITLES_IN_MSG:
        titles_str += f" ... 等共{n}篇"
    commit_msg = f"docs: 更新 {n} 篇文章 - {titles_str} [skip ci]"
    with open(COMMIT_MSG_FILE, 'w', encoding='utf-8') as f:
        f.write(commit_msg)
    print(f"Commit message written: {commit_msg}")

if __name__ == "__main__":
    update_readme()
