import os
import re
import socket
import ssl
import time
import json
import requests
import base64
import websocket
import shutil
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor

# ------------------ Настройки ------------------
BASE_DIR = "checked"
FOLDER_RU = os.path.join(BASE_DIR, "RU_Best")
FOLDER_EURO = os.path.join(BASE_DIR, "My_Euro")

if os.path.exists(FOLDER_RU):
    shutil.rmtree(FOLDER_RU)
if os.path.exists(FOLDER_EURO):
    shutil.rmtree(FOLDER_EURO)
os.makedirs(FOLDER_RU, exist_ok=True)
os.makedirs(FOLDER_EURO, exist_ok=True)

TIMEOUT = 5
socket.setdefaulttimeout(TIMEOUT)
THREADS = 40

CACHE_HOURS = 6
CHUNK_LIMIT = 1000
EURO_CHUNK_LIMIT = 500
MAX_KEYS_TO_CHECK = 30000

MAX_PING_MS = 3000
FAST_LIMIT = 3000
MAX_HISTORY_AGE = 2 * 24 * 3600

RU_FILES = ["ru_white_part1.txt", "ru_white_part2.txt", "ru_white_part3.txt", "ru_white_part4.txt"]
EURO_FILES = ["my_euro_part1.txt", "my_euro_part2.txt", "my_euro_part3.txt"]

HISTORY_FILE = os.path.join(BASE_DIR, "history.json")
MY_CHANNEL = "@vlesstrojan"

URLS_RU = [
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/BLACK_VLESS_RUS_mobile.txt",
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/BLACK_SS%2BAll_RUS.txt",
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/WHITE-CIDR-RU-all.txt",
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/WHITE-CIDR-RU-checked.txt",
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/vsevjik/OBSpiskov/refs/heads/main/wwh",
    "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love",
    "https://etoneya.a9fm.site/1",
    "https://s3c3.001.gpucloud.ru/vahe4xkwi/cjdr"
]

URLS_MY = [
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/githubmirror/new/all_new.txt"
]

EURO_CODES = {
    "NL", "DE", "FI", "GB", "FR", "SE", "PL", "CZ", "AT", "CH",
    "IT", "ES", "NO", "DK", "BE", "IE", "LU", "EE", "LV", "LT"
}
BAD_MARKERS = ["CN", "IR", "KR", "BR", "IN", "RELAY", "POOL", "🇨🇳", "🇮🇷", "🇰🇷"]

# ------------------ Жёсткий фильтр русских выходных серверов ------------------

RU_MARKERS_STRICT = [
    ".ru", "moscow", "msk", "spb", "saint-peter", "russia",
    "россия", "москва", "питер", "ru-", "-ru.",
    "178.154.", "77.88.", "5.255.", "87.250.",
    "95.108.", "213.180.", "195.208.",
    "91.108.", "149.154.",
]

def is_russian_exit(key_str, host, country):
    # Сигнатура не тронута — country теперь уже exit-страна из detect_exit_country_via_http
    if country == "RU":
        return True
    # Резерв: маркеры по хосту/ключу на случай, если geo-API не ответил
    host_lower = host.lower()
    key_upper = key_str.upper()
    if host_lower.endswith(".ru"):
        return True
    for marker in RU_MARKERS_STRICT:
        if marker.lower() in host_lower:
            return True
        if marker.upper() in key_upper:
            return True
    return False

# ------------------ Страна → название + флаг ------------------

COUNTRY_NAMES_RU = {
    "RU": "Россия",
    "NL": "Нидерланды",
    "DE": "Германия",
    "FI": "Финляндия",
    "GB": "Великобритания",
    "FR": "Франция",
    "SE": "Швеция",
    "PL": "Польша",
    "CZ": "Чехия",
    "AT": "Австрия",
    "CH": "Швейцария",
    "IT": "Италия",
    "ES": "Испания",
    "NO": "Норвегия",
    "DK": "Дания",
    "BE": "Бельгия",
    "IE": "Ирландия",
    "LU": "Люксембург",
    "EE": "Эстония",
    "LV": "Латвия",
    "LT": "Литва",
}

COUNTRY_FLAGS = {
    "RU": "🇷🇺", "NL": "🇳🇱", "DE": "🇩🇪", "FI": "🇫🇮", "GB": "🇬🇧",
    "FR": "🇫🇷", "SE": "🇸🇪", "PL": "🇵🇱", "CZ": "🇨🇿", "AT": "🇦🇹",
    "CH": "🇨🇭", "IT": "🇮🇹", "ES": "🇪🇸", "NO": "🇳🇴", "DK": "🇩🇰",
    "BE": "🇧🇪", "IE": "🇮🇪", "LU": "🇱🇺", "EE": "🇪🇪", "LV": "🇱🇻",
    "LT": "🇱🇹",
}

def country_to_title_ru(code: str) -> str:
    return COUNTRY_NAMES_RU.get(code, code or "UNKNOWN")

def country_to_flag(code: str) -> str:
    return COUNTRY_FLAGS.get(code, "")

# ------------------ In-memory кэш IP → страна (чтобы не бомбить geo-API) ------------------
# Ключ: строка IP-адреса, значение: двухбуквенный код страны или "UNKNOWN"
_ip_country_cache: dict = {}

def detect_exit_country_via_http(proxy_host: str, proxy_port: int, scheme: str) -> str:
    """
    Определяет exit-страну сервера по его реальному IP через ip-api.com.
    Не маршрутизирует трафик через прокси-протокол — резолвит хост в IP,
    затем делает прямой запрос к geo-API. Для VLESS/VMess/Trojan exit IP —
    это и есть IP самого сервера (если нет relay).

    Возвращает двухбуквенный код страны или "UNKNOWN".
    """
    global _ip_country_cache
    try:
        # Резолвим хост в IP (с таймаутом через socket.setdefaulttimeout)
        ip = socket.gethostbyname(proxy_host)

        if ip in _ip_country_cache:
            return _ip_country_cache[ip]

        # ip-api.com: бесплатный, не требует ключа, лимит ~45 req/min
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=countryCode",
            timeout=4
        )
        if r.status_code == 200:
            data = r.json()
            code = data.get("countryCode", "UNKNOWN") or "UNKNOWN"
            _ip_country_cache[ip] = code
            return code
    except Exception:
        pass
    return "UNKNOWN"

# ------------------ Функции ------------------

def load_json(path):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            pass
    return {}

def save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except:
        pass

def get_country_fast(host, key_name):
    """Быстрый hint по доменному суффиксу / тексту ключа. Только fallback."""
    try:
        host = host.lower()
        name = key_name.upper()
        if host.endswith(".ru"):
            return "RU"
        if host.endswith(".de"):
            return "DE"
        if host.endswith(".nl"):
            return "NL"
        if host.endswith(".uk") or host.endswith(".co.uk"):
            return "GB"
        if host.endswith(".fr"):
            return "FR"
        for code in EURO_CODES:
            if code in name:
                return code
    except:
        pass
    return "UNKNOWN"

def is_garbage_text(key_str):
    upper = key_str.upper()
    for m in BAD_MARKERS:
        if m in upper:
            return True
    if ".ir" in key_str or ".cn" in key_str or "127.0.0.1" in key_str:
        return True
    return False

def fetch_keys(urls, tag):
    out = []
    print(f"Загрузка {tag}...")
    for url in urls:
        try:
            if "github.com" in url and "/blob/" in url:
                url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            r = requests.get(url, timeout=10)
            if r.status_code != 200:
                continue
            content = r.text.strip()
            if "://" not in content:
                try:
                    lines = base64.b64decode(content + "==").decode('utf-8', errors='ignore').splitlines()
                except:
                    lines = content.splitlines()
            else:
                lines = content.splitlines()
            for l in lines:
                l = l.strip()
                if len(l) > 2000:
                    continue
                if l.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                    if tag == "MY" and is_garbage_text(l):
                        continue
                    out.append((l, tag))
        except:
            pass
    return out

def check_single_key(data):
    key, tag = data
    try:
        if "@" in key and ":" in key:
            part = key.split("@")[1].split("?")[0].split("#")[0]
            host, port = part.split(":")[0], int(part.split(":")[1])
        else:
            return None, None, None, None, key

        is_tls = (
            "security=tls" in key or
            "security=reality" in key or
            "trojan://" in key or
            "vmess://" in key
        )
        is_ws = "type=ws" in key or "net=ws" in key
        path = "/"
        match = re.search(r"path=([^&]+)", key)
        if match:
            path = unquote(match.group(1))

        start = time.time()

        if is_ws:
            protocol = "wss" if is_tls else "ws"
            ws_url = f"{protocol}://{host}:{port}{path}"
            ws = websocket.create_connection(
                ws_url,
                timeout=TIMEOUT,
                sslopt={"cert_reqs": ssl.CERT_NONE},
                sockopt=((socket.SOL_SOCKET, socket.SO_RCVTIMEO, TIMEOUT),)
            )
            ws.close()
        elif is_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    pass
        else:
            with socket.create_connection((host, port), timeout=TIMEOUT):
                pass

        latency = int((time.time() - start) * 1000)

        # ── Определяем exit-страну по реальному IP сервера ──
        scheme = "wss" if (is_ws and is_tls) else ("ws" if is_ws else ("tls" if is_tls else "tcp"))
        country_exit = detect_exit_country_via_http(host, port, scheme)

        # Fallback: если geo-API не ответил — берём hint по хосту/ключу
        if country_exit == "UNKNOWN":
            country_exit = get_country_fast(host, key)

        return latency, tag, country_exit, host, key
    except:
        return None, None, None, None, key

def make_final_key(k_id, latency, country):
    title_ru = country_to_title_ru(country)
    flag = country_to_flag(country)
    if country and country != "UNKNOWN":
        title_full = f"{title_ru} {country}"
    else:
        title_full = title_ru
    info_str = f"[{latency}ms {title_full} {flag} {MY_CHANNEL}]"
    return f"{k_id}#{info_str}"

def extract_ping(key_str):
    try:
        label = key_str.split("#")[-1]
        match = re.search(r"(\d+)ms", label)
        if match:
            return int(match.group(1))
        return None
    except:
        return None

def save_exact(keys, folder, filename):
    path = os.path.join(folder, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(keys) if keys else "")
    return path

def save_fixed_chunks_ru(keys_list, folder):
    valid_keys = [k.strip() for k in keys_list if k and k.strip()]
    chunks = [
        valid_keys[i:i + CHUNK_LIMIT]
        for i in range(0, min(len(valid_keys), CHUNK_LIMIT * 4), CHUNK_LIMIT)
    ]
    while len(chunks) < 4:
        chunks.append([])
    for i, filename in enumerate(RU_FILES):
        save_exact(chunks[i] if i < len(chunks) else [], folder, filename)
        count = len(chunks[i]) if i < len(chunks) else 0
        print(f"  {filename}: {count} ключей")
    return RU_FILES

def save_fixed_chunks_euro(keys_list, folder):
    valid_keys = [k.strip() for k in keys_list if k and k.strip()]
    chunks = [
        valid_keys[i:i + EURO_CHUNK_LIMIT]
        for i in range(0, min(len(valid_keys), EURO_CHUNK_LIMIT * 3), EURO_CHUNK_LIMIT)
    ]
    while len(chunks) < 3:
        chunks.append([])
    for i, filename in enumerate(EURO_FILES):
        save_exact(chunks[i] if i < len(chunks) else [], folder, filename)
        count = len(chunks[i]) if i < len(chunks) else 0
        print(f"  {filename}: {count} ключей")
    return EURO_FILES

def save_chunked(keys_list, folder, base_name, chunk_size=None):
    if chunk_size is None:
        chunk_size = CHUNK_LIMIT
    valid_keys = [k.strip() for k in keys_list if k and k.strip()]
    chunks = [valid_keys[i:i + chunk_size] for i in range(0, len(valid_keys), chunk_size)]
    file_names = []
    for idx, chunk in enumerate(chunks, start=1):
        filename = f"{base_name}_part{idx}.txt"
        save_exact(chunk, folder, filename)
        file_names.append(filename)
        print(f"  {filename}: {len(chunk)} ключей")
    return file_names

def generate_subscriptions_list():
    GITHUB_USER_REPO = "kort0881/vpn-checker-backend"
    BRANCH = "main"
    BASE_RAW = f"https://raw.githubusercontent.com/{GITHUB_USER_REPO}/{BRANCH}"

    subs_lines = []

    subs_lines.append("=== 🇷🇺 RUSSIA (FAST) ===")
    for filename in RU_FILES:
        subs_lines.append(f"{BASE_RAW}/checked/RU_Best/{filename}")
    subs_lines.append("")

    subs_lines.append("=== 🇷🇺 RUSSIA (ALL) ===")
    ru_all_candidates = sorted(
        f for f in os.listdir(FOLDER_RU)
        if f.startswith("ru_white_all_part") and f.endswith(".txt")
    )
    for fname in ru_all_candidates[:2]:
        subs_lines.append(f"{BASE_RAW}/checked/RU_Best/{fname}")
    subs_lines.append("")

    subs_lines.append("=== 🇪🇺 EUROPE (FAST) ===")
    for filename in EURO_FILES:
        subs_lines.append(f"{BASE_RAW}/checked/My_Euro/{filename}")
    subs_lines.append("")

    subs_lines.append("=== 🇪🇺 EUROPE (ALL) ===")
    euro_all_candidates = sorted(
        f for f in os.listdir(FOLDER_EURO)
        if f.startswith("my_euro_all_part") and f.endswith(".txt")
    )
    for fname in euro_all_candidates[:2]:
        subs_lines.append(f"{BASE_RAW}/checked/My_Euro/{fname}")
    subs_lines.append("")

    subs_lines.append("=== ✅ WHITE RUSSIA (ALL) ===")
    subs_lines.append(f"{BASE_RAW}/checked/RU_Best/ru_white_all_WHITE.txt")
    subs_lines.append("")

    subs_lines.append("=== ✅ WHITE EUROPE (ALL) ===")
    subs_lines.append(f"{BASE_RAW}/checked/My_Euro/my_euro_all_WHITE.txt")
    subs_lines.append("")

    subs_lines.append("=== ⚠️ BLACK RUSSIA (ALL) ===")
    subs_lines.append(f"{BASE_RAW}/checked/RU_Best/ru_white_all_BLACK.txt")
    subs_lines.append("")

    subs_lines.append("=== ⚠️ BLACK EUROPE (ALL) ===")
    subs_lines.append(f"{BASE_RAW}/checked/My_Euro/my_euro_all_BLACK.txt")

    subs_path = os.path.join(BASE_DIR, "subscriptions_list.txt")
    with open(subs_path, "w", encoding="utf-8") as f:
        f.write("\n".join(subs_lines))

    print(f"\n📋 subscriptions_list.txt создан ({len([l for l in subs_lines if l.startswith('http')])} ссылок):")
    for line in subs_lines:
        if line:
            print(f"  {line}")

    return subs_path

# ------------------ MAIN ------------------

if __name__ == "__main__":
    print("=== CHECKER v5 (FAST/ALL + WHITE/BLACK) ===")
    print(f"Параметры: CACHE={CACHE_HOURS}h, MAX_PING={MAX_PING_MS}ms, FAST={FAST_LIMIT}, HISTORY={MAX_HISTORY_AGE//3600}h")

    history = load_json(HISTORY_FILE)
    tasks = fetch_keys(URLS_RU, "RU") + fetch_keys(URLS_MY, "MY")

    unique_tasks = {k: tag for k, tag in tasks}
    all_items = list(unique_tasks.items())

    if len(all_items) > MAX_KEYS_TO_CHECK:
        all_items = all_items[:MAX_KEYS_TO_CHECK]

    current_time = time.time()
    to_check = []
    res_ru = []
    res_euro = []
    dead_ru = []
    dead_euro = []

    print(f"\n📊 Всего уникальных ключей: {len(all_items)}")

    for k, tag in all_items:
        k_id = k.split("#")[0]
        cached = history.get(k_id)

        if cached and (current_time - cached["time"] < CACHE_HOURS * 3600) and cached["alive"]:
            # country в кэше — уже exit-страна (для старых записей — hint, обновится при следующей проверке)
            latency = cached["latency"]
            country = cached.get("country", "UNKNOWN")
            host = cached.get("host", "")
            final = make_final_key(k_id, latency, country)

            if tag == "RU":
                res_ru.append(final)
            elif tag == "MY" and not is_russian_exit(k, host, country):
                res_euro.append(final)
        else:
            to_check.append((k, tag))

    print(f"✅ Из кэша: RU={len(res_ru)}, EURO={len(res_euro)}")
    print(f"🔍 На проверку: {len(to_check)}")

    if to_check:
        checked_count = 0
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            future_to_item = {executor.submit(check_single_key, item): item for item in to_check}

            for future in future_to_item:
                key, tag = future_to_item[future]
                res = future.result()
                latency, _, country, host, original_key = res

                if latency is None:
                    if tag == "RU":
                        dead_ru.append(original_key)
                    elif tag == "MY":
                        dead_euro.append(original_key)
                    continue

                k_id = original_key.split("#")[0]

                # Сохраняем exit-страну (формат history не меняется)
                history[k_id] = {
                    "alive": True,
                    "latency": latency,
                    "time": time.time(),
                    "country": country,   # теперь exit-страна
                    "host": host,
                }

                final = make_final_key(k_id, latency, country)

                if tag == "RU":
                    res_ru.append(final)
                elif tag == "MY" and not is_russian_exit(original_key, host, country):
                    res_euro.append(final)

                checked_count += 1

        print(f"✅ Проверено успешно: {checked_count}")

    save_json(
        HISTORY_FILE,
        {
            k: v
            for k, v in history.items()
            if current_time - v["time"] < MAX_HISTORY_AGE
        },
    )

    res_ru_clean = [k for k in res_ru if extract_ping(k) is not None and extract_ping(k) <= MAX_PING_MS]
    res_euro_clean = [k for k in res_euro if extract_ping(k) is not None and extract_ping(k) <= MAX_PING_MS]

    res_ru_clean.sort(key=extract_ping)
    res_euro_clean.sort(key=extract_ping)

    print(f"\n📈 После фильтрации (≤ {MAX_PING_MS} ms) и сортировки:")
    print(f"  RU: {len(res_ru_clean)} ключей")
    print(f"  EURO: {len(res_euro_clean)} ключей")

    res_ru_fast = res_ru_clean[:FAST_LIMIT]
    res_euro_fast = res_euro_clean[:FAST_LIMIT]
    res_ru_all = res_ru_clean
    res_euro_all = res_euro_clean

    print(f"\n🚀 FAST слои (топ {FAST_LIMIT}):")
    print(f"  RU FAST: {len(res_ru_fast)}")
    print(f"  EURO FAST: {len(res_euro_fast)}")

    print(f"\n💾 Сохранение RU FAST → {FOLDER_RU}:")
    save_fixed_chunks_ru(res_ru_fast, FOLDER_RU)

    print(f"\n💾 Сохранение EURO FAST → {FOLDER_EURO} (по {EURO_CHUNK_LIMIT} ключей):")
    save_fixed_chunks_euro(res_euro_fast, FOLDER_EURO)

    print(f"\n💾 Сохранение RU ALL → {FOLDER_RU}:")
    ru_all_files = save_chunked(res_ru_all, FOLDER_RU, "ru_white_all")

    print(f"\n💾 Сохранение EURO ALL → {FOLDER_EURO} (по {EURO_CHUNK_LIMIT} ключей):")
    euro_all_files = save_chunked(res_euro_all, FOLDER_EURO, "my_euro_all", chunk_size=EURO_CHUNK_LIMIT)

    print(f"\n💾 WHITE/BLACK → {FOLDER_RU}:")
    save_exact(res_ru_all, FOLDER_RU, "ru_white_all_WHITE.txt")
    save_exact(dead_ru, FOLDER_RU, "ru_white_all_BLACK.txt")

    print(f"\n💾 WHITE/BLACK → {FOLDER_EURO}:")
    save_exact(res_euro_all, FOLDER_EURO, "my_euro_all_WHITE.txt")
    save_exact(dead_euro, FOLDER_EURO, "my_euro_all_BLACK.txt")

    generate_subscriptions_list()

    print("\n✅ SUCCESS: FAST/ALL + WHITE/BLACK GENERATED")
    print(f"  RU FAST: {len(res_ru_fast)}, RU WHITE: {len(res_ru_all)}, RU BLACK: {len(dead_ru)}")
    print(f"  EURO FAST: {len(res_euro_fast)}, EURO WHITE: {len(res_euro_all)}, EURO BLACK: {len(dead_euro)}")































































































































































































































































