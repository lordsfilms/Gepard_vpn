import os
import re
import html
import socket
import ssl
import time
from datetime import datetime
from urllib.parse import quote, unquote
import websocket  # Библиотека для WebSocket

# ------------------ Настройки ------------------
# В GitHub Actions папки будут создаваться относительно скрипта
KEYS_FOLDER = "keys"          # Сюда мы будем класть исходные ключи (или качать их)
NEW_KEYS_FOLDER = "checked"   # Сюда скрипт положит результат
os.makedirs(KEYS_FOLDER, exist_ok=True)
os.makedirs(NEW_KEYS_FOLDER, exist_ok=True)

TIMEOUT = 3   # 3 секунды достаточно для быстрого чека
RETRIES = 1   # 1 попытка для скорости (в облаке лучше быстрее)

timestamp = datetime.now().strftime("%Y%m%d_%H%M")
LIVE_KEYS_FILE = os.path.join(NEW_KEYS_FOLDER, "live_keys.txt") # Фиксированное имя файла для удобства ссылок
LOG_FILE = os.path.join(NEW_KEYS_FOLDER, "log.txt")

MY_CHANNEL = "@vlesstrojan" 

# ------------------ Функции ------------------
def log(msg: str):
    print(msg)
    # В GitHub Actions лог в файл не обязателен, все видно в консоли, но оставим
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as lf:
            lf.write(msg + "\n")
    except: pass

def decode_html_entities(key):
    return html.unescape(key)

def load_all_keys(folder):
    all_keys = []
    if not os.path.isdir(folder):
        return all_keys
    for filename in os.listdir(folder):
        full_path = os.path.join(folder, filename)
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and "://" in line: # Простая проверка на мусор
                        all_keys.append(line)
        except: pass
    return all_keys

def remove_duplicates(keys):
    return list(set(keys))

def extract_host_port(key):
    # Универсальный парсер VLESS/VMess/Trojan/SS
    try:
        if "@" in key and ":" in key:
            # Ищем часть после @ и до ? или #
            after_at = key.split("@")[1]
            main_part = re.split(r'[?#]', after_at)[0]
            if ":" in main_part:
                host, port = main_part.split(":")
                return host, int(port)
    except: return None, None
    return None, None

def classify_latency(latency_ms: int) -> str:
    if latency_ms < 200: return "fast"
    if latency_ms < 800: return "normal"
    return "slow"

def measure_latency(key, host, port, timeout=TIMEOUT):
    """
    Гибридная проверка: WebSocket или TCP
    """
    # Определяем параметры из ссылки
    is_tls = 'security=tls' in key or 'security=reality' in key or 'trojan://' in key or 'vmess://' in key
    is_ws = 'type=ws' in key or 'net=ws' in key
    
    # Пытаемся вытащить path для WS (если есть)
    path = "/"
    path_match = re.search(r'path=([^&]+)', key)
    if path_match: path = unquote(path_match.group(1))

    # Формируем URL
    protocol = "wss" if is_tls else "ws"
    
    # Если это не WS, но нужен TLS (простой VLESS-TLS / Trojan)
    if not is_ws and is_tls:
        try:
            start = time.time()
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    pass
            return int((time.time() - start) * 1000)
        except: return None

    # Если это WS (самое важное для Cloudflare)
    if is_ws:
        try:
            start = time.time()
            ws_url = f"{protocol}://{host}:{port}{path}"
            # Suppress SSL verification for speed/stability in checker
            ws = websocket.create_connection(ws_url, timeout=timeout, sslopt={"cert_reqs": ssl.CERT_NONE})
            ws.close()
            return int((time.time() - start) * 1000)
        except: return None

    # Обычный TCP (для чистого VLESS/Shadowsocks)
    try:
        start = time.time()
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return int((time.time() - start) * 1000)
    except: return None

def add_comment(key, latency, quality):
    # Добавляем инфо в хештег
    if "#" in key: base, _ = key.split("#", 1)
    else: base = key
    tag = f"{quality}_{latency}ms_{MY_CHANNEL}".replace(" ", "_")
    return f"{base}#{tag}"

# ------------------ Main ------------------
log("=== START CHECKER ===")
all_keys = load_all_keys(KEYS_FOLDER)
all_keys = remove_duplicates(all_keys)
log(f"Загружено уникальных ключей: {len(all_keys)}")

valid_count = 0
with open(LIVE_KEYS_FILE, "w", encoding="utf-8") as f_out:
    for i, key in enumerate(all_keys):
        key = decode_html_entities(key).strip()
        host, port = extract_host_port(key)
        
        if not host: continue

        latency = measure_latency(key, host, port)
        if latency is not None:
            qual = classify_latency(latency)
            final_key = add_comment(key, latency, qual)
            f_out.write(final_key + "\n")
            valid_count += 1
            print(f"[OK] {latency}ms | {host}")
        else:
            pass # print(f"[FAIL] {host}")

log(f"=== DONE. Valid keys: {valid_count} ===")
