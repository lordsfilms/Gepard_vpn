import os
import re
import html
import socket
import ssl
import time
import json
import requests
import base64
import websocket
from datetime import datetime
from urllib.parse import quote, unquote
from concurrent.futures import ThreadPoolExecutor # Для скорости!

# ------------------ Настройки ------------------
NEW_KEYS_FOLDER = "checked"
os.makedirs(NEW_KEYS_FOLDER, exist_ok=True)

TIMEOUT = 2
THREADS = 50          # Проверять 50 ключей одновременно (можно ставить до 100)
CACHE_HOURS = 12      # Верить истории 12 часов

LIVE_KEYS_FILE = os.path.join(NEW_KEYS_FOLDER, "live_keys.txt")
HISTORY_FILE = os.path.join(NEW_KEYS_FOLDER, "history.json")
MY_CHANNEL = "@vlesstrojan" 

URLS = [
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/githubmirror/new/all_new.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/vsevjik/OBSpiskov/refs/heads/main/wwh",
    "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love",
    "https://etoneya.a9fm.site/1",
    "https://s3c3.001.gpucloud.ru/vahe4xkwi/cjdr"
]

# ------------------ Функции ------------------

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except: pass
    return {}

def save_history(history):
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, ensure_ascii=False, indent=2)
    except: pass

def fetch_and_load_keys(urls):
    all_keys = set()
    print(f"Загрузка источников...")
    for url in urls:
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code != 200: continue
            
            content = resp.text.strip()
            # Простой детект: если похоже на base64 и нет протоколов
            if "://" not in content:
                try:
                    decoded = base64.b64decode(content + "==").decode('utf-8', errors='ignore')
                    lines = decoded.splitlines()
                except: lines = content.splitlines()
            else:
                lines = content.splitlines()

            for line in lines:
                line = line.strip()
                if line.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                    all_keys.add(line)
        except: pass
    return list(all_keys)

def check_single_key(key):
    """Функция для проверки ОДНОГО ключа (запускается в потоке)"""
    try:
        # Парсинг
        if "@" in key and ":" in key:
            part = key.split("@")[1].split("?")[0].split("#")[0]
            host, port = part.split(":")[0], int(part.split(":")[1])
        else: return None

        # Определение типа
        is_tls = 'security=tls' in key or 'security=reality' in key or 'trojan://' in key or 'vmess://' in key
        is_ws = 'type=ws' in key or 'net=ws' in key
        path = "/"
        match = re.search(r'path=([^&]+)', key)
        if match: path = unquote(match.group(1))

        # Тест
        start = time.time()
        
        if is_ws:
            protocol = "wss" if is_tls else "ws"
            ws_url = f"{protocol}://{host}:{port}{path}"
            ws = websocket.create_connection(ws_url, timeout=TIMEOUT, sslopt={"cert_reqs": ssl.CERT_NONE})
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
        
        return int((time.time() - start) * 1000)
    except:
        return None

# ------------------ Main ------------------
if __name__ == "__main__":
    print(f"=== FAST CHECKER (Threads: {THREADS}) ===")
    
    # 1. Загрузка
    history = load_history()
    keys_raw = fetch_and_load_keys(URLS)
    print(f"Всего ключей: {len(keys_raw)}")
    
    # 2. Фильтрация (что проверять, что брать из кэша)
    to_check = []     # (key_original, key_clean)
    results = []      # готовые строки для файла
    current_time = time.time()
    
    for k in keys_raw:
        k = html.unescape(k).strip()
        k_id = k.split("#")[0] # ID без хештега
        
        # Проверяем кэш
        cached = history.get(k_id)
        if cached and (current_time - cached['time'] < CACHE_HOURS * 3600) and cached['alive']:
            # Взять из кэша
            latency = cached['latency']
            tag = f"cached_{latency}ms_{MY_CHANNEL}"
            if "#" in k: base = k.split("#")[0]
            else: base = k
            results.append(f"{base}#{tag}")
        else:
            # Нужно проверять
            to_check.append(k)

    print(f"Взято из кэша: {len(results)}")
    print(f"Нужно проверить: {len(to_check)}")

    # 3. Многопоточная проверка
    print("Запуск потоков...")
    new_history_updates = {}
    
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        # Запускаем задачи
        future_to_key = {executor.submit(check_single_key, k): k for k in to_check}
        
        # Собираем результаты по мере готовности
        for i, future in enumerate(future_to_key):
            key = future_to_key[future]
            latency = future.result()
            
            k_id = key.split("#")[0]
            new_history_updates[k_id] = {
                'alive': latency is not None,
                'latency': latency,
                'time': current_time
            }

            if latency is not None:
                qual = "fast" if latency < 500 else "normal"
                tag = f"{qual}_{latency}ms_{MY_CHANNEL}"
                if "#" in key: base = key.split("#")[0]
                else: base = key
                results.append(f"{base}#{tag}")
            
            if i % 100 == 0:
                print(f"Checked {i}/{len(to_check)}")

    # 4. Сохранение
    # Объединяем старую историю с новыми данными
    history.update(new_history_updates)
    
    # Чистим совсем старое (>3 дней)
    clean_hist = {k:v for k,v in history.items() if current_time - v['time'] < 259200}
    save_history(clean_hist)

    with open(LIVE_KEYS_FILE, "w", encoding="utf-8") as f:
        for r in results:
            f.write(r + "\n")
            
    print(f"=== DONE. Valid: {len(results)} ===")










