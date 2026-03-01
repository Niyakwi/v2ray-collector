import os
import re
import base64
import socket
import requests
from urllib.parse import urlparse
from typing import List, Dict, Any

# ---------- НАСТРОЙКИ ----------
SOURCES_ENV_VAR = "SOURCES"  # имя переменной окружения со списком URL (каждый с новой строки)
TIMEOUT = 5  # таймаут tcping в секундах
# --------------------------------

def get_sources() -> List[str]:
    """Получить список источников из переменной окружения"""
    sources_str = os.environ.get(SOURCES_ENV_VAR, "")
    if not sources_str:
        print("❌ Переменная окружения SOURCES не задана!")
        return []
    # разделяем по строкам, удаляем пустые
    sources = [line.strip() for line in sources_str.splitlines() if line.strip()]
    return sources

def fetch_text(url: str) -> str:
    """Загрузить текст по URL"""
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"⚠️ Ошибка загрузки {url}: {e}")
        return ""

def extract_links(text: str) -> List[str]:
    """Извлечь все ссылки, похожие на прокси (vless://, vmess://, ss://, trojan://)"""
    pattern = r'(vless|vmess|ss|trojan)://[^\s<>"\']+'
    return re.findall(pattern, text)

def parse_vmess(link: str) -> Dict[str, Any]:
    """Попытаться распарсить vmess:// (может быть base64)"""
    try:
        b64 = link[8:]  # убираем 'vmess://'
        # иногда добавляют лишнее, пробуем декодировать
        decoded = base64.b64decode(b64).decode('utf-8')
        return json.loads(decoded)
    except:
        return {}

def get_host_port_from_link(link: str) -> tuple:
    """
    Извлечь хост и порт из ссылки прокси.
    Возвращает (host, port) или (None, None) если не удалось.
    """
    # Для vless, vmess, trojan, ss структура разная.
    # Пробуем стандартный URI parser для vless/vmess/trojan (они похожи)
    try:
        parsed = urlparse(link)
        if parsed.hostname:
            port = parsed.port or 443  # многие используют 443 по умолчанию
            return parsed.hostname, port
    except:
        pass

    # Для vmess может быть JSON
    if link.startswith('vmess://'):
        data = parse_vmess(link)
        if data and 'add' in data and 'port' in data:
            return data['add'], int(data['port'])

    # Для ss может быть после @
    if link.startswith('ss://'):
        # формат ss://method:password@host:port
        match = re.search(r'@([^:]+):(\d+)', link)
        if match:
            return match.group(1), int(match.group(2))

    # Для trojan обычно trojan://password@host:port
    if link.startswith('trojan://'):
        match = re.search(r'@([^:]+):(\d+)', link)
        if match:
            return match.group(1), int(match.group(2))

    return None, None

def tcping(host: str, port: int, timeout: float = TIMEOUT) -> bool:
    """Проверить, открыт ли порт на хосте (TCP ping)"""
    if not host or not port:
        return False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def is_working(link: str) -> bool:
    """Проверить, рабочий ли ключ (по tcping)"""
    host, port = get_host_port_from_link(link)
    if host and port:
        return tcping(host, port)
    return False

def main():
    print("🔄 Запуск сборщика ключей")
    sources = get_sources()
    if not sources:
        print("❌ Нет источников. Завершение.")
        return

    all_links = []
    for url in sources:
        print(f"📡 Загрузка {url}")
        text = fetch_text(url)
        if text:
            links = extract_links(text)
            print(f"   Найдено {len(links)} ссылок")
            all_links.extend(links)
        else:
            print(f"   Пропущен (пусто)")

    # Удаляем дубликаты, сохраняя порядок (можно использовать set, но порядок не важен)
    unique_links = list(dict.fromkeys(all_links))
    print(f"📊 Всего уникальных ссылок: {len(unique_links)}")

    # Проверка работоспособности
    working = []
    for i, link in enumerate(unique_links, 1):
        print(f"🔍 Проверка {i}/{len(unique_links)}: {link[:50]}...")
        if is_working(link):
            working.append(link)
            print("   ✅ рабочий")
        else:
            print("   ❌ не работает")

    print(f"✅ Рабочих ключей: {len(working)}")

    # Группировка по протоколам
    protocols = {
        'vless': [],
        'vmess': [],
        'ss': [],
        'trojan': [],
        'other': []
    }
    for link in working:
        if link.startswith('vless://'):
            protocols['vless'].append(link)
        elif link.startswith('vmess://'):
            protocols['vmess'].append(link)
        elif link.startswith('ss://'):
            protocols['ss'].append(link)
        elif link.startswith('trojan://'):
            protocols['trojan'].append(link)
        else:
            protocols['other'].append(link)

    # Запись в файлы
    output_dir = "subscription"
    os.makedirs(output_dir, exist_ok=True)
    for proto, links in protocols.items():
        if links:
            filename = os.path.join(output_dir, f"{proto}.txt")
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("\n".join(links))
            print(f"📁 Записано {len(links)} ключей в {filename}")

    # Также запишем общий файл со всеми рабочими
    all_working_file = os.path.join(output_dir, "all_working.txt")
    with open(all_working_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(working))
    print(f"📁 Записано {len(working)} ключей в {all_working_file}")

    print("✅ Готово!")

if __name__ == "__main__":
    main()
