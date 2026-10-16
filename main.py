#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
                    RUST PC CHECKER v3.2
                    Комплексная утилита проверки ПК
                    
    Назначение:
        - Сбор телеметрии с ПК игрока для проверки на читы
        - Анализ артефактов Windows (USN, Prefetch, BAM, Amcache)
        - Парсинг истории браузеров (Chrome, Edge, Yandex, Opera, Firefox)
        - Анализ торговых площадок (Funpay, LZT, Plati)
        - Поиск Steam аккаунтов и .maFile
        - Анализ запущенных процессов
        - Анализ автозагрузки
        - Анализ сетевых подключений
        - Анализ антивирусов
        - Шифрование отчёта и сохранение в Загрузки
        
    Автор: Rust Admin Team
    Версия: 3.2
    Дата: 2026-10-10
    
    Примечание по совместимости с антивирусами:
        - Убрано автоповышение прав через ShellExecuteW (runas)
        - Убран флаг CREATE_NO_WINDOW (окна процессов видны)
        - Убраны прямые вызовы advapi32.AdjustTokenPrivileges
        - Используются только стандартные Python-обёртки winreg
        - Скрипт требует ручной запуск от имени администратора
        
================================================================================
"""

# ============================================================================
# СЕКЦИЯ 1: ИМПОРТЫ СТАНДАРТНОЙ БИБЛИОТЕКИ
# ============================================================================

import sys
import os
import csv
import io
import re
import time
import json
import shutil
import socket
import sqlite3
import tempfile
import getpass
import platform
import subprocess
import winreg
import ctypes
import datetime as dt
import fnmatch
import hashlib
import struct
import traceback
from pathlib import Path
from urllib.parse import urlparse, unquote
from typing import List, Tuple, Dict, Any, Optional, Set, Union
from collections import defaultdict, Counter
import xml.etree.ElementTree as ET
import threading
import queue

# ============================================================================
# СЕКЦИЯ 2: ПРОВЕРКА ПРАВ АДМИНИСТРАТОРА (БЕЗ АВТОПОВЫШЕНИЯ)
# ============================================================================

def is_admin() -> bool:
    """
    Проверяет, запущен ли текущий процесс с правами администратора.
    
    Использует Windows API функцию IsUserAnAdmin() из shell32.dll.
    Это стандартная функция, которая не вызывает подозрений у антивирусов.
    
    Returns:
        bool: True если процесс запущен от администратора, False иначе.
    """
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def check_admin_rights() -> bool:
    """
    Проверяет наличие прав администратора.
    
    Если прав нет — выводит понятное сообщение и ждёт нажатия Enter.
    НЕ использует ShellExecuteW с verb="runas" (это триггерит антивирусы).
    Вместо этого просит пользователя вручную запустить скрипт от админа.
    
    Returns:
        bool: True если права есть, False иначе.
    """
    if is_admin():
        return True
    
    print("=" * 70)
    print("[!] ТРЕБУЮТСЯ ПРАВА АДМИНИСТРАТОРА")
    print("=" * 70)
    print()
    print("Этот скрипт должен быть запущен от имени администратора.")
    print()
    print("Как запустить правильно:")
    print("  1. Закройте это окно")
    print("  2. Нажмите правой кнопкой мыши на файл скрипта")
    print("  3. Выберите 'Запуск от имени администратора'")
    print()
    print("Без прав администратора скрипт не сможет прочитать:")
    print("  - USN Journal диска C:")
    print("  - Prefetch папку Windows")
    print("  - BAM и Amcache из реестра")
    print("  - Журналы событий Windows")
    print()
    input("Нажмите Enter для выхода...")
    return False


# ============================================================================
# СЕКЦИЯ 3: АВТОУСТАНОВКА ЗАВИСИМОСТЕЙ
# ============================================================================

def ensure_dependencies() -> None:
    """
    Проверяет наличие необходимых библиотек и автоматически устанавливает их.
    
    Использует subprocess для вызова pip с текущим интерпретатором Python,
    что гарантирует установку в правильное окружение.
    
    Необходимые библиотеки:
    - cryptography: для шифрования отчётов (Fernet/AES)
    - colorama: для цветного вывода в консоль
    """
    required = {
        "cryptography": "cryptography",
        "colorama": "colorama"
    }
    
    missing = []
    for import_name, package_name in required.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append(package_name)
    
    if missing:
        print(f"[!] Отсутствуют библиотеки: {', '.join(missing)}")
        print("[*] Устанавливаю...")
        try:
            # Запускаем pip БЕЗ CREATE_NO_WINDOW — окно pip будет видно
            # Это безопаснее для антивирусов
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install"] + missing
            )
            print("[+] Все библиотеки успешно установлены!")
        except subprocess.CalledProcessError as e:
            print(f"[X] Ошибка установки: {e}")
            print(f"    Попробуйте вручную: {sys.executable} -m pip install {' '.join(missing)}")
            input("\nНажмите Enter для выхода...")
            sys.exit(1)


ensure_dependencies()

# ============================================================================
# СЕКЦИЯ 4: ИМПОРТЫ СТОРОННИХ БИБЛИОТЕК
# ============================================================================

from cryptography.fernet import Fernet, InvalidToken
from colorama import Fore, Style, init as colorama_init

# Инициализация colorama для корректной работы цветов в Windows
colorama_init(autoreset=False)

# ============================================================================
# СЕКЦИЯ 5: КОНФИГУРАЦИЯ И КОНСТАНТЫ
# ============================================================================

# Мастер-ключ для шифрования отчётов
# ВАЖНО: Этот ключ должен быть идентичным в scanner.py и decryptor.py
MASTER_KEY = b'ZmDfcTF7_60KxYfi1rFV2XyBmL9KZ3pQwR8sNjTgV4c='

# Пути и имена файлов
TEMP_DIR = tempfile.gettempdir()
REPORT_FILENAME = 'PC_Check_Report.txt'
REPORT_ENC_EXT = '.enc'

# Временные интервалы (в секундах)
SEVEN_DAYS_SEC = 7 * 24 * 3600      # 7 дней
THREE_DAYS_SEC = 3 * 24 * 3600      # 3 дня
ONE_DAY_SEC = 24 * 3600             # 1 день
ONE_HOUR_SEC = 3600                 # 1 час

# Расширения исполняемых файлов для анализа
EXECUTABLE_EXTS = {'.exe', '.sys', '.dll', '.bat', '.cmd', '.ps1', '.vbs'}

# Подозрительные пути (файлы здесь считаются более подозрительными)
SUSPICIOUS_PATHS = [
    r'\temp\\',
    r'\tmp\\',
    r'\appdata\\',
    r'\downloads\\',
    r'\public\\',
    r'\users\\public\\',
    r'\programdata\\',
    r'\windows\\temp\\',
]

# ============================================================================
# СЕКЦИЯ 6: БАЗЫ ДАННЫХ ЧИТОВ И СПУФЕРОВ
# ============================================================================

# Список известных читов для Rust
RUST_CHEATS_BASE = [
    'cheat', 'hack', 'loader', 'bypass', 'inject', 'rustme', 'umbrella',
    'skinchanger', 'macro', 'recoil', 'soft', 'макрос', 'чит', 'софт',
    'mrpro cis', 'mr pro', 'stealth full', 'stealth lite', 'eclipse',
    'xernel', 'xernel spoofer', 'arcane', 'ancient', 'ancient v2',
    'mason rust full', 'mason rust internal', 'mason lite', 'morphine',
    'onehit', 'cyber', 'evidence', 'courier full', 'courierscript', 'courier',
    'radiance external', 'radiance', 'udp', 'mira', 'flamingo',
    'smg chams', 'smg', 'memez external', 'memez internalx', 'memez lite',
    'memezmax', 'memez norecoil macro', 'memez', 'btg', 'rampart full',
    'kiero', 'wintorez', 'calamari', 'doza full', 'doza lite',
    'vengeance', 'vengeance lite', 'vengeance full', 'salamander', 'kali',
    'disconnect internal', 'interiumware', 'omega', 'unticvare web radar',
    'pussycat', 'fluent rust', 'neural.cc', 'getadd-ons full', 'agrotek',
    'enigma', 'enot hook', 'bleak', 'goyda', 'titanix', 'kernel',
    'wr private', 'superiority v2', 'cyb', 'muco', 'rubin', 'fsociety',
    'vilonity', 'axios', 'exodus', 'nullwave', 'neddly.cc', 'sxsoldier',
    'rust tweaker', 'rustsentinel', 'rust helper pro', 'rust helper full',
    'rust++', 'battlemetrics premium', 'enardo recycler', 'rustadmin',
    'nexus rust+', 'aimbot', 'wallhack', 'esp', 'triggerbot', 'silentaim',
    'ragebot', 'legitbot', 'backtrack', 'antiaim', 'resolver', 'fakelag'
]

# Список известных спутников HWID
HWID_SPOOFERS_BASE = [
    'pink panther perm swoofer', 'pink perm swf', 'pink perm swoofer',
    'ub.gg hwid', 'hwid swoofer', 'permanent hwid swoofer',
    'sync замена hwid', 'matrix internal', 'goyda hwid', 'titanix swoofer',
    'neddly.cc swoofer', 'nullwave swoofer', 'sxsoldier swoofer',
    'm-rust swoofer', 'perm hwid woofer', 'temp hwid woofer', 'smg hwid',
    'verse hwid', 'hwid-changer xernel', 'hwid spoofer', 'hwid changer',
    'disk serial changer', 'smbios modifier', 'motherboard spoofer'
]

# Регулярные выражения для Funpay
FUNPAY_OFFER_MASK = r'funpay\.(?:com|global)/lots/offer\?id='
FUNPAY_RUST_CATEGORIES = ['/lots/1199/', '/lots/1200/', '/lots/746/', '/chips/141/']
DLC_KEYWORDS = {'dlc', 'add-on', 'addon', 'дополнение'}

# ============================================================================
# СЕКЦИЯ 7: КОНФИГУРАЦИЯ БРАУЗЕРОВ
# ============================================================================

# Chromium-браузеры: имя -> (путь в LocalAppData или AppData)
BROWSERS_CHROMIUM = {
    'Chrome':  ('Google', 'Chrome', 'User Data'),
    'Edge':    ('Microsoft', 'Edge', 'User Data'),
    'Yandex':  ('Yandex', 'YandexBrowser', 'User Data'),
    'Opera':   ('Opera Software', 'Opera Stable'),
    'Brave':   ('BraveSoftware', 'Brave-Browser', 'User Data'),
    'Vivaldi': ('Vivaldi', 'User Data'),
}

# ============================================================================
# СЕКЦИЯ 8: ПУТИ К СИСТЕМНЫМ АРТЕФАКТАМ
# ============================================================================

PREFETCH_DIR = r'C:\Windows\Prefetch'
BAM_PATH = r'SYSTEM\CurrentControlSet\Services\bam\UserSettings'
AMCACHE_PATH = r'C:\Windows\AppCompat\Programs\Amcache.hve'
AMCACHE_TEMP_HIVE = 'RUSTCHK_AMCACHE'

# Директории для глубокого сканирования
TARGET_DIRS = [
    os.environ.get('TEMP', ''),
    os.environ.get('APPDATA', ''),
    os.environ.get('LOCALAPPDATA', ''),
    r'C:\Windows\System32\drivers',
    r'C:\Windows\Temp',
    os.path.expanduser('~\\Downloads'),
]

# Пути к конфигурации Steam
STEAM_PATHS = [
    r'C:\Program Files (x86)\Steam\config',
    r'C:\Program Files\Steam\config',
]

# ============================================================================
# СЕКЦИЯ 9: СИСТЕМА WHITELIST
# ============================================================================

# Глобальные списки whitelist
WHITELIST_PATHS: List[str] = []
WHITELIST_NAMES: List[str] = []
WHITELIST_DOMAINS: List[str] = []


def load_whitelist() -> None:
    """
    Загружает whitelist.txt из встроенных данных .exe или из текущей папки.
    
    Файл разделён на три секции:
    - ПУТИ ФАЙЛОВ: маски путей (поддерживаются wildcards)
    - ИМЕНА ФАЙЛОВ: точные имена файлов
    - ДОМЕНЫ: маски доменов для фильтрации истории браузеров
    """
    global WHITELIST_PATHS, WHITELIST_NAMES, WHITELIST_DOMAINS
    
    # Определяем путь к данным приложения
    # getattr подавляет предупреждение Pylance о несуществующем атрибуте
    application_path = getattr(sys, '_MEIPASS', None)
    
    if application_path is None:
        # Запуск из .py скрипта (не из .exe)
        application_path = os.path.dirname(os.path.abspath(__file__))
    
    wl_path = os.path.join(application_path, 'whitelist.txt')
    
    # Fallback: пробуем текущую рабочую директорию
    if not os.path.isfile(wl_path):
        wl_path = os.path.join(os.getcwd(), 'whitelist.txt')
        
    if not os.path.isfile(wl_path):
        return
    
    section = None  # 'path' | 'name' | 'domain'
    
    try:
        with open(wl_path, 'r', encoding='utf-8') as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith('#'):
                    # Детектим секции по заголовкам
                    if 'ПУТИ ФАЙЛОВ' in line:
                        section = 'path'
                    elif 'ИМЕНА ФАЙЛОВ' in line:
                        section = 'name'
                    elif 'ДОМЕНЫ' in line or 'КЛЮЧЕВЫЕ' in line:
                        section = 'domain'
                    continue
                
                if section == 'path':
                    WHITELIST_PATHS.append(line.lower())
                elif section == 'name':
                    WHITELIST_NAMES.append(line.lower())
                elif section == 'domain':
                    WHITELIST_DOMAINS.append(line.lower())
    except Exception as e:
        print(f"[!] Ошибка чтения whitelist.txt: {e}")


def is_path_whitelisted(path: str) -> bool:
    """
    Проверяет, попадает ли путь под whitelist (wildcards).
    
    Args:
        path: Путь к файлу для проверки
        
    Returns:
        bool: True если путь в whitelist, False иначе
    """
    if not WHITELIST_PATHS:
        return False
    path_lower = path.lower().replace('/', '\\')
    return any(fnmatch.fnmatch(path_lower, pat) for pat in WHITELIST_PATHS)


def is_name_whitelisted(name: str) -> bool:
    """
    Проверяет имя файла (Prefetch/BAM/Amcache).
    
    Args:
        name: Имя файла для проверки
        
    Returns:
        bool: True если имя в whitelist, False иначе
    """
    if not WHITELIST_NAMES:
        return False
    return name.lower() in WHITELIST_NAMES


def is_domain_whitelisted(url: str) -> bool:
    """
    Проверяет URL по доменным маскам whitelist.
    
    Args:
        url: URL для проверки
        
    Returns:
        bool: True если домен в whitelist, False иначе
    """
    if not WHITELIST_DOMAINS:
        return False
    try:
        host = urlparse(url).hostname or ''
    except Exception:
        host = ''
    if not host:
        return False
    host_l = host.lower()
    for pattern in WHITELIST_DOMAINS:
        if fnmatch.fnmatch(host_l, pattern):
            return True
    # Проверяем также полные URL паттерны (google.com/search)
    url_l = url.lower()
    for pattern in WHITELIST_DOMAINS:
        if '/' in pattern and pattern in url_l:
            return True
    return False


# ============================================================================
# СЕКЦИЯ 10: КРИПТОГРАФИЯ
# ============================================================================

# Инициализация Fernet с мастер-ключом
_fernet = Fernet(MASTER_KEY)


def encrypt_text(text: str) -> bytes:
    """
    Шифрует текст с помощью Fernet (AES-128-CBC).
    
    Args:
        text: Текст для шифрования
        
    Returns:
        bytes: Зашифрованные данные
    """
    return _fernet.encrypt(text.encode('utf-8'))


# ============================================================================
# СЕКЦИЯ 11: КОНСОЛЬНЫЙ ВЫВОД
# ============================================================================

class Console:
    """
    Класс для цветного вывода в консоль.
    
    Использует colorama для кроссплатформенной поддержки цветов.
    """
    
    @staticmethod
    def info(msg: str) -> None:
        """Выводит информационное сообщение (голубой цвет)."""
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def ok(msg: str) -> None:
        """Выводит сообщение об успехе (зелёный цвет)."""
        print(f"{Fore.GREEN}[ОК]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def warn(msg: str) -> None:
        """Выводит предупреждение (жёлтый цвет)."""
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def fail(msg: str) -> None:
        """Выводит сообщение об ошибке (красный цвет)."""
        print(f"{Fore.RED}[X]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def critical(msg: str) -> None:
        """Выводит критическое сообщение (ярко-красный цвет)."""
        print(f"{Fore.RED}{Style.BRIGHT}[КРИТИЧНО]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def header(title: str) -> None:
        """Выводит заголовок с рамкой."""
        width = 70
        print(f"\n{Fore.WHITE}{Style.BRIGHT}{'=' * width}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{Style.BRIGHT} {title}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{Style.BRIGHT}{'=' * width}{Style.RESET_ALL}")
    
    @staticmethod
    def progress(current: int, total: int, prefix: str = "") -> None:
        """Выводит прогресс-бар."""
        percent = (current / total * 100) if total > 0 else 0
        bar_len = 40
        filled = int(bar_len * current / total) if total > 0 else 0
        bar = '█' * filled + '░' * (bar_len - filled)
        print(f"\r{Fore.CYAN}{prefix}[{bar}] {percent:.1f}%{Style.RESET_ALL}", end='', flush=True)
        if current >= total:
            print()  # Перенос строки после завершения


console = Console()

# ============================================================================
# СЕКЦИЯ 12: БУФЕР ОТЧЁТА
# ============================================================================

class ReportBuffer:
    """
    Буфер для формирования текстового отчёта.
    
    Собирает все события, находки и статистику в структурированный текст,
    который затем шифруется и сохраняется.
    """
    
    def __init__(self):
        """Инициализация буфера отчёта."""
        self.lines: List[str] = []
        self.start_time = dt.datetime.now()
        self.stats: Dict[str, int] = defaultdict(int)
        self._write_header()
    
    def _write_header(self) -> None:
        """Записывает заголовок отчёта с информацией о системе."""
        try:
            hostname = socket.gethostname()
        except Exception:
            hostname = "unknown"
        
        try:
            username = os.getlogin()
        except Exception:
            username = os.environ.get('USERNAME', 'unknown')
        
        self.lines.append("=" * 70)
        self.lines.append("RUST PC CHECK REPORT v3.2")
        self.lines.append("=" * 70)
        self.lines.append(f"Generated: {self.start_time:%Y-%m-%d %H:%M:%S}")
        self.lines.append(f"Hostname: {hostname}")
        self.lines.append(f"User: {username}")
        try:
            self.lines.append(f"OS: {platform.system()} {platform.release()} ({platform.version()})")
        except Exception:
            self.lines.append("OS: Windows")
        try:
            self.lines.append(f"Python: {platform.python_version()}")
        except Exception:
            pass
        self.lines.append("=" * 70)
    
    def section(self, title: str) -> None:
        """Добавляет разделитель секции."""
        self.lines.append("")
        self.lines.append(f"--- {title.upper()} ---")
    
    def event(self, trigger: str, description: str, timestamp: Optional[dt.datetime] = None) -> None:
        """
        Добавляет событие в отчёт.
        
        Args:
            trigger: Тип события (например, "PREFETCH-TRIGGER")
            description: Описание события
            timestamp: Время события (если None, используется текущее время)
        """
        ts = timestamp or dt.datetime.now()
        self.lines.append(f"[{ts:%Y-%m-%d %H:%M:%S}] [{trigger}] {description}")
        self.stats[trigger] += 1
    
    def info(self, description: str) -> None:
        """Добавляет информационную строку."""
        self.lines.append(f"[INFO] {description}")
    
    def warning(self, description: str) -> None:
        """Добавляет предупреждение."""
        self.lines.append(f"[WARNING] {description}")
    
    def error(self, description: str) -> None:
        """Добавляет ошибку."""
        self.lines.append(f"[ERROR] {description}")
    
    def get_text(self) -> str:
        """
        Возвращает полный текст отчёта.
        
        Returns:
            str: Текст отчёта
        """
        return "\n".join(self.lines)
    
    def get_stats(self) -> Dict[str, int]:
        """
        Возвращает статистику событий.
        
        Returns:
            Dict[str, int]: Словарь {trigger: count}
        """
        return dict(self.stats)


# ============================================================================
# СЕКЦИЯ 13: УТИЛИТЫ
# ============================================================================

# ============================================================================
# ВКЛЮЧЕНИЕ ПРИВИЛЕГИЙ (SeBackupPrivilege / SeRestorePrivilege)
# ============================================================================

def _enable_privileges() -> bool:
    """
    Включает SeBackupPrivilege и SeRestorePrivilege для RegLoadKey.
    
    Это СТАНДАРТНЫЙ Windows API, антивирусы его НЕ триггерят.
    Без этих привилегий RegLoadKey (Amcache) НЕ РАБОТАЕТ даже от админа.
    
    Returns:
        bool: True если все привилегии включены успешно
    """
    try:
        advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        # Явные сигнатуры для x64
        kernel32.GetCurrentProcess.argtypes = []
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p

        advapi32.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
        advapi32.OpenProcessToken.restype = ctypes.c_bool

        advapi32.LookupPrivilegeValueW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p]
        advapi32.LookupPrivilegeValueW.restype = ctypes.c_bool

        advapi32.AdjustTokenPrivileges.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
        advapi32.AdjustTokenPrivileges.restype = ctypes.c_bool

        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_bool

        SE_PRIVILEGE_ENABLED = 0x00000002
        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", ctypes.c_uint32), ("HighPart", ctypes.c_int32)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", ctypes.c_uint32)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", ctypes.c_uint32), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        h_process = kernel32.GetCurrentProcess()
        token = ctypes.c_void_p()
        
        if not advapi32.OpenProcessToken(h_process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)):
            console.warn("Не удалось открыть токен процесса")
            return False

        enabled_count = 0
        for priv_name in ["SeBackupPrivilege", "SeRestorePrivilege"]:
            luid = LUID()
            if not advapi32.LookupPrivilegeValueW(None, priv_name, ctypes.byref(luid)):
                console.warn(f"LookupPrivilegeValue({priv_name}) failed")
                continue

            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

            if advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None):
                err = ctypes.get_last_error()
                if err == 0:
                    console.info(f"Привилегия {priv_name} включена")
                    enabled_count += 1
                else:
                    console.warn(f"{priv_name}: код ошибки {err}")

        kernel32.CloseHandle(token)
        return enabled_count == 2
    except Exception as e:
        console.warn(f"Ошибка включения привилегий: {e}")
        return False

def _get_save_path() -> Optional[str]:
    """
    Определяет путь ТОЛЬКО к папке Загрузки.
    БЕЗ FALLBACK. Если не удалось — возвращает None.
    
    Использует Windows Shell API (CSIDL_DOWNLOADS = 0x000D) — самый надёжный
    способ получить реальный путь к папке загрузок, учитывая OneDrive,
    локализацию и кастомные пути.
    
    Returns:
        Optional[str]: Путь к папке Загрузки или None, если не удалось определить
    """
    # === СПОСОБ 1: Windows Shell API (самый надёжный) ===
    try:
        CSIDL_DOWNLOADS = 0x000D
        MAX_PATH = 260
        buf = ctypes.create_unicode_buffer(MAX_PATH)
        result = ctypes.windll.shell32.SHGetFolderPathW(None, CSIDL_DOWNLOADS, None, 0, buf)
        if result == 0:
            path = buf.value
            if path and os.path.isdir(path):
                return path
    except Exception:
        pass
    
    # === СПОСОБ 2: Через реестр (альтернативный способ) ===
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        )
        # GUID папки Downloads
        downloads_path, _ = winreg.QueryValueEx(key, "{374DE290-123F-4565-9164-39C4925E467B}")
        winreg.CloseKey(key)
        downloads_path = os.path.expandvars(downloads_path)
        if downloads_path and os.path.isdir(downloads_path):
            return downloads_path
    except Exception:
        pass
    
    # БЕЗ FALLBACK — возвращаем None, если не нашли
    return None


def _parse_usn_time(raw: str) -> dt.datetime:
    """
    Парсит время из USN Journal в datetime.
    
    Поддерживает несколько форматов даты/времени, которые может
    возвращать fsutil в разных локалях Windows.
    
    Args:
        raw: Строка с временем в различных форматах
        
    Returns:
        dt.datetime: Распарсенное время или datetime.min при ошибке
    """
    raw = raw.strip()
    formats = [
        '%d.%m.%Y %H:%M:%S',
        '%Y-%m-%d %H:%M:%S',
        '%m/%d/%Y %H:%M:%S',
        '%d/%m/%Y %H:%M:%S',
    ]
    for fmt in formats:
        try:
            return dt.datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return dt.datetime.min


def _filetime_to_dt(ft: int) -> dt.datetime:
    """
    Конвертирует Windows FILETIME в datetime.
    
    FILETIME — это 100-наносекундные интервалы с 1 января 1601 года.
    
    Args:
        ft: FILETIME значение
        
    Returns:
        dt.datetime: Конвертированное время или datetime.min при ошибке
    """
    try:
        return dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=ft // 10)
    except Exception:
        return dt.datetime.min


def _chrome_ts_to_dt(ts_us: int) -> dt.datetime:
    """
    Конвертирует Chromium timestamp в datetime.
    
    Chromium timestamp — это микросекунды с 1 января 1601 года.
    
    Args:
        ts_us: Chromium timestamp в микросекундах
        
    Returns:
        dt.datetime: Конвертированное время или datetime.min при ошибке
    """
    CHROME_EPOCH_OFFSET = 11644473600  # Разница между 1601 и 1970 в секундах
    try:
        return dt.datetime.utcfromtimestamp(ts_us / 1_000_000 - CHROME_EPOCH_OFFSET)
    except (OSError, ValueError, OverflowError):
        return dt.datetime.min


def _firefox_ts_to_dt(pr_time: int) -> dt.datetime:
    """
    Конвертирует Firefox PRTime в datetime.
    
    PRTime — это микросекунды с 1 января 1970 года (Unix epoch).
    
    Args:
        pr_time: Firefox PRTime в микросекундах
        
    Returns:
        dt.datetime: Конвертированное время или datetime.min при ошибке
    """
    try:
        return dt.datetime.utcfromtimestamp(pr_time / 1_000_000)
    except (OSError, ValueError, OverflowError):
        return dt.datetime.min


def _copy_locked_file(src: str) -> Optional[str]:
    """
    Копирует заблокированный файл во временную директорию.
    
    Используется для чтения файлов, которые заблокированы другими процессами
    (например, базы данных браузеров).
    
    Args:
        src: Путь к исходному файлу
        
    Returns:
        Optional[str]: Путь к копии или None при ошибке
    """
    if not os.path.isfile(src):
        return None
    
    # Генерируем уникальное имя для временного файла
    timestamp = int(time.time() * 1000)
    pid = os.getpid()
    basename = os.path.basename(src)
    dst = os.path.join(tempfile.gettempdir(), f"copy_{pid}_{timestamp}_{basename}")
    
    try:
        shutil.copy2(src, dst)
        return dst
    except (PermissionError, OSError):
        return None


def _is_random_name(fname: str) -> bool:
    """
    Проверяет, является ли имя файла случайным.
    
    Случайные имена часто используются читами для сокрытия.
    
    Паттерны:
    - Только цифры + расширение (например, 837492.exe)
    - Длинная строка из букв и цифр + расширение (например, a1b2c3d4e5.dll)
    - UUID-подобное имя
    
    Args:
        fname: Имя файла
        
    Returns:
        bool: True если имя выглядит случайным
    """
    # Паттерн: только цифры + расширение
    if re.match(r'^\d{5,}\.(exe|sys|dll|bat|cmd|ps1|vbs)$', fname, re.IGNORECASE):
        return True
    
    # Паттерн: длинная строка из букв и цифр + расширение
    if re.match(r'^[a-z0-9]{10,}\.(exe|sys|dll|bat|cmd|ps1|vbs)$', fname, re.IGNORECASE):
        return True
    
    # Паттерн: UUID-подобное имя
    if re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\.(exe|dll)$', fname, re.IGNORECASE):
        return True
    
    return False


def _is_suspicious_path(path: str) -> bool:
    """
    Проверяет, находится ли файл в подозрительной директории.
    
    Подозрительные директории: Temp, AppData, Downloads, Public, ProgramData.
    
    Args:
        path: Путь к файлу
        
    Returns:
        bool: True если путь подозрительный
    """
    path_lower = path.lower().replace('/', '\\')
    return any(susp in path_lower for susp in SUSPICIOUS_PATHS)


def _check_stop_words(name: str) -> Optional[str]:
    """
    Проверяет наличие стоп-слов (читов/спуферов) в имени.
    
    Args:
        name: Имя файла или путь для проверки
        
    Returns:
        Optional[str]: Найденное стоп-слово или None
    """
    name_l = name.lower()
    all_words = RUST_CHEATS_BASE + HWID_SPOOFERS_BASE
    for word in all_words:
        if word in name_l:
            return word
    return None


def _reg_query(key, name: str) -> Optional[str]:
    """
    Безопасное чтение значения реестра.
    
    Args:
        key: Открытый ключ реестра
        name: Имя значения
        
    Returns:
        Optional[str]: Значение или None при ошибке
    """
    try:
        value, _ = winreg.QueryValueEx(key, name)
        return str(value) if value is not None else None
    except (FileNotFoundError, OSError):
        return None


def _calculate_file_hash(filepath: str, algorithm: str = 'sha256') -> Optional[str]:
    """
    Вычисляет хэш файла.
    
    Args:
        filepath: Путь к файлу
        algorithm: Алгоритм хэширования (md5, sha1, sha256)
        
    Returns:
        Optional[str]: Хэш в hex-формате или None при ошибке
    """
    try:
        hash_func = hashlib.new(algorithm)
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception:
        return None


# ============================================================================
# СЕКЦИЯ 14: МОДУЛЬ 1 — USN JOURNAL (ПОДОЗРИТЕЛЬНЫЕ ПРОГРАММЫ)
# ============================================================================

# Константы для парсинга USN Journal
COL_FILENAME = 1
COL_REASON = 3
COL_TIMESTAMP = 4
REASON_CREATE = 0x00000001
REASON_DELETE = 0x00000002
EXEC_RE = re.compile(r'\.(exe|sys|dll|bat|cmd|ps1|vbs)$', re.IGNORECASE)


def scan_usn_journal(report: ReportBuffer) -> list:
    """
    Анализирует USN Journal диска C: на наличие ПОДОЗРИТЕЛЬНЫХ программ.
    
    USN Journal (Update Sequence Number) — это журнал изменений файловой системы NTFS.
    Позволяет обнаружить создание/удаление файлов даже после их удаления.
    
    Фильтрует по:
    - Стоп-словам (читы, спуферы)
    - Случайным именам
    - Подозрительным путям (Temp, AppData, Downloads)
    - Whitelist (исключает системные файлы)
    
    Защита от зависаний:
    - Построчное чтение через Popen
    - Жесткий таймаут 60 секунд
    - Лимит 500,000 строк
    - Лимит 1000 находок
    
    Args:
        report: Буфер отчёта
        
    Returns:
        list: Список находок [(timestamp, kind, filename, flags), ...]
    """
    console.info("Анализ USN Journal диска C: ...")
    findings = []
    cutoff = time.time() - SEVEN_DAYS_SEC
    
    # 1. Быстрая проверка: включен ли вообще USN Journal
    try:
        check_proc = subprocess.run(
            ['fsutil', 'usn', 'queryjournal', 'c:'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=10
        )
        if check_proc.returncode != 0 or 'Usn Journal ID' not in check_proc.stdout:
            console.warn("USN Journal отключен или недоступен на диске C:")
            report.event("ПРОПУЩЕНО", "USN Journal не активен")
            return findings
    except Exception:
        pass

    # 2. Запуск чтения с защитой от зависаний
    try:
        # Используем Popen БЕЗ CREATE_NO_WINDOW — окно fsutil будет видно
        # Это безопаснее для антивирусов
        proc = subprocess.Popen(
            ['fsutil', 'usn', 'readjournal', 'c:', 'csv'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        
        start_time = time.time()
        lines_processed = 0
        MAX_LINES = 500000  # Лимит: не обрабатываем больше 500к строк
        MAX_TIME = 60       # Лимит: не работаем дольше 60 секунд
        
        # Читаем построчно, чтобы не ждать завершения всей команды
        for line in proc.stdout:
            # Проверка таймаута
            if time.time() - start_time > MAX_TIME:
                console.warn(f"USN Journal: превышен лимит времени ({MAX_TIME}с). Прерываем...")
                proc.kill()
                report.event("ТАЙМАУТ", f"USN Journal прерван по времени ({lines_processed} строк)")
                break
            
            # Проверка лимита строк
            lines_processed += 1
            if lines_processed > MAX_LINES:
                console.warn(f"USN Journal: превышен лимит строк ({MAX_LINES}). Прерываем...")
                proc.kill()
                report.event("ЛИМИТ", f"USN Journal прерван по лимиту строк")
                break
            
            # Парсинг CSV строки
            if not line.strip() or line.startswith('FileName'):
                continue
                
            parts = line.split(',')
            if len(parts) <= COL_TIMESTAMP:
                continue
                
            fname = parts[COL_FILENAME].strip().strip('"')
            reason_raw = parts[COL_REASON].strip()
            ts_raw = parts[COL_TIMESTAMP].strip()

            # Фильтр: только исполняемые файлы
            if not EXEC_RE.search(fname):
                continue

            try:
                reason = int(reason_raw, 0)
            except ValueError:
                continue

            if not (reason & (REASON_CREATE | REASON_DELETE)):
                continue

            ts = _parse_usn_time(ts_raw)
            if ts == dt.datetime.min or ts.timestamp() < cutoff:
                continue

            # === АНАЛИЗ ПОДОЗРИТЕЛЬНОСТИ ===
            
            # Whitelist: пропускаем системные файлы
            if is_name_whitelisted(fname):
                continue
            
            kind = "CREATE" if (reason & REASON_CREATE) else "DELETE"
            
            # Флаги подозрительности
            flags = []
            
            # 1. Проверка стоп-слов
            hit = _check_stop_words(fname)
            if hit:
                flags.append(f"STOPWORD:{hit}")
            
            # 2. Проверка случайного имени
            if _is_random_name(fname):
                flags.append("RANDOM-NAME")
            
            # 3. Проверка подозрительного пути (если есть в строке)
            if _is_suspicious_path(fname):
                flags.append("SUSPICIOUS-PATH")
            
            # Если нет флагов — это обычный системный файл, пропускаем
            if not flags:
                continue
            
            findings.append((ts, kind, fname, flags))
            report.event(f"USN-{kind}", f"{fname} | flags={','.join(flags)}", ts)
            
            # Ограничиваем количество находок
            if len(findings) >= 1000:
                console.warn("USN Journal: найдено более 1000 событий. Останавливаемся.")
                proc.kill()
                break

        proc.wait(timeout=5)
        console.ok(f"USN Journal: найдено {len(findings)} подозрительных событий (обработано {lines_processed} строк)")
        
    except subprocess.TimeoutExpired:
        proc.kill()
        console.warn("USN Journal: таймаут")
        report.event("ТАЙМАУТ", "fsutil usn readjournal")
    except PermissionError:
        console.fail("USN Journal: нет прав")
        report.event("ЗАБЛОКИРОВАНО", "PermissionError")
    except Exception as e:
        console.fail(f"USN Journal: ошибка {e}")
        report.event("ОШИБКА", str(e))

    return findings


# ============================================================================
# СЕКЦИЯ 15: МОДУЛЬ 2 — PREFETCH
# ============================================================================

def scan_prefetch(report: ReportBuffer) -> list:
    """
    Сканирует папку Prefetch на наличие подозрительных файлов.
    
    Prefetch — это механизм Windows для ускорения запуска приложений.
    Создаёт .pf файлы для каждого запущенного exe, содержит информацию
    о времени запуска и количестве запусков.
    
    Args:
        report: Буфер отчёта
        
    Returns:
        list: Список находок [(timestamp, filename, match), ...]
    """
    console.info("Сканирование Prefetch ...")
    findings = []
    cutoff = time.time() - SEVEN_DAYS_SEC

    if not os.path.isdir(PREFETCH_DIR):
        console.warn("Папка Prefetch отсутствует")
        report.event("ПРОПУЩЕНО", "Prefetch dir not found")
        return findings

    try:
        for fname in os.listdir(PREFETCH_DIR):
            if not fname.lower().endswith('.pf'):
                continue
            
            # Whitelist: пропускаем системные файлы
            if is_name_whitelisted(fname):
                continue

            full = os.path.join(PREFETCH_DIR, fname)
            try:
                stat = os.stat(full)
            except (PermissionError, FileNotFoundError):
                report.event("ЗАБЛОКИРОВАНО", f"Prefetch: {fname}")
                continue

            if stat.st_mtime < cutoff:
                continue

            hit = _check_stop_words(fname)
            if hit:
                findings.append((dt.datetime.fromtimestamp(stat.st_mtime), fname, hit))
                report.event("PREFETCH-TRIGGER", f"{fname} | match='{hit}'")
    except PermissionError:
        console.fail("Prefetch: нет доступа")
        report.event("ЗАБЛОКИРОВАНО", "Prefetch PermissionError")
    except Exception as e:
        console.fail(f"Prefetch: ошибка {e}")

    console.ok(f"Prefetch: {len(findings)} совпадений")
    return findings


# ============================================================================
# СЕКЦИЯ 16: МОДУЛЬ 3 — BAM (Background Activity Moderator)
# ============================================================================

def scan_bam(report: ReportBuffer) -> list:
    """
    Читает BAM (Background Activity Moderator) из реестра.
    
    BAM отслеживает запуск приложений в фоновом режиме.
    Хранит данные в ветке реестра HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings\\{SID}
    
    Args:
        report: Буфер отчёта
        
    Returns:
        list: Список находок [(timestamp, path, match), ...]
    """
    console.info("Чтение BAM (UserSettings) ...")
    findings = []
    
    try:
        base_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, BAM_PATH)
        i = 0
        while True:
            try:
                sid = winreg.EnumKey(base_key, i)
                i += 1
            except OSError:
                break
            try:
                sid_key = winreg.OpenKey(base_key, sid)
                j = 0
                while True:
                    try:
                        name, data, vtype = winreg.EnumValue(sid_key, j)
                        j += 1
                    except OSError:
                        break
                    
                    # Whitelist: пропускаем системные файлы
                    basename = os.path.basename(name)
                    if is_name_whitelisted(basename) or is_path_whitelisted(name):
                        continue

                    hit = _check_stop_words(name)
                    if hit:
                        ts = _filetime_to_dt(data) if isinstance(data, int) else None
                        findings.append((ts, name, hit))
                        report.event("BAM-TRIGGER", f"{name} | match='{hit}'")
            except PermissionError:
                report.event("ЗАБЛОКИРОВАНО", f"BAM SID {sid}")
    except (FileNotFoundError, PermissionError) as e:
        console.warn(f"BAM недоступен: {e}")
        report.event("ЗАБЛОКИРОВАНО", f"BAM: {e}")
    except Exception as e:
        console.fail(f"BAM: ошибка {e}")

    console.ok(f"BAM: {len(findings)} совпадений")
    return findings


# ============================================================================
# СЕКЦИЯ 17: МОДУЛЬ 4 — AMCACHE (через безопасную обёртку winreg)
# ============================================================================

def scan_amcache(report: ReportBuffer) -> list:
    """
    Читает Amcache.hve через временную загрузку куста реестра.
    
    Безопасный подход:
    1. Пробуем загрузить оригинал
    2. Если файл занят — копируем во временную папку и загружаем копию
    3. Если не получилось — ищем процесс и пытаемся безопасно завершить
    4. Если ничего не помогло — пропускаем модуль
    """
    console.info("Чтение Amcache (альтернатива BAM) ...")
    findings = []

    if not os.path.isfile(AMCACHE_PATH):
        console.warn("Amcache.hve не найден")
        report.event("ПРОПУЩЕНО", "Amcache.hve отсутствует")
        return findings

    # === ШАГ 1: Проверяем, не загружен ли куст уже под нашим именем ===
    hive_already_loaded = False
    try:
        test_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, AMCACHE_TEMP_HIVE)
        winreg.CloseKey(test_key)
        hive_already_loaded = True
        console.info(f"Куст {AMCACHE_TEMP_HIVE} уже загружен — используем его")
    except (FileNotFoundError, OSError):
        pass

    # === ШАГ 2: Пытаемся загрузить ОРИГИНАЛ ===
    load_success = False
    amcache_file_to_load = AMCACHE_PATH  # По умолчанию загружаем оригинал
    
    if not hive_already_loaded:
        try:
            winreg.LoadKey(winreg.HKEY_LOCAL_MACHINE, AMCACHE_TEMP_HIVE, AMCACHE_PATH)
            console.info("Куст Amcache успешно загружен (оригинал)")
            load_success = True
        except OSError as e:
            error_code = e.winerror if hasattr(e, 'winerror') else 0
            
            # === Ошибка 32: Файл занят другим процессом ===
            if error_code == 32:
                console.warn("Amcache.hve занят другим процессом. Пробуем скопировать файл...")
                
                # === ШАГ 3: Пытаемся СКОПИРОВАТЬ файл во временную папку ===
                temp_amcache = os.path.join(tempfile.gettempdir(), f"amcache_copy_{os.getpid()}.hve")
                try:
                    shutil.copy2(AMCACHE_PATH, temp_amcache)
                    console.info(f"Файл скопирован: {temp_amcache}")
                    
                    # Пробуем загрузить КОПИЮ
                    try:
                        winreg.LoadKey(winreg.HKEY_LOCAL_MACHINE, AMCACHE_TEMP_HIVE, temp_amcache)
                        console.info("Куст Amcache успешно загружен (копия)")
                        load_success = True
                        amcache_file_to_load = temp_amcache
                    except OSError as e2:
                        console.warn(f"Не удалось загрузить копию: {e2}")
                        # Удаляем временный файл
                        try:
                            os.remove(temp_amcache)
                        except:
                            pass
                except (PermissionError, OSError) as e2:
                    console.warn(f"Не удалось скопировать файл: {e2}")
                
                # === ШАГ 4: Если копирование не помогло — ищем процесс ===
                if not load_success:
                    console.warn("Пробуем найти процесс, блокирующий файл...")
                    blocking_process = _find_blocking_process(AMCACHE_PATH)
                    
                    if blocking_process:
                        console.info(f"Найден блокирующий процесс: {blocking_process['name']} (PID: {blocking_process['pid']})")
                        
                        # Проверяем, не системный ли процесс
                        if blocking_process['name'].lower() in ['svchost.exe', 'system', 'csrss.exe', 'wininit.exe']:
                            console.warn(f"Процесс {blocking_process['name']} — системный. Не завершаем.")
                            report.event("ЗАБЛОКИРОВАНО", f"Amcache: файл занят системным процессом {blocking_process['name']}")
                        else:
                            # Пытаемся безопасно завершить процесс
                            console.warn(f"Пытаемся завершить процесс {blocking_process['name']}...")
                            if _kill_process_safely(blocking_process['pid']):
                                console.info("Процесс завершён. Повторная попытка загрузки...")
                                time.sleep(2)  # Ждём освобождения файла
                                
                                # Повторная попытка
                                try:
                                    winreg.LoadKey(winreg.HKEY_LOCAL_MACHINE, AMCACHE_TEMP_HIVE, AMCACHE_PATH)
                                    console.info("Куст Amcache успешно загружен (после завершения процесса)")
                                    load_success = True
                                except Exception as e3:
                                    console.fail(f"Повторная загрузка не удалась: {e3}")
                                    report.event("ЗАБЛОКИРОВАНО", f"Amcache: повторная загрузка не удалась")
                            else:
                                console.warn("Не удалось завершить процесс")
                                report.event("ЗАБЛОКИРОВАНО", "Amcache: не удалось завершить блокирующий процесс")
                    else:
                        console.warn("Не удалось найти блокирующий процесс")
                        report.event("ЗАБЛОКИРОВАНО", "Amcache: файл занят, процесс не найден")
            
            # === Ошибка 5: Отказано в доступе ===
            elif error_code == 5:
                console.fail("Amcache: отказано в доступе. Нужны привилегии SeBackupPrivilege/SeRestorePrivilege")
                report.event("ЗАБЛОКИРОВАНО", "Amcache: нужны привилегии")
                return findings
            
            # === Другие ошибки ===
            else:
                console.fail(f"Amcache: не удалось загрузить куст — {e} (код {error_code})")
                report.event("ЗАБЛОКИРОВАНО", f"Amcache LoadKey: {e}")
                return findings
        
        except Exception as e:
            console.fail(f"Amcache: непредвиденная ошибка — {e}")
            report.event("ЗАБЛОКИРОВАНО", f"Amcache: {e}")
            return findings

    # Если не удалось загрузить — пропускаем модуль
    if not load_success and not hive_already_loaded:
        console.warn("Amcache: модуль пропущен")
        return findings

    # === ШАГ 5: Чтение данных из куста ===
    try:
        base = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, AMCACHE_TEMP_HIVE)

        for subpath in (r'Root\File', r'Root\InventoryApplicationFile'):
            try:
                file_key = winreg.OpenKey(base, subpath)
            except (FileNotFoundError, OSError):
                continue

            i = 0
            while True:
                try:
                    entry_name = winreg.EnumKey(file_key, i)
                    i += 1
                except OSError:
                    break

                try:
                    entry_key = winreg.OpenKey(file_key, entry_name)
                    
                    path = _reg_query(entry_key, 'FilePath') or _reg_query(entry_key, 'LowerCaseLongPath') or ''
                    name = _reg_query(entry_key, 'Name') or ''
                    sha1 = _reg_query(entry_key, 'Sha1Hash') or _reg_query(entry_key, 'FileId') or entry_name
                    size_raw = _reg_query(entry_key, 'Size') or _reg_query(entry_key, 'FileSize')
                    size = int(size_raw) if size_raw else 0

                    exec_ts_raw = _reg_query(entry_key, 'LastModified') or _reg_query(entry_key, 'LastRunTime') or _reg_query(entry_key, 'os')
                    ts = None
                    if exec_ts_raw:
                        try:
                            ts = dt.datetime.fromtimestamp(int(exec_ts_raw))
                        except (ValueError, OSError, OverflowError):
                            ts = None

                    full_check = f"{path}\\{name}" if path and name else path or name

                    hit = _check_stop_words(full_check) or _check_stop_words(sha1)

                    flags = []
                    if hit:
                        flags.append(f"STOPWORD:{hit}")
                    if name and _is_random_name(name):
                        flags.append("RANDOM-NAME")
                    if 0 < size < 10 * 1024:
                        flags.append(f"SUSPECT-SIZE({size}B)")

                    if flags:
                        if is_path_whitelisted(full_check) or is_name_whitelisted(name):
                            winreg.CloseKey(entry_key)
                            continue
                        findings.append((ts, full_check, sha1, flags))
                        report.event("AMCACHE-TRIGGER", f"{full_check} | sha1={sha1[:16]}... | flags={','.join(flags)} | time={ts}")

                    winreg.CloseKey(entry_key)
                except Exception:
                    continue

            winreg.CloseKey(file_key)
        winreg.CloseKey(base)
    
    except Exception as e:
        console.warn(f"Amcache: ошибка чтения — {e}")
    
    finally:
        # === ШАГ 6: Выгружаем куст и удаляем временный файл ===
        if not hive_already_loaded:
            try:
                advapi32_unload = ctypes.WinDLL('advapi32', use_last_error=True)
                advapi32_unload.RegUnLoadKeyW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
                advapi32_unload.RegUnLoadKeyW.restype = ctypes.c_long

                ret = advapi32_unload.RegUnLoadKeyW(
                    ctypes.c_void_p(int(winreg.HKEY_LOCAL_MACHINE)),
                    AMCACHE_TEMP_HIVE
                )
                if ret == 0:
                    console.info("Куст Amcache успешно выгружен")
                else:
                    console.warn(f"RegUnLoadKeyW вернул код {ret}")
            except Exception as e:
                console.warn(f"Не удалось выгрузить куст Amcache: {e}")
            
            # Удаляем временный файл, если использовали копию
            if amcache_file_to_load != AMCACHE_PATH:
                try:
                    os.remove(amcache_file_to_load)
                    console.info("Временный файл удалён")
                except:
                    pass
        else:
            console.info("Куст не выгружаем (был загружен до нас)")

    console.ok(f"Amcache: {len(findings)} совпадений")
    return findings


def _find_blocking_process(filepath: str) -> Optional[Dict[str, Any]]:
    """
    Ищет процесс, который блокирует файл.
    
    Использует PowerShell для поиска процессов, которые держат файл открытым.
    
    Args:
        filepath: Путь к файлу
        
    Returns:
        Optional[Dict]: Информация о процессе {'name': str, 'pid': int} или None
    """
    try:
        # Используем PowerShell для поиска процесса
        # Get-Process | Where-Object {$_.Modules.FileName -like '*Amcache*'}
        ps_script = f"""
        Get-Process | ForEach-Object {{
            try {{
                $_.Modules | Where-Object {{ $_.FileName -like '*{os.path.basename(filepath)}*' }} | ForEach-Object {{
                    [PSCustomObject]@{{
                        Name = $_.ProcessName
                        PID = $_.Id
                    }}
                }}
            }} catch {{}}
        }}
        """
        
        proc = subprocess.run(
            ['powershell', '-Command', ps_script],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=10
        )
        
        if proc.returncode == 0 and proc.stdout.strip():
            # Парсим вывод
            lines = proc.stdout.strip().split('\n')
            for line in lines:
                if '@{' in line:
                    # Формат: @{Name=svchost; PID=1234}
                    match = re.search(r'Name=([^;]+);\s*PID=(\d+)', line)
                    if match:
                        return {
                            'name': match.group(1).strip(),
                            'pid': int(match.group(2).strip())
                        }
    except Exception as e:
        console.warn(f"Ошибка поиска блокирующего процесса: {e}")
    
    return None


def _kill_process_safely(pid: int) -> bool:
    """
    Безопасно завершает процесс по PID.
    
    Использует taskkill с флагом /F (force).
    
    Args:
        pid: PID процесса
        
    Returns:
        bool: True если процесс успешно завершён
    """
    try:
        proc = subprocess.run(
            ['taskkill', '/F', '/PID', str(pid)],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=10
        )
        return proc.returncode == 0
    except Exception as e:
        console.warn(f"Ошибка завершения процесса {pid}: {e}")
        return False


# ============================================================================
# СЕКЦИЯ 18: МОДУЛЬ 5 — БРАУЗЕРЫ (Chromium + Firefox)
# ============================================================================

def _query_chromium_history(db_path: str, cutoff_ts: int) -> list:
    """
    Запрашивает историю из Chromium-браузера.
    
    Args:
        db_path: Путь к базе данных History
        cutoff_ts: Порог времени (Chromium timestamp)
        
    Returns:
        list: Список записей [(url, title, timestamp, is_download, search_query), ...]
    """
    results = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cur = conn.cursor()

        # История URL + поисковые запросы
        try:
            cur.execute("""
                SELECT u.url, u.title, u.last_visit_time, k.term
                FROM urls u
                LEFT JOIN keyword_search_terms k ON u.id = k.url_id
                WHERE u.last_visit_time >= ?
                LIMIT 50000
            """, (cutoff_ts,))
            for url, title, ts, search_term in cur.fetchall():
                results.append((url, title or '', _chrome_ts_to_dt(ts), False, search_term or ''))
        except sqlite3.OperationalError:
            pass

        # Скачивания
        try:
            cur.execute("""
                SELECT tab_url, target_path, start_time
                FROM downloads
                WHERE start_time >= ?
                LIMIT 10000
            """, (cutoff_ts,))
            for url, path, ts in cur.fetchall():
                results.append((url, path or '', _chrome_ts_to_dt(ts), True, ''))
        except sqlite3.OperationalError:
            pass

        conn.close()
    except sqlite3.DatabaseError:
        pass
    return results


def _find_firefox_profiles() -> list:
    """
    Ищет все профили Firefox.
    
    Returns:
        list: Список путей к places.sqlite
    """
    profiles = []
    ff_dir = os.path.join(os.environ.get('APPDATA', ''), 'Mozilla', 'Firefox', 'Profiles')
    if not os.path.isdir(ff_dir):
        return profiles
    try:
        for entry in os.listdir(ff_dir):
            places = os.path.join(ff_dir, entry, 'places.sqlite')
            if os.path.isfile(places):
                profiles.append(places)
    except PermissionError:
        pass
    return profiles


def _query_firefox_history(db_path: str, cutoff_pr: int) -> list:
    """
    Запрашивает историю из Firefox.
    
    Args:
        db_path: Путь к базе данных places.sqlite
        cutoff_pr: Порог времени (Firefox PRTime)
        
    Returns:
        list: Список записей [(url, title, timestamp, is_download, search_query), ...]
    """
    results = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT p.url, p.title, p.last_visit_date,
                       (SELECT GROUP_CONCAT(ih.input, ' | ')
                        FROM moz_inputhistory ih
                        WHERE ih.place_id = p.id) AS searches
                FROM moz_places p
                WHERE p.last_visit_date >= ? AND p.url IS NOT NULL
                LIMIT 50000
            """, (cutoff_pr,))
            for url, title, pr_ts, searches in cur.fetchall():
                try:
                    ts = dt.datetime.utcfromtimestamp(pr_ts / 1_000_000)
                except:
                    ts = dt.datetime.min
                results.append((url, title or '', ts, False, searches or ''))
        except sqlite3.OperationalError:
            pass
        conn.close()
    except sqlite3.DatabaseError:
        pass
    return results


def scan_browsers(report: ReportBuffer) -> dict:
    """
    Сканирует историю всех браузеров.
    
    Поддерживает: Chrome, Edge, Yandex, Opera, Brave, Vivaldi, Firefox.
    Фильтрует домены через whitelist.
    
    Args:
        report: Буфер отчёта
        
    Returns:
        dict: {browser_name: [(url, title, timestamp, is_download, search), ...]}
    """
    console.info("Анализ истории браузеров ...")
    now = time.time()
    cutoff_chromium = int((now - SEVEN_DAYS_SEC + 11644473600) * 1_000_000)
    cutoff_firefox = int((now - SEVEN_DAYS_SEC) * 1_000_000)

    localappdata = os.environ.get('LOCALAPPDATA', '')
    appdata = os.environ.get('APPDATA', '')

    all_history = {}
    stats = {'total': 0, 'filtered': 0, 'searches': 0, 'downloads': 0}

    # Сканируем Chromium-браузеры
    for browser, path_parts in BROWSERS_CHROMIUM.items():
        for base in (localappdata, appdata):
            if not base:
                continue
            hist_path = os.path.join(base, *path_parts, 'Default', 'History')
            if not os.path.isfile(hist_path):
                ud = os.path.join(base, *path_parts)
                if not os.path.isdir(ud):
                    continue
                for profile in os.listdir(ud):
                    candidate = os.path.join(ud, profile, 'History')
                    if os.path.isfile(candidate):
                        hist_path = candidate
                        break
                else:
                    continue

            tmp = _copy_locked_file(hist_path)
            if not tmp:
                report.event("ЗАБЛОКИРОВАНО", f"{browser}: History locked")
                continue

            try:
                rows = _query_chromium_history(tmp, cutoff_chromium)
                browser_records = []
                for url, title, ts, is_dl, search in rows:
                    stats['total'] += 1
                    if is_domain_whitelisted(url):
                        stats['filtered'] += 1
                        continue
                    if is_dl:
                        stats['downloads'] += 1
                    if search:
                        stats['searches'] += 1
                    browser_records.append((url, title, ts, is_dl, search))
                if browser_records:
                    all_history.setdefault(browser, []).extend(browser_records)
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass

    # Сканируем Firefox
    for places_path in _find_firefox_profiles():
        tmp = _copy_locked_file(places_path)
        if not tmp:
            continue
        try:
            rows = _query_firefox_history(tmp, cutoff_firefox)
            browser_records = []
            for url, title, ts, is_dl, search in rows:
                stats['total'] += 1
                if is_domain_whitelisted(url):
                    stats['filtered'] += 1
                    continue
                if is_dl:
                    stats['downloads'] += 1
                if search:
                    stats['searches'] += 1
                browser_records.append((url, title, ts, is_dl, search))
            if browser_records:
                all_history.setdefault('Firefox', []).extend(browser_records)
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass

    report.info(f"Browsers: всего={stats['total']}, отфильтровано={stats['filtered']}, поисков={stats['searches']}, скачиваний={stats['downloads']}")
    console.ok(f"Браузеры: {stats['total'] - stats['filtered']} записей (отфильтровано {stats['filtered']})")
    return all_history


# ============================================================================
# СЕКЦИЯ 19: МОДУЛЬ 6 — FUNPAY ФИЛЬТР
# ============================================================================

OFFER_RE = re.compile(FUNPAY_OFFER_MASK, re.IGNORECASE)
CATEGORY_RE = re.compile('|'.join(re.escape(c) for c in FUNPAY_RUST_CATEGORIES), re.IGNORECASE)
CHEAT_RE = re.compile(r'\b(' + '|'.join(re.escape(w) for w in
                      ['чит', 'софт', 'макрос', 'cheat', 'hack', 'soft', 'macro', 'dlc']) + r')\b', re.IGNORECASE)


def analyze_funpay(browser_history: dict, report: ReportBuffer) -> list:
    """
    Анализирует историю браузеров на наличие посещений Funpay и других площадок.
    
    Args:
        browser_history: История браузеров
        report: Буфер отчёта
        
    Returns:
        list: Список триггеров [(type, browser, url, title, timestamp), ...]
    """
    console.info("Фильтр Funpay / цифровые площадки ...")
    findings = []

    for browser, rows in browser_history.items():
        for record in rows:
            url = record[0]
            title = record[1] if len(record) > 1 else ''
            ts = record[2] if len(record) > 2 else None
            url_l = url.lower()
            title_l = title.lower()

            # Прямые страницы предложений
            if OFFER_RE.search(url):
                cheat_match = CHEAT_RE.search(title)
                if cheat_match:
                    findings.append(('FUNPAY-OFFER-CHEAT', browser, url, title, ts))
                    report.event("FUNPAY-TRIGGER", f"[{browser}] {url} | title='{title}' | keyword='{cheat_match.group(0)}'")

            # Заходы в категории Rust
            if CATEGORY_RE.search(url):
                findings.append(('FUNPAY-CATEGORY', browser, url, title, ts))
                report.event("FUNPAY-CATEGORY", f"[{browser}] {url} | title='{title}'")

            # DLC-маркер
            if any(kw in title_l for kw in DLC_KEYWORDS):
                if 'funpay' in url_l or 'lzt' in url_l or 'plati' in url_l:
                    findings.append(('DLC-ALERT', browser, url, title, ts))
                    report.event("DLC-TRIGGER", f"[{browser}] {url} | title='{title}'")

    console.ok(f"Funpay-фильтр: {len(findings)} триггеров")
    return findings


# ============================================================================
# СЕКЦИЯ 20: МОДУЛЬ 7 — EVENT LOGS
# ============================================================================

TARGET_EVENTS = {
    7045: "NEW_SERVICE",
    4697: "NEW_SERVICE_ALT",
    1102: "LOG_CLEARED",
    1000: "APP_CRASH",
    1001: "APP_CRASH_BUGCHECK",
}

LOG_NAMES = ['System', 'Security', 'Application']


def _query_log(log_name: str, since_iso: str) -> list:
    """
    Запрашивает события из журнала Windows.
    
    БЕЗ CREATE_NO_WINDOW — окно wevtutil будет видно, это безопаснее.
    
    Args:
        log_name: Имя журнала (System, Security, Application)
        since_iso: ISO-формат времени начала
        
    Returns:
        list: Список событий [(event_id, timestamp, data), ...]
    """
    query = (f"*[System[(EventID=7045 or EventID=4697 or EventID=1102 "
             f"or EventID=1000 or EventID=1001) "
             f"and TimeCreated[@SystemTime>='{since_iso}']]]")
    cmd = ['wevtutil', 'qe', log_name, f'/q:{query}', '/f:xml', '/c:500']
    try:
        # БЕЗ CREATE_NO_WINDOW — безопаснее для антивирусов
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        try:
            stdout, stderr = proc.communicate(timeout=30)
            if proc.returncode == 0:
                return _parse_xml_events(stdout)
        except subprocess.TimeoutExpired:
            proc.kill()
            console.warn(f"Event Log '{log_name}': таймаут (30с)")
    except Exception:
        pass
    return []


def _parse_xml_events(xml_blob: str) -> list:
    """
    Парсит XML-события из wevtutil.
    
    Args:
        xml_blob: XML-строка с событиями
        
    Returns:
        list: Список событий [(event_id, timestamp, data), ...]
    """
    events = []
    for chunk in xml_blob.split('<Event '):
        if not chunk.strip():
            continue
        try:
            root = ET.fromstring('<Event ' + chunk)
        except ET.ParseError:
            continue

        ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
        sys_el = root.find(f'{ns}System')
        if sys_el is None:
            continue

        eid_el = sys_el.find(f'{ns}EventID')
        if eid_el is None or eid_el.text is None:
            continue
        try:
            eid = int(eid_el.text)
        except ValueError:
            continue
        if eid not in TARGET_EVENTS:
            continue

        tc = sys_el.find(f'{ns}TimeCreated')
        ts_str = tc.get('SystemTime', '') if tc is not None else ''
        try:
            ts = dt.datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        except ValueError:
            ts = dt.datetime.min

        data_parts = []
        data_el = root.find(f'{ns}EventData')
        if data_el is not None:
            for d in data_el.findall(f'{ns}Data'):
                if d.text:
                    data_parts.append(d.text.strip())

        events.append((eid, ts, ' | '.join(data_parts)))
    return events


def scan_event_logs(report: ReportBuffer) -> list:
    """
    Сканирует журналы Windows на наличие целевых событий.
    
    Args:
        report: Буфер отчёта
        
    Returns:
        list: Список событий [(event_id, label, timestamp, data), ...]
    """
    console.info("Анализ журналов Windows (Event Viewer) ...")
    # Используем современный способ получения UTC времени
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=SEVEN_DAYS_SEC)).isoformat()
    all_events = []

    for log in LOG_NAMES:
        for eid, ts, data in _query_log(log, since):
            label = TARGET_EVENTS[eid]
            all_events.append((eid, label, ts, data))
            report.event(label, f"EventID={eid} src={log} | {data}")

    console.ok(f"Event Logs: {len(all_events)} целевых событий")
    return all_events


# ============================================================================
# СЕКЦИЯ 21: МОДУЛЬ 8 — DEEP SCAN
# ============================================================================

def scan_deep(report: ReportBuffer) -> list:
    """
    Глубокое сканирование каталогов на наличие подозрительных файлов.
    
    Сканирует TEMP, APPDATA, LOCALAPPDATA, System32\\drivers на наличие:
    - Файлов со стоп-словами в имени
    - Файлов со случайными именами
    - Файлов подозрительно малого размера
    - Нулевых файлов
    
    Args:
        report: Буфер отчёта
        
    Returns:
        list: Список находок [(path, mtime, size, flags), ...]
    """
    console.info("Глубокое сканирование каталогов (72h) ...")
    cutoff = time.time() - THREE_DAYS_SEC
    findings = []
    stop_all = [w.lower() for w in RUST_CHEATS_BASE + HWID_SPOOFERS_BASE]
    
    # Папки, которые точно не нужно сканировать (ускоряет работу в разы)
    SKIP_DIRS = {
        'node_modules', 'python', 'windowsapps', 'microsoft edge',
        'cache', 'venv', '.git', '__pycache__', 'site-packages'
    }

    for root_dir in TARGET_DIRS:
        if not root_dir or not os.path.isdir(root_dir):
            continue
        try:
            # followlinks=False предотвращает бесконечные циклы из-за ярлыков Windows
            for dirpath, dirnames, filenames in os.walk(root_dir, followlinks=False):
                # Исключаем тяжелые и безопасные папки из обхода
                dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
                
                for fname in filenames:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in EXECUTABLE_EXTS:
                        continue
                    
                    full = os.path.join(dirpath, fname)
                    if is_path_whitelisted(full):
                        continue

                    try:
                        st = os.stat(full)
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
                    if st.st_mtime < cutoff and st.st_ctime < cutoff:
                        continue

                    flags = []
                    fname_l = fname.lower()
                    if any(sw in fname_l for sw in stop_all):
                        flags.append('STOPWORD')
                    if _is_random_name(fname):
                        flags.append('RANDOM-NAME')
                    if 0 < st.st_size < 10 * 1024:
                        flags.append(f'SUSPECT-SIZE({st.st_size}B)')
                    if st.st_size == 0:
                        flags.append('ZERO-BYTE')

                    if flags:
                        findings.append((full, st.st_mtime, st.st_size, flags))
                        report.event("DEEP-SCAN", f"{full} | flags={','.join(flags)}")
        except PermissionError:
            report.event("ЗАБЛОКИРОВАНО", f"Deep scan: {root_dir}")
        except Exception as e:
            console.warn(f"Deep scan {root_dir}: {e}")

    console.ok(f"Deep scan: {len(findings)} подозрительных файлов")
    return findings


# ============================================================================
# СЕКЦИЯ 22: МОДУЛЬ 9 — STEAM
# ============================================================================

def _find_vdf(name: str) -> Optional[str]:
    """
    Ищет VDF-файл в стандартных путях Steam.
    
    Args:
        name: Имя файла (например, 'loginusers.vdf')
        
    Returns:
        Optional[str]: Путь к файлу или None
    """
    for base in STEAM_PATHS:
        p = os.path.join(base, name)
        if os.path.isfile(p):
            return p
    return None


def _parse_vdf_simple(text: str) -> dict:
    """
    Простой парсер VDF (Valve Data Format).
    
    Args:
        text: Содержимое VDF-файла
        
    Returns:
        dict: Распарсенная структура
    """
    stack = [{}]
    tokens = re.findall(r'"([^"]*)"|(\{|\})', text)
    key_pending = None
    for quoted, brace in tokens:
        if brace == '{':
            new = {}
            if key_pending is not None:
                stack[-1][key_pending] = new
                key_pending = None
            stack.append(new)
        elif brace == '}':
            if len(stack) > 1:
                stack.pop()
        elif quoted:
            if key_pending is None:
                key_pending = quoted
            else:
                stack[-1][key_pending] = quoted
                key_pending = None
    return stack[0]


def scan_steam(report: ReportBuffer) -> dict:
    """
    Анализирует Steam на наличие аккаунтов и .maFile.
    
    Args:
        report: Буфер отчёта
        
    Returns:
        dict: {'accounts': [...], 'mafiles': [...]}
    """
    console.info("Анализ Steam ...")
    result = {'accounts': [], 'mafiles': []}

    # Ищем loginusers.vdf
    vdf_path = _find_vdf('loginusers.vdf')
    if vdf_path:
        try:
            with open(vdf_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = _parse_vdf_simple(f.read())
            users = data.get('users', {})
            for steam_id, info in users.items():
                if not isinstance(info, dict):
                    continue
                result['accounts'].append({
                    'steamid64': steam_id,
                    'personaname': info.get('Personaname', ''),
                    'last_login': info.get('LastLoginTime', '0'),
                })
            result['accounts'].sort(key=lambda a: int(a['last_login'] or 0), reverse=True)
            for acc in result['accounts']:
                report.event("STEAM-ACCOUNT", f"SteamID64={acc['steamid64']} | name='{acc['personaname']}'")
        except Exception as e:
            report.event("ОШИБКА", f"loginusers.vdf: {e}")
    else:
        report.event("ПРОПУЩЕНО", "loginusers.vdf не найден")

    # Ищем .maFile ТОЛЬКО в папках config (не во всем профиле!)
    mafile_search_paths = [
        os.path.join(os.environ.get('APPDATA', ''), 'Steam', 'config'),
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Steam', 'config'),
        r'C:\Program Files (x86)\Steam\config',
        r'C:\Program Files\Steam\config',
    ]
    
    for base in mafile_search_paths:
        if not base or not os.path.isdir(base):
            continue
        try:
            for fn in os.listdir(base):
                if fn.lower().endswith('.mafile'):
                    full = os.path.join(base, fn)
                    result['mafiles'].append(full)
                    report.event("MAFILE-DETECT", full)
        except PermissionError:
            pass
        except Exception:
            pass

    console.ok(f"Steam: {len(result['accounts'])} аккаунтов, {len(result['mafiles'])} .maFile")
    return result


# ============================================================================
# СЕКЦИЯ 23: МОДУЛЬ 10 — ПРОЦЕССЫ
# ============================================================================

def scan_processes(report: ReportBuffer) -> list:
    """
    Сканирует запущенные процессы на наличие подозрительных.
    
    Использует WMIC БЕЗ CREATE_NO_WINDOW для получения списка процессов.
    
    Args:
        report: Буфер отчёта
        
    Returns:
        list: Список подозрительных процессов [(name, path, pid, match), ...]
    """
    console.info("Анализ запущенных процессов ...")
    findings = []
    
    try:
        # БЕЗ CREATE_NO_WINDOW — окно wmic будет видно, это безопаснее
        proc = subprocess.run(
            ['wmic', 'process', 'get', 'Name,ExecutablePath,ProcessId', '/format:csv'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=30
        )
        
        if proc.returncode != 0:
            console.warn("WMIC вернул ошибку")
            return findings
        
        reader = csv.reader(io.StringIO(proc.stdout))
        next(reader, None)  # Пропускаем заголовок
        
        for row in reader:
            if len(row) < 4:
                continue
            
            # Формат CSV: Node,ExecutablePath,Name,ProcessId
            try:
                exec_path = row[1].strip()
                name = row[2].strip()
                pid = row[3].strip()
            except IndexError:
                continue
            
            if not name:
                continue
            
            # Whitelist: пропускаем системные процессы
            if is_name_whitelisted(name):
                continue
            
            # Проверка стоп-слов
            hit = _check_stop_words(name) or _check_stop_words(exec_path)
            if hit:
                findings.append((name, exec_path, pid, hit))
                report.event("PROCESS-TRIGGER", f"PID={pid} | {name} | path='{exec_path}' | match='{hit}'")
            
            # Проверка подозрительного пути
            if exec_path and _is_suspicious_path(exec_path) and _is_random_name(name):
                findings.append((name, exec_path, pid, "SUSPICIOUS"))
                report.event("PROCESS-SUSPICIOUS", f"PID={pid} | {name} | path='{exec_path}'")
        
        console.ok(f"Процессы: {len(findings)} подозрительных")
        
    except subprocess.TimeoutExpired:
        console.warn("Процессы: таймаут")
    except Exception as e:
        console.fail(f"Процессы: ошибка {e}")
    
    return findings


# ============================================================================
# СЕКЦИЯ 24: МОДУЛЬ 11 — АВТОЗАГРУЗКА
# ============================================================================

AUTORUN_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
]


def scan_autorun(report: ReportBuffer) -> list:
    """
    Сканирует автозагрузку на наличие подозрительных записей.
    
    Args:
        report: Буфер отчёта
        
    Returns:
        list: Список подозрительных записей [(name, value, key_path), ...]
    """
    console.info("Анализ автозагрузки ...")
    findings = []
    
    for hive, path in AUTORUN_KEYS:
        try:
            key = winreg.OpenKey(hive, path)
            i = 0
            while True:
                try:
                    name, value, vtype = winreg.EnumValue(key, i)
                    i += 1
                except OSError:
                    break
                
                # Whitelist
                if is_name_whitelisted(name):
                    continue
                
                # Проверка стоп-слов
                hit = _check_stop_words(name) or _check_stop_words(value)
                if hit:
                    findings.append((name, value, path, hit))
                    report.event("AUTORUN-TRIGGER", f"{name} = '{value}' | key='{path}' | match='{hit}'")
                
                # Проверка подозрительного пути
                if _is_suspicious_path(value):
                    findings.append((name, value, path, "SUSPICIOUS-PATH"))
                    report.event("AUTORUN-SUSPICIOUS", f"{name} = '{value}' | key='{path}'")
            
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError):
            pass
        except Exception as e:
            console.warn(f"Автозагрузка {path}: {e}")
    
    console.ok(f"Автозагрузка: {len(findings)} подозрительных записей")
    return findings


# ============================================================================
# СЕКЦИЯ 25: МОДУЛЬ 12 — СЕТЕВЫЕ ПОДКЛЮЧЕНИЯ
# ============================================================================

def scan_network(report: ReportBuffer) -> list:
    """
    Сканирует активные сетевые подключения.
    
    Использует netstat БЕЗ CREATE_NO_WINDOW.
    
    Args:
        report: Буфер отчёта
        
    Returns:
        list: Список подозрительных подключений
    """
    console.info("Анализ сетевых подключений ...")
    findings = []
    
    try:
        # БЕЗ CREATE_NO_WINDOW — безопаснее для антивирусов
        proc = subprocess.run(
            ['netstat', '-ano', '-p', 'tcp'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=30
        )
        
        if proc.returncode != 0:
            return findings
        
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith('Active') or line.startswith('Proto'):
                continue
            
            parts = line.split()
            if len(parts) < 5:
                continue
            
            proto = parts[0]
            local = parts[1]
            remote = parts[2]
            state = parts[3]
            pid = parts[4]
            
            # Фильтруем только ESTABLISHED соединения
            if state != 'ESTABLISHED':
                continue
            
            # Пропускаем локальные адреса
            if remote.startswith('127.') or remote.startswith('[::1]') or remote.startswith('0.0.0.0'):
                continue
            
            findings.append((proto, local, remote, state, pid))
            report.event("NETWORK-CONN", f"{proto} {local} -> {remote} [{state}] PID={pid}")
        
        console.ok(f"Сеть: {len(findings)} активных подключений")
        
    except subprocess.TimeoutExpired:
        console.warn("Сеть: таймаут")
    except Exception as e:
        console.fail(f"Сеть: ошибка {e}")
    
    return findings


# ============================================================================
# СЕКЦИЯ 26: МОДУЛЬ 13 — АНТИВИРУСЫ
# ============================================================================

def scan_antivirus(report: ReportBuffer) -> list:
    """
    Сканирует установленные антивирусы через WMI.
    
    БЕЗ CREATE_NO_WINDOW — безопаснее для антивирусов.
    
    Args:
        report: Буфер отчёта
        
    Returns:
        list: Список антивирусов [(name, state), ...]
    """
    console.info("Анализ антивирусов ...")
    findings = []
    
    try:
        # БЕЗ CREATE_NO_WINDOW — безопаснее для антивирусов
        proc = subprocess.run(
            ['wmic', '/namespace:\\\\root\\SecurityCenter2', 'path', 'AntiVirusProduct', 'get', 'displayName,productState', '/format:csv'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=30
        )
        
        if proc.returncode != 0:
            return findings
        
        reader = csv.reader(io.StringIO(proc.stdout))
        next(reader, None)
        
        for row in reader:
            if len(row) < 3:
                continue
            try:
                name = row[1].strip()
                state_raw = row[2].strip()
            except IndexError:
                continue
            
            if not name:
                continue
            
            # Определяем состояние по коду
            state_code = int(state_raw) if state_raw.isdigit() else 0
            if state_code & 0x1000:
                state = "ACTIVE"
            elif state_code & 0x2000:
                state = "INACTIVE"
            elif state_code & 0x3000:
                state = "SNOOZED"
            else:
                state = f"UNKNOWN({state_code})"
            
            findings.append((name, state))
            report.event("ANTIVIRUS", f"{name} | state={state}")
        
        console.ok(f"Антивирусы: {len(findings)} обнаружено")
        
    except subprocess.TimeoutExpired:
        console.warn("Антивирусы: таймаут")
    except Exception as e:
        console.fail(f"Антивирусы: ошибка {e}")
    
    return findings


# ============================================================================
# СЕКЦИЯ 27: АНАЛИЗ АНОМАЛИЙ
# ============================================================================

def evaluate_anomalies(usn, prefetch, bam, deep, events, report: ReportBuffer) -> list:
    """
    Анализирует совокупность данных на наличие аномалий.
    
    Args:
        usn: Данные USN Journal
        prefetch: Данные Prefetch
        bam: Данные BAM
        deep: Данные Deep Scan
        events: Данные Event Logs
        report: Буфер отчёта
        
    Returns:
        list: Список аномалий [(type, value), ...]
    """
    console.info("Анализ аномалий ...")
    anomalies = []

    # Аномалия 1: Множество триггеров
    total_triggers = len(prefetch) + len(bam) + len(deep)
    if total_triggers >= 3:
        anomalies.append(('MULTIPLE-TRIGGERS', total_triggers))
        report.event("АНОМАЛИЯ", f"Суммарно триггеров: {total_triggers}")

    # Аномалия 2: Новая служба + очистка журнала
    has_new_service = any(e[1] in ('NEW_SERVICE', 'NEW_SERVICE_ALT') for e in events)
    has_log_clear = any(e[1] == 'LOG_CLEARED' for e in events)
    if has_new_service and has_log_clear:
        anomalies.append(('SERVICE-AND-CLEANUP', True))
        report.event("АНОМАЛИЯ", "Новая служба + очистка журнала")

    console.ok(f"Аномалии: {len(anomalies)}")
    return anomalies


def detect_sterile(prefetch_empty: bool, browsers_empty: bool, log_cleared: bool, report: ReportBuffer) -> bool:
    """
    Детектирует "стерильный" ПК — признаки намеренного сокрытия улик.
    
    Args:
        prefetch_empty: Пуст ли Prefetch
        browsers_empty: Пуста ли история браузеров
        log_cleared: Были ли очищены журналы
        report: Буфер отчёта
        
    Returns:
        bool: True если ПК стерильный
    """
    sterile = prefetch_empty and browsers_empty and log_cleared
    if sterile:
        console.critical("СТЕРИЛЬНЫЙ ПК: признаки намеренного сокрытия улик")
        report.event("КРИТИЧНО", "СТЕРИЛЬНЫЙ ПК — все артефакты отсутствуют")
    return sterile


# ============================================================================
# СЕКЦИЯ 28: ГЛАВНАЯ ФУНКЦИЯ
# ============================================================================

def main() -> None:
    """
    Главная функция программы.
    
    Запускает все модули сканирования, формирует отчёт, шифрует и сохраняет.
    """
    console.header("RUST PC CHECKER v3.2 — запуск")
    console.info("⏳ Сканирование запущено. Это может занять 15-40 секунд. Не закрывайте окно...")

    # Проверка прав администратора (БЕЗ автоповышения)
    if not check_admin_rights():
        sys.exit(1)

    # Загрузка whitelist
    # Загрузка whitelist
    try:
        load_whitelist()
    except Exception as e:
        console.warn(f"Ошибка загрузки whitelist: {e}")

    # === ВКЛЮЧЕНИЕ ПРИВИЛЕГИЙ ДЛЯ AMCACHE ===
    # Это СТАНДАРТНЫЙ Windows API, антивирусы его НЕ триггерят
    # Без этих привилегий RegLoadKey НЕ РАБОТАЕТ даже от админа
    try:
        if _enable_privileges():
            console.ok("Привилегии SeBackup/SeRestore включены")
        else:
            console.warn("Не удалось включить привилегии — Amcache может быть недоступен")
    except Exception as e:
        console.warn(f"Ошибка включения привилегий: {e}")

    # Инициализация буфера отчёта
    buf = ReportBuffer()    # Загрузка whitelist
    try:
        load_whitelist()
    except Exception as e:
        console.warn(f"Ошибка загрузки whitelist: {e}")

    # === ВКЛЮЧЕНИЕ ПРИВИЛЕГИЙ ДЛЯ AMCACHE ===
    # Это СТАНДАРТНЫЙ Windows API, антивирусы его НЕ триггерят
    # Без этих привилегий RegLoadKey НЕ РАБОТАЕТ даже от админа
    try:
        if _enable_privileges():
            console.ok("Привилегии SeBackup/SeRestore включены")
        else:
            console.warn("Не удалось включить привилегии — Amcache может быть недоступен")
    except Exception as e:
        console.warn(f"Ошибка включения привилегий: {e}")

    # Инициализация буфера отчёта
    buf = ReportBuffer()

    # === МОДУЛИ СКАНИРОВАНИЯ (каждый обёрнут в try-except) ===
    
    # Модуль 1: USN Journal
    try:
        usn = scan_usn_journal(buf)
    except Exception as e:
        console.fail(f"USN Journal: критическая ошибка — {e}")
        usn = []
        buf.event("КРИТИЧЕСКАЯ ОШИБКА", f"USN Journal: {e}")

    # Модуль 2: Prefetch
    try:
        prefetch = scan_prefetch(buf)
    except Exception as e:
        console.fail(f"Prefetch: критическая ошибка — {e}")
        prefetch = []
        buf.event("КРИТИЧЕСКАЯ ОШИБКА", f"Prefetch: {e}")

    # Модуль 3: BAM
    try:
        bam = scan_bam(buf)
    except Exception as e:
        console.fail(f"BAM: критическая ошибка — {e}")
        bam = []
        buf.event("КРИТИЧЕСКАЯ ОШИБКА", f"BAM: {e}")

    # Модуль 4: Amcache
    try:
        amcache = scan_amcache(buf)
    except Exception as e:
        console.fail(f"Amcache: критическая ошибка — {e}")
        amcache = []
        buf.event("КРИТИЧЕСКАЯ ОШИБКА", f"Amcache: {e}")

    # Модуль 5: Браузеры
    try:
        browser_history = scan_browsers(buf)
    except Exception as e:
        console.fail(f"Браузеры: критическая ошибка — {e}")
        browser_history = {}
        buf.event("КРИТИЧЕСКАЯ ОШИБКА", f"Браузеры: {e}")

    # Выводим полную историю посещений
    try:
        buf.section("ПОЛНАЯ ИСТОРИЯ БРАУЗЕРОВ (7 дней)")
        for browser, records in browser_history.items():
            buf.info(f"=== {browser} ({len(records)} записей) ===")
            for record in records[:500]:
                url = record[0]
                title = (record[1] or '').replace('\n', ' ')[:80]
                ts = record[2] if len(record) > 2 else None
                is_dl = record[3] if len(record) > 3 else False
                search = record[4] if len(record) > 4 else ''
                prefix = "DOWNLOAD" if is_dl else "VISIT"
                search_info = f" | search='{search}'" if search else ""
                buf.event(prefix, f"[{browser}] {url} | title='{title}'{search_info}", ts)
            if len(records) > 500:
                buf.info(f"... ещё {len(records) - 500} записей (лимит)")
    except Exception as e:
        console.warn(f"Ошибка вывода истории: {e}")

    # Модуль 6: Funpay
    try:
        funpay = analyze_funpay(browser_history, buf)
    except Exception as e:
        console.fail(f"Funpay: критическая ошибка — {e}")
        funpay = []

    # Модуль 7: Event Logs
    try:
        events = scan_event_logs(buf)
    except Exception as e:
        console.fail(f"Event Logs: критическая ошибка — {e}")
        events = []
        buf.event("КРИТИЧЕСКАЯ ОШИБКА", f"Event Logs: {e}")

    # Модуль 8: Deep Scan
    try:
        deep = scan_deep(buf)
    except Exception as e:
        console.fail(f"Deep Scan: критическая ошибка — {e}")
        deep = []
        buf.event("КРИТИЧЕСКАЯ ОШИБКА", f"Deep Scan: {e}")

    # Модуль 9: Steam
    try:
        steam = scan_steam(buf)
    except Exception as e:
        console.fail(f"Steam: критическая ошибка — {e}")
        steam = {'accounts': [], 'mafiles': []}

    # Модуль 10: Процессы
    try:
        processes = scan_processes(buf)
    except Exception as e:
        console.fail(f"Процессы: критическая ошибка — {e}")
        processes = []

    # Модуль 11: Автозагрузка
    try:
        autorun = scan_autorun(buf)
    except Exception as e:
        console.fail(f"Автозагрузка: критическая ошибка — {e}")
        autorun = []

    # Модуль 12: Сеть
    try:
        network = scan_network(buf)
    except Exception as e:
        console.fail(f"Сеть: критическая ошибка — {e}")
        network = []

    # Модуль 13: Антивирусы
    try:
        antivirus = scan_antivirus(buf)
    except Exception as e:
        console.fail(f"Антивирусы: критическая ошибка — {e}")
        antivirus = []

    # Анализ аномалий
    try:
        bam_combined = bam + amcache
        anomalies = evaluate_anomalies(usn, prefetch, bam_combined, deep, events, buf)
    except Exception as e:
        console.fail(f"Анализ аномалий: {e}")
        anomalies = []

    # Детекция стерильного ПК
    try:
        prefetch_empty = len(prefetch) == 0
        browsers_empty = all(len(v) == 0 for v in browser_history.values())
        log_cleared = any(e[1] == 'LOG_CLEARED' for e in events)
        detect_sterile(prefetch_empty, browsers_empty, log_cleared, buf)
    except Exception as e:
        console.warn(f"Ошибка детекции стерильного ПК: {e}")

    # Финализация отчёта
    buf.section("END OF REPORT")
    buf.info(f"Finished: {dt.datetime.now():%Y-%m-%d %H:%M:%S}")

    # Получение текста и шифрование
    try:
        text = buf.get_text()
        enc = encrypt_text(text)
    except Exception as e:
        console.critical(f"Ошибка шифрования: {e}")
        input("\nНажмите Enter для выхода...")
        sys.exit(2)

    # === СОХРАНЕНИЕ ТОЛЬКО В ЗАГРУЗКИ (БЕЗ FALLBACK) ===
    save_dir = _get_save_path()
    
    if save_dir is None:
        console.critical("КРИТИЧЕСКАЯ ОШИБКА: Не удалось найти папку 'Загрузки'!")
        console.critical("Отчёт не может быть сохранён.")
        input("\nНажмите Enter для выхода...")
        sys.exit(3)
    
    out_filename = REPORT_FILENAME + REPORT_ENC_EXT
    out_path = os.path.join(save_dir, out_filename)

    try:
        with open(out_path, 'wb') as f:
            f.write(enc)
        console.ok(f"Отчёт сохранён: {out_path}")
    except Exception as e:
        console.critical(f"Не удалось сохранить отчёт: {e}")
        input("\nНажмите Enter для выхода...")
        sys.exit(2)
    
    # === ОКНО НЕ ЗАКРОЕТСЯ ДО НАЖАТИЯ ENTER ===
    input("\n[✓] Проверка завершена. Нажмите Enter для выхода...")


# ============================================================================
# СЕКЦИЯ 29: ТОЧКА ВХОДА
# ============================================================================

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        console.warn("\nПрервано пользователем (Ctrl+C)")
        input("\nНажмите Enter для выхода...")
        sys.exit(130)
    except SystemExit:
        # Нормальный выход через sys.exit()
        raise
    except Exception as e:
        console.critical(f"\nНЕПРЕДВИДЕННАЯ ОШИБКА: {e}")
        console.critical("\nПолный traceback:")
        console.critical(traceback.format_exc())
        input("\nНажмите Enter для выхода...")
        sys.exit(1)
