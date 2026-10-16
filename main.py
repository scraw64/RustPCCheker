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
