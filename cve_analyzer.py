import pandas as pd
import requests
import time
import json
import os
import sys
import random
import logging
from datetime import datetime
from openpyxl import load_workbook, Workbook
from openpyxl.styles import PatternFill
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ==============================
# НАСТРОЙКИ ЛОГИРОВАНИЯ
# ==============================
LOG_LEVEL = "INFO"

# Настройка логирования
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

file_handler = logging.FileHandler('cve_analyzer.log', encoding='utf-8')
file_handler.setFormatter(log_formatter)
file_handler.setLevel(getattr(logging, LOG_LEVEL))

console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
console_handler.setLevel(logging.WARNING)

logger = logging.getLogger()
logger.setLevel(getattr(logging, LOG_LEVEL))
logger.addHandler(file_handler)
logger.addHandler(console_handler)

api_logger = logging.getLogger('NVD_API')
exploit_logger = logging.getLogger('EXPLOIT_CHECK')
main_logger = logging.getLogger('MAIN')
file_logger = logging.getLogger('FILE_HANDLING')

# ==============================
# КОНЕЦ НАСТРОЕК ЛОГИРОВАНИЯ
# ==============================

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

NVD_API_KEY = "93d9dc54-a6d1-4d16-a62c-c7cfa5351bca"

NVD_DELAY = 1.5
EXPLOIT_DELAY = 2
RETRY_DELAY = 10
MAX_RETRIES = 3

MODES = {
    '1': 'third-party',
    '2': 'microsoft', 
    '3': 'all'
}

def severity_to_number(severity):
    """Преобразует текстовую оценку критичности в числовое значение для сравнения"""
    severity_map = {
        'None': 0,
        'Low': 1,
        'Medium': 2, 
        'High': 3,
        'Critical': 4,
        'Низкий': 1,
        'Средний': 2,
        'Высокий': 3,
        'Критический': 4
    }
    return severity_map.get(severity, 0)

def number_to_severity(number):
    """Преобразует числовое значение обратно в текстовую оценку критичности"""
    severity_map = {
        0: 'None',
        1: 'Low', 
        2: 'Medium',
        3: 'High',
        4: 'Critical'
    }
    return severity_map.get(number, 'N/A')

def get_highest_severity(severity1, severity2):
    """Возвращает наивысшую оценку критичности из двух"""
    num1 = severity_to_number(severity1)
    num2 = severity_to_number(severity2)
    
    highest_num = max(num1, num2)
    return number_to_severity(highest_num)

def create_session():
    """Создает сессию с повторными попытками и отключенной проверкой SSL"""
    main_logger.debug("Создание HTTP сессии с повторными попытками")
    session = requests.Session()
    
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = False
    
    main_logger.debug("HTTP сессия создана успешно")
    return session

def find_column_name(df, possible_names):
    """Находит имя столбца в DataFrame по списку возможных имен"""
    for name in possible_names:
        if name in df.columns:
            return name
    return None

def find_details_sheet(file_path):
    """Автоматически находит лист с именем 'Details' в файле Excel"""
    file_logger.info(f"Поиск листа Details в файле: {file_path}")
    try:
        excel_file = pd.ExcelFile(file_path)
        sheet_names = excel_file.sheet_names
        
        file_logger.debug(f"Найдены листы в файле: {sheet_names}")
        
        details_sheet = None
        details_index = None
        
        for i, sheet_name in enumerate(sheet_names):
            if 'details' in sheet_name.lower():
                details_sheet = sheet_name
                details_index = i
                file_logger.info(f"Найден лист 'Details': '{sheet_name}' (индекс {i})")
                break
        
        if details_sheet is None:
            file_logger.warning("Лист с именем 'Details' не найден, поиск по содержанию...")
            for i, sheet_name in enumerate(sheet_names):
                try:
                    test_df = pd.read_excel(file_path, sheet_name=sheet_name, nrows=5)
                    # Ищем столбец с CVE ID по разным возможным названиям
                    cve_column = find_column_name(test_df, ['CVE ID', 'CVE ID', 'CVE_ID', 'CVE-ID', 'CVE'])
                    if cve_column:
                        details_sheet = sheet_name
                        details_index = i
                        file_logger.info(f"Найден лист с CVE данными: '{sheet_name}' (индекс {i})")
                        break
                except Exception as e:
                    file_logger.debug(f"Ошибка при проверке листа {sheet_name}: {e}")
                    continue
        
        if details_sheet is None:
            if len(sheet_names) > 1:
                details_sheet = sheet_names[1]
                details_index = 1
                file_logger.warning(f"Используем лист по умолчанию (второй): '{details_sheet}'")
            else:
                details_sheet = sheet_names[0]
                details_index = 0
                file_logger.warning(f"Используем единственный лист: '{details_sheet}'")
        
        return details_sheet, details_index
        
    except Exception as e:
        file_logger.error(f"Ошибка при поиске листа 'Details': {e}", exc_info=True)
        return None, None

def get_cvss_score(cve_id, session, retry_count=0):
    """Получает CVSS 3.x базовую оценку для CVE через API NVD с использованием API ключа"""
    api_logger.debug(f"Запрос данных для {cve_id} (попытка {retry_count + 1})")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    headers = {
        "apiKey": NVD_API_KEY
    }
    
    try:
        start_time = time.time()
        response = session.get(url, headers=headers, timeout=30)
        response_time = time.time() - start_time
        
        api_logger.debug(f"Ответ от NVD API для {cve_id}: статус {response.status_code}, время: {response_time:.2f}с")
        
        if response.status_code == 403:
            if retry_count < MAX_RETRIES:
                api_logger.warning(f"Получен статус 403 для {cve_id}. Повторная попытка {retry_count + 1}/{MAX_RETRIES} через {RETRY_DELAY} сек...")
                time.sleep(RETRY_DELAY)
                return get_cvss_score(cve_id, session, retry_count + 1)
            else:
                api_logger.error(f"Превышено максимальное количество попыток для {cve_id} (403 ошибка)")
                return "Error: 403 Forbidden after retries", "API Error", "N/A", "N/A"
        elif response.status_code == 429:
            api_logger.warning(f"Превышен лимит запросов (429) для {cve_id}")
            return "Error: 429 Rate Limited", "API Error", "N/A", "N/A"
        elif response.status_code != 200:
            api_logger.warning(f"Некорректный статус ответа для {cve_id}: {response.status_code}")
        
        response.raise_for_status()
        
        data = response.json()
        
        if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
            vulnerability = data['vulnerabilities'][0]['cve']
            
            published_date = vulnerability.get('published', 'N/A')
            
            if 'cvssMetricV31' in vulnerability['metrics']:
                cvss_data = vulnerability['metrics']['cvssMetricV31'][0]['cvssData']
                base_score = cvss_data['baseScore']
                version = cvss_data['version']
                api_logger.debug(f"{cve_id}: CVSS {version} оценка = {base_score}")
            elif 'cvssMetricV30' in vulnerability['metrics']:
                cvss_data = vulnerability['metrics']['cvssMetricV30'][0]['cvssData']
                base_score = cvss_data['baseScore']
                version = cvss_data['version']
                api_logger.debug(f"{cve_id}: CVSS {version} оценка = {base_score}")
            elif 'cvssMetricV2' in vulnerability['metrics']:
                cvss_data = vulnerability['metrics']['cvssMetricV2'][0]['cvssData']
                base_score = cvss_data['baseScore']
                version = "2.0"
                api_logger.debug(f"{cve_id}: CVSS {version} оценка = {base_score}")
            else:
                base_score = "N/A"
                version = "No CVSS data"
                api_logger.debug(f"{cve_id}: данные CVSS не найдены")
            
            if isinstance(base_score, (int, float)):
                if base_score >= 9.0:
                    severity = "Critical"
                elif base_score >= 7.0:
                    severity = "High"
                elif base_score >= 4.0:
                    severity = "Medium"
                elif base_score >= 0.1:
                    severity = "Low"
                else:
                    severity = "None"
            else:
                severity = "N/A"
                
            api_logger.info(f"{cve_id}: оценка {base_score}, уровень {severity}, версия {version}")
            return base_score, version, severity, published_date
        else:
            api_logger.warning(f"{cve_id}: уязвимость не найдена в NVD")
            return "Not Found", "CVE not found", "N/A", "N/A"
            
    except requests.exceptions.RequestException as e:
        api_logger.error(f"Ошибка запроса для {cve_id}: {str(e)}", exc_info=True)
        if retry_count < MAX_RETRIES:
            api_logger.warning(f"Повторная попытка {retry_count + 1}/{MAX_RETRIES} для {cve_id} через {RETRY_DELAY} сек...")
            time.sleep(RETRY_DELAY)
            return get_cvss_score(cve_id, session, retry_count + 1)
        else:
            api_logger.error(f"Превышено максимальное количество попыток для {cve_id}")
            return f"Error: {str(e)}", "API Error", "N/A", "N/A"
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        api_logger.error(f"Ошибка парсинга данных для {cve_id}: {str(e)}", exc_info=True)
        return f"Parse Error: {str(e)}", "Data Parse Error", "N/A", "N/A"

def check_exploit_availability(cve_id, session):
    """Проверяет наличие эксплойтов для CVE через различные источники"""
    exploit_logger.debug(f"Проверка эксплойтов для {cve_id}")
    sources = [
        f"https://www.exploit-db.com/search?cve={cve_id}",
        f"https://github.com/search?q={cve_id}+exploit&type=repositories",
        f"https://packetstormsecurity.com/search/?q={cve_id}",
        f"https://0day.today/search?search_request={cve_id}"
    ]
    
    source_names = ["exploit-db.com", "github.com", "packetstormsecurity.com", "0day.today"]
    exploit_sources = []
    
    for i, source in enumerate(sources):
        try:
            exploit_logger.debug(f"Проверка {source_names[i]} для {cve_id}")
            response = session.get(source, timeout=15, verify=False)
            if response.status_code == 200:
                if any(keyword in response.text.lower() for keyword in ['exploit', 'poc', 'proof of concept', 'code execution']):
                    exploit_sources.append(source_names[i])
                    exploit_logger.debug(f"Найден эксплойт для {cve_id} в {source_names[i]}")
            else:
                exploit_logger.debug(f"Статус {response.status_code} для {source_names[i]}")
        except Exception as e:
            exploit_logger.debug(f"Ошибка при проверке {source_names[i]}: {e}")
            continue
        
        time.sleep(0.5 + random.uniform(0, 0.5))
    
    result = f"Найдены в: {', '.join(exploit_sources)}" if exploit_sources else "Не найдено подтверждений о наличии публичных эксплойтов"
    exploit_logger.info(f"Результат проверки эксплойтов для {cve_id}: {result}")
    return result

def print_progress_bar(iteration, total, prefix='', suffix='', decimals=1, length=50, fill='█'):
    """Выводит прогресс-бар в консоль"""
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    if iteration == total:
        print()

def initialize_excel_output(output_file):
    """Инициализирует Excel файл с заголовками"""
    main_logger.info(f"Инициализация выходного файла: {output_file}")
    
    wb = Workbook()
    ws = wb.active
    ws.title = 'CVE Report'
    
    # Заголовки столбцов
    headers = [
        'Узел',
        'CVE-идентификатор', 
        'Дата публикации информации об уязвимости',
        'Оценка уязвимости CVSSv3',
        'Оценка критичности согласно CVSSv3',
        'Оценка критичности согласно Kaspersky',  # Новый столбец
        'Оценка критичности согласно внутренней методики',  # Теперь комбинированная оценка
        'Наличие exploit/workaround',
        'Дата обнаружения',
        'Дата устранения (фактическая или запланированная)',
        'Комментарий'
    ]
    
    # Записываем заголовки
    for col, header in enumerate(headers, 1):
        ws.cell(row=1, column=col, value=header)
    
    # Настраиваем ширину колонок
    column_widths = {
        'A': 25, 'B': 20, 'C': 25, 'D': 15, 'E': 25,
        'F': 30, 'G': 35, 'H': 35, 'I': 20, 'J': 30, 'K': 40
    }
    
    for col, width in column_widths.items():
        ws.column_dimensions[col].width = width
    
    wb.save(output_file)
    main_logger.info("Выходной файл инициализирован успешно")
    return len(headers)

def append_to_excel(output_file, row_data, row_number):
    """Добавляет строку данных в Excel файл"""
    try:
        wb = load_workbook(output_file)
        ws = wb.active
        
        for col, value in enumerate(row_data, 1):
            ws.cell(row=row_number, column=col, value=value)
        
        wb.save(output_file)
        return True
    except Exception as e:
        main_logger.error(f"Ошибка при записи в файл {output_file}: {e}")
        return False

def apply_color_formatting(output_file):
    """Применяет цветовое форматирование к Excel файлу"""
    main_logger.debug(f"Применение цветового форматирования к файлу: {output_file}")
    try:
        wb = load_workbook(output_file)
        ws = wb.active
        
        critical_fill = PatternFill(start_color='FF0000', end_color='FF0000', fill_type='solid')
        high_fill = PatternFill(start_color='FFA500', end_color='FFA500', fill_type='solid')
        medium_fill = PatternFill(start_color='FFFF00', end_color='FFFF00', fill_type='solid')
        low_fill = PatternFill(start_color='00FF00', end_color='00FF00', fill_type='solid')
        na_fill = PatternFill(start_color='CCCCCC', end_color='CCCCCC', fill_type='solid')
        
        formatted_cells = 0
        for row in range(2, ws.max_row + 1):
            score_cell = ws.cell(row=row, column=4)  # Столбец D - Оценка CVSSv3
            
            try:
                if isinstance(score_cell.value, (int, float)):
                    score = float(score_cell.value)
                    
                    if score >= 9.0:
                        score_cell.fill = critical_fill
                    elif score >= 7.0:
                        score_cell.fill = high_fill
                    elif score >= 4.0:
                        score_cell.fill = medium_fill
                    elif score >= 0.1:
                        score_cell.fill = low_fill
                    formatted_cells += 1
                else:
                    score_cell.fill = na_fill
                    formatted_cells += 1
                    
            except (ValueError, TypeError):
                score_cell.fill = na_fill
                formatted_cells += 1
        
        wb.save(output_file)
        main_logger.info(f"Цветовое форматирование применено к {formatted_cells} ячейкам")
    except Exception as e:
        main_logger.error(f"Ошибка при применении форматирования: {e}")

def process_cve_list(file_path, mode='third-party'):
    """Обрабатывает файл Excel и получает CVSS оценки для CVE с пошаговой записью"""
    main_logger.info(f"Начало обработки файла: {file_path} в режиме: {mode}")
    
    details_sheet_name, details_sheet_index = find_details_sheet(file_path)
    
    if details_sheet_name is None:
        main_logger.error("Не удалось найти подходящий лист с CVE данными")
        return {}, []
    
    try:
        main_logger.info(f"Чтение листа: '{details_sheet_name}'")
        df = pd.read_excel(file_path, sheet_name=details_sheet_name)
        main_logger.info(f"Успешно прочитан лист '{details_sheet_name}', колонки: {list(df.columns)}")
    except Exception as e:
        main_logger.error(f"Ошибка при чтении листа '{details_sheet_name}': {e}", exc_info=True)
        return {}, []
    
    # Определяем имена столбцов
    cve_column = find_column_name(df, ['CVE ID', 'CVE ID', 'CVE_ID', 'CVE-ID', 'CVE'])
    vendor_column = find_column_name(df, ['Vendor', 'Vendor name', 'Производитель'])
    device_column = find_column_name(df, ['Device', 'Устройство', 'Host', 'Хост'])
    app_column = find_column_name(df, ['Application name', 'Application', 'Приложение'])
    severity_column = find_column_name(df, ['Severity level', 'Severity', 'Уровень критичности', 'Критичность'])
    
    if not cve_column:
        main_logger.error("Столбец с CVE ID не найден в файле")
        main_logger.error(f"Доступные колонки: {list(df.columns)}")
        return {}, []
    
    main_logger.info(f"Используемые столбцы: CVE={cve_column}, Vendor={vendor_column}, Device={device_column}, App={app_column}, Severity={severity_column}")
    
    # Фильтруем записи в зависимости от выбранного режима
    if vendor_column:
        initial_count = len(df)
        
        if mode == 'third-party':
            df = df[df[vendor_column] != 'Microsoft']
            filtered_count = initial_count - len(df)
            main_logger.info(f"Режим 'third-party': отфильтровано записей Microsoft: {filtered_count}")
        elif mode == 'microsoft':
            df = df[df[vendor_column] == 'Microsoft']
            filtered_count = initial_count - len(df)
            main_logger.info(f"Режим 'microsoft': отфильтровано записей не-Microsoft: {filtered_count}")
        else:
            main_logger.info(f"Режим 'all': все записи сохранены, без фильтрации")
            filtered_count = 0
    
    # Собираем данные по CVE, включая оценку Kaspersky
    cve_data = {}
    
    main_logger.info("Извлечение уникальных CVE из файла с оценками Kaspersky")
    for index, row in df.iterrows():
        cve_id = str(row[cve_column]) if pd.notna(row[cve_column]) else ""
        if cve_id.startswith('CVE-'):
            device = str(row[device_column]) if device_column and pd.notna(row.get(device_column, '')) else ""
            application = str(row[app_column]) if app_column and pd.notna(row.get(app_column, '')) else ""
            
            # Получаем оценку Kaspersky
            kaspersky_severity = ""
            if severity_column and pd.notna(row.get(severity_column)):
                kaspersky_severity = str(row[severity_column])
            
            if cve_id not in cve_data:
                cve_data[cve_id] = {
                    'devices': set([device]) if device else set(),
                    'applications': set([application]) if application else set(),
                    'kaspersky_severity': kaspersky_severity
                }
            else:
                if device:
                    cve_data[cve_id]['devices'].add(device)
                if application:
                    cve_data[cve_id]['applications'].add(application)
                # Если для этого CVE уже есть оценка Kaspersky, берем наивысшую
                if kaspersky_severity:
                    current_severity = cve_data[cve_id]['kaspersky_severity']
                    if current_severity:
                        # Выбираем наивысшую оценку
                        highest = get_highest_severity(current_severity, kaspersky_severity)
                        cve_data[cve_id]['kaspersky_severity'] = highest
                    else:
                        cve_data[cve_id]['kaspersky_severity'] = kaspersky_severity
    
    cve_list = list(cve_data.keys())
    cve_list.sort()
    
    main_logger.info(f"Найдено {len(cve_list)} уникальных CVE для обработки (режим: {mode})")
    
    # Создаем выходной файл
    output_dir = os.path.dirname(file_path)
    mode_suffix = f"_{mode}" if mode != 'all' else ""
    output_file = os.path.join(output_dir, f"CVE_Analysis_Report{mode_suffix}.xlsx")
    
    # Инициализируем Excel файл
    num_columns = initialize_excel_output(output_file)
    
    # Создаем сессию
    session = create_session()
    
    # Статистика
    stats = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'errors': 0,
        'not_found': 0,
        'rate_limited': 0
    }
    
    top_cves = []
    today_date = datetime.now().strftime('%Y-%m-%d 00:00:00')
    
    main_logger.info("Начало обработки CVE через NVD API с пошаговой записью")
    current_row = 2
    
    for i, cve_id in enumerate(cve_list):
        base_score, version, cvss_severity, published_date = get_cvss_score(cve_id, session)
        
        # Проверяем наличие эксплойтов
        time.sleep(EXPLOIT_DELAY + random.uniform(0, 0.5))
        exploit_info = check_exploit_availability(cve_id, session)
        
        # Получаем оценку Kaspersky для этого CVE
        kaspersky_severity = cve_data[cve_id].get('kaspersky_severity', 'N/A')
        
        # Вычисляем комбинированную оценку (наивысшую из CVSS и Kaspersky)
        combined_severity = get_highest_severity(cvss_severity, kaspersky_severity)
        
        # Обновляем статистику на основе комбинированной оценки
        severity_num = severity_to_number(combined_severity)
        if severity_num == 4:
            stats['critical'] += 1
        elif severity_num == 3:
            stats['high'] += 1
        elif severity_num == 2:
            stats['medium'] += 1
        elif severity_num == 1:
            stats['low'] += 1
        
        # Сохраняем для топа (на основе числовой оценки CVSS)
        if isinstance(base_score, (int, float)):
            top_cves.append((cve_id, base_score, combined_severity))
            top_cves.sort(key=lambda x: x[1], reverse=True)
            if len(top_cves) > 5:
                top_cves = top_cves[:5]
        elif "403 Forbidden" in str(base_score):
            stats['rate_limited'] += 1
        elif "Not Found" in str(base_score):
            stats['not_found'] += 1
        else:
            stats['errors'] += 1
        
        # Форматируем дату публикации
        if published_date != 'N/A' and published_date != 'N/A':
            try:
                published_date = pd.to_datetime(published_date).strftime('%Y-%m-%d 00:00:00')
            except Exception as e:
                main_logger.debug(f"Ошибка форматирования даты для {cve_id}: {e}")
                published_date = 'N/A'
        
        # Получаем устройства и приложения
        devices = ', '.join(cve_data[cve_id]['devices']) if cve_data[cve_id]['devices'] else ''
        applications = ', '.join(cve_data[cve_id]['applications']) if cve_data[cve_id]['applications'] else ''
        
        # Формируем строку для записи
        row_data = [
            devices,
            cve_id,
            published_date,
            base_score if isinstance(base_score, (int, float)) else 'N/A',
            cvss_severity,
            kaspersky_severity,  # Оценка Kaspersky
            combined_severity,    # Комбинированная оценка
            exploit_info,
            today_date,
            '',  # Дата устранения
            applications
        ]
        
        # Записываем строку в Excel
        success = append_to_excel(output_file, row_data, current_row)
        if not success:
            main_logger.error(f"Не удалось записать данные для {cve_id}")
        
        current_row += 1
        
        # Обновляем прогресс-бар
        progress_prefix = f"Режим {mode}: {stats['critical']} критич, {stats['high']} высок, {stats['medium']} средн, {stats['low']} низк, {stats['errors']} ошибок"
        print_progress_bar(i + 1, len(cve_list), prefix=progress_prefix, suffix=f'Обработано: {i+1}/{len(cve_list)}')
        
        # Пауза для соблюдения лимитов API
        time.sleep(NVD_DELAY + random.uniform(0, 0.3))
    
    print()
    main_logger.info("Обработка всех CVE завершена")
    
    # Применяем цветовое форматирование
    apply_color_formatting(output_file)
    
    print(f"Результаты сохранены в файл: {output_file}")
    return stats, top_cves

def get_file_path():
    """Запрашивает путь к файлу у пользователя"""
    default_path = r"C:\Users\cu-nazarov-na\Desktop\kasper_cve\example.xlsx"
    
    print("Введите путь к файлу Excel с CVE данными:")
    print(f"Нажмите Enter для использования пути по умолчанию: {default_path}")
    
    user_input = input("Путь к файлу: ").strip()
    
    if user_input == "":
        file_path = default_path
    else:
        file_path = user_input
    
    if file_path.startswith('"') and file_path.endswith('"'):
        file_path = file_path[1:-1]
    
    return file_path

def get_work_mode():
    """Запрашивает у пользователя режим работы"""
    print("\nВыберите режим работы:")
    print("1 - Third-party (исключить Microsoft) - по умолчанию")
    print("2 - Microsoft (только Microsoft)")
    print("3 - All (все CVE)")
    
    user_input = input("Введите номер режима (1/2/3): ").strip()
    
    if user_input in MODES:
        mode = MODES[user_input]
        print(f"Выбран режим: {mode}")
    else:
        mode = 'third-party'
        print(f"Неверный ввод, используется режим по умолчанию: {mode}")
    
    return mode

def main():
    main_logger.info("Запуск CVE анализатора")
    
    file_path = get_file_path()
    mode = get_work_mode()
    
    if not os.path.exists(file_path):
        main_logger.error(f"Файл не найден: {file_path}")
        print(f"Файл не найден: {file_path}")
        return
    
    print("Начинаем анализ CVE уязвимостей...")
    print(f"Исходный файл: {file_path}")
    print(f"Режим работы: {mode}")
    print(f"API ключ: {NVD_API_KEY}")
    print(f"Уровень логирования: {LOG_LEVEL}")
    print(f"Настройки задержек: NVD={NVD_DELAY}с, Exploit={EXPLOIT_DELAY}с, Retry={RETRY_DELAY}с")
    print("=" * 60)
    
    main_logger.info(f"Настройки: режим={mode}, NVD_DELAY={NVD_DELAY}, EXPLOIT_DELAY={EXPLOIT_DELAY}, RETRY_DELAY={RETRY_DELAY}")
    
    try:
        stats, top_cves = process_cve_list(file_path, mode)
    except Exception as e:
        main_logger.critical(f"Критическая ошибка при выполнении анализа: {e}", exc_info=True)
        print(f"Произошла критическая ошибка: {e}")
        print("Подробности смотрите в файле лога cve_analyzer.log")
        return
    
    print("\n" + "=" * 60)
    print("ИТОГОВАЯ СТАТИСТИКА АНАЛИЗА")
    print("=" * 60)
    print(f"Режим работы: {mode}")
    print(f"Всего обработано CVE: {sum(stats.values())}")
    print(f"Критические (9.0-10.0): {stats['critical']}")
    print(f"Высокие (7.0-8.9): {stats['high']}")
    print(f"Средние (4.0-6.9): {stats['medium']}")
    print(f"Низкие (0.1-3.9): {stats['low']}")
    print(f"Ошибки/не найдено: {stats['errors'] + stats['not_found']}")
    if stats['rate_limited'] > 0:
        print(f"Ошибки лимита запросов (403): {stats['rate_limited']}")
    
    main_logger.info(f"Итоговая статистика: {stats}")
    
    if top_cves:
        print("\nТОП-5 САМЫХ КРИТИЧНЫХ УЯЗВИМОСТЕЙ:")
        for cve_id, score, severity in top_cves:
            print(f"  {cve_id}: {score} ({severity})")
        
        main_logger.info("Топ-5 критичных уязвимостей:")
        for cve_id, score, severity in top_cves:
            main_logger.info(f"  {cve_id}: {score}")
    
    print("\nАнализ завершен!")
    print("Подробный лог сохранен в файл: cve_analyzer.log")
    main_logger.info("Анализ успешно завершен")

if __name__ == "__main__":
    main()
