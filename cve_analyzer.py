import pandas as pd
import requests
import time
import json
import os
import sys
from datetime import datetime
from openpyxl import load_workbook
from openpyxl.styles import PatternFill
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Отключаем предупреждения SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ваш API ключ для NVD
NVD_API_KEY = "93d9dc54-a6d1-4d16-a62c-c7cfa5351bca"

def create_session():
    """
    Создает сессию с повторными попытками и отключенной проверкой SSL
    """
    session = requests.Session()
    
    # Настраиваем повторные попытки
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Отключаем проверку SSL
    session.verify = False
    
    return session

def find_details_sheet(file_path):
    """
    Автоматически находит лист с именем 'Details' в файле Excel
    Возвращает имя листа и его индекс
    """
    try:
        # Получаем все названия листов
        excel_file = pd.ExcelFile(file_path)
        sheet_names = excel_file.sheet_names
        
        print(f"Найдены листы в файле: {sheet_names}")
        
        # Ищем лист с названием 'Details' (регистронезависимо)
        details_sheet = None
        details_index = None
        
        for i, sheet_name in enumerate(sheet_names):
            if 'details' in sheet_name.lower():
                details_sheet = sheet_name
                details_index = i
                print(f"Найден лист 'Details': '{sheet_name}' (индекс {i})")
                break
        
        if details_sheet is None:
            # Если не нашли по имени, пробуем найти по содержанию (лист с CVE ID)
            print("Лист с именем 'Details' не найден, поиск по содержанию...")
            for i, sheet_name in enumerate(sheet_names):
                try:
                    # Пробуем прочитать лист и проверить наличие столбца 'CVE ID'
                    test_df = pd.read_excel(file_path, sheet_name=sheet_name, nrows=5)
                    if 'CVE ID' in test_df.columns:
                        details_sheet = sheet_name
                        details_index = i
                        print(f"Найден лист с CVE данными: '{sheet_name}' (индекс {i})")
                        break
                except Exception as e:
                    continue
        
        if details_sheet is None:
            # Если все еще не нашли, используем лист с индексом 1 (второй лист)
            if len(sheet_names) > 1:
                details_sheet = sheet_names[1]
                details_index = 1
                print(f"Используем лист по умолчанию (второй): '{details_sheet}'")
            else:
                # Если только один лист, используем его
                details_sheet = sheet_names[0]
                details_index = 0
                print(f"Используем единственный лист: '{details_sheet}'")
        
        return details_sheet, details_index
        
    except Exception as e:
        print(f"Ошибка при поиске листа 'Details': {e}")
        return None, None

def get_cvss_score(cve_id, session):
    """
    Получает CVSS 3.x базовую оценку для CVE через API NVD с использованием API ключа
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    headers = {
        "apiKey": NVD_API_KEY
    }
    
    try:
        response = session.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
            vulnerability = data['vulnerabilities'][0]['cve']
            
            # Получаем дату публикации
            published_date = vulnerability.get('published', 'N/A')
            
            # Пытаемся получить CVSS 3.1
            if 'cvssMetricV31' in vulnerability['metrics']:
                cvss_data = vulnerability['metrics']['cvssMetricV31'][0]['cvssData']
                base_score = cvss_data['baseScore']
                version = cvss_data['version']
            # Если нет 3.1, пытаемся получить CVSS 3.0
            elif 'cvssMetricV30' in vulnerability['metrics']:
                cvss_data = vulnerability['metrics']['cvssMetricV30'][0]['cvssData']
                base_score = cvss_data['baseScore']
                version = cvss_data['version']
            # Если нет 3.x, пытаемся получить CVSS 2.0
            elif 'cvssMetricV2' in vulnerability['metrics']:
                cvss_data = vulnerability['metrics']['cvssMetricV2'][0]['cvssData']
                base_score = cvss_data['baseScore']
                version = "2.0"
            else:
                base_score = "N/A"
                version = "No CVSS data"
            
            # Определяем уровень критичности на основе CVSS
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
                
            return base_score, version, severity, published_date
        else:
            return "Not Found", "CVE not found", "N/A", "N/A"
            
    except requests.exceptions.RequestException as e:
        return f"Error: {str(e)}", "API Error", "N/A", "N/A"
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        return f"Parse Error: {str(e)}", "Data Parse Error", "N/A", "N/A"

def check_exploit_availability(cve_id, session):
    """
    Проверяет наличие эксплойтов для CVE через различные источники
    """
    sources = [
        # ExploitDB
        f"https://www.exploit-db.com/search?cve={cve_id}",
        # GitHub (поиск репозиториев с эксплойтами)
        f"https://github.com/search?q={cve_id}+exploit&type=repositories",
        # Packet Storm Security
        f"https://packetstormsecurity.com/search/?q={cve_id}",
        # 0day.today
        f"https://0day.today/search?search_request={cve_id}"
    ]
    
    exploit_sources = []
    
    for source in sources:
        try:
            response = session.get(source, timeout=10, verify=False)
            if response.status_code == 200:
                # Простая проверка на наличие контента, связанного с эксплойтами
                if any(keyword in response.text.lower() for keyword in ['exploit', 'poc', 'proof of concept', 'code execution']):
                    exploit_sources.append(source.split('/')[2])  # Извлекаем домен
        except:
            continue
    
    if exploit_sources:
        return f"Найдены в: {', '.join(exploit_sources)}"
    else:
        return "Не найдено подтверждений о наличии публичных эксплойтов"

def print_progress_bar(iteration, total, prefix='', suffix='', decimals=1, length=50, fill='█'):
    """
    Выводит прогресс-бар в консоль
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    # Если завершено, print новую строку
    if iteration == total:
        print()

def process_cve_list(file_path):
    """
    Обрабатывает файл Excel и получает CVSS оценки для CVE
    """
    # Автоматически находим лист Details
    details_sheet_name, details_sheet_index = find_details_sheet(file_path)
    
    if details_sheet_name is None:
        print("Не удалось найти подходящий лист с CVE данными")
        return pd.DataFrame(), {}
    
    # Читаем найденный лист
    try:
        print(f"Читаем лист: '{details_sheet_name}'")
        df = pd.read_excel(file_path, sheet_name=details_sheet_name)
        print(f"Успешно прочитан лист '{details_sheet_name}', колонки: {list(df.columns)}")
    except Exception as e:
        print(f"Ошибка при чтении листа '{details_sheet_name}': {e}")
        return pd.DataFrame(), {}
    
    # Фильтруем записи: исключаем Microsoft
    if 'Vendor' in df.columns:
        initial_count = len(df)
        df = df[df['Vendor'] != 'Microsoft']
        filtered_count = initial_count - len(df)
        print(f"Отфильтровано записей Microsoft: {filtered_count}")
    
    # Извлекаем CVE из столбца 'CVE ID'
    if 'CVE ID' not in df.columns:
        print("Столбец 'CVE ID' не найден в файле")
        print(f"Доступные колонки: {list(df.columns)}")
        return pd.DataFrame(), {}
    
    # Удаляем дубликаты CVE, но сохраняем информацию об устройствах и приложениях
    cve_data = {}
    cve_count = 0
    
    for index, row in df.iterrows():
        cve_id = str(row['CVE ID']) if pd.notna(row['CVE ID']) else ""
        if cve_id.startswith('CVE-'):
            device = str(row['Device']) if pd.notna(row.get('Device', '')) else ""
            application = str(row['Application name']) if pd.notna(row.get('Application name', '')) else ""
            
            if cve_id not in cve_data:
                cve_data[cve_id] = {
                    'devices': set([device]) if device else set(),
                    'applications': set([application]) if application else set()
                }
                cve_count += 1
            else:
                if device:
                    cve_data[cve_id]['devices'].add(device)
                if application:
                    cve_data[cve_id]['applications'].add(application)
    
    cve_list = list(cve_data.keys())
    cve_list.sort()
    
    print(f"Найдено {len(cve_list)} уникальных CVE для обработки (исключая Microsoft)")
    
    # Создаем сессию
    session = create_session()
    
    # Создаем DataFrame для результатов в требуемом формате
    results = []
    
    # Статистика для отображения в реальном времени
    stats = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'errors': 0,
        'not_found': 0
    }
    
    # Получаем сегодняшнюю дату
    today_date = datetime.now().strftime('%Y-%m-%d 00:00:00')
    
    # Обрабатываем каждый CVE
    for i, cve_id in enumerate(cve_list):
        base_score, version, severity, published_date = get_cvss_score(cve_id, session)
        
        # Проверяем наличие эксплойтов (с дополнительной задержкой, чтобы не перегружать сайты)
        time.sleep(1)
        exploit_info = check_exploit_availability(cve_id, session)
        
        # Обновляем статистику
        if isinstance(base_score, (int, float)):
            if base_score >= 9.0:
                stats['critical'] += 1
            elif base_score >= 7.0:
                stats['high'] += 1
            elif base_score >= 4.0:
                stats['medium'] += 1
            elif base_score >= 0.1:
                stats['low'] += 1
        elif "Not Found" in str(base_score):
            stats['not_found'] += 1
        else:
            stats['errors'] += 1
        
        # Форматируем дату публикации
        if published_date != 'N/A' and published_date != 'N/A':
            try:
                # Преобразуем дату в формат YYYY-MM-DD 00:00:00
                published_date = pd.to_datetime(published_date).strftime('%Y-%m-%d 00:00:00')
            except:
                published_date = 'N/A'
        
        # Получаем устройства и приложения для этого CVE
        devices = ', '.join(cve_data[cve_id]['devices']) if cve_data[cve_id]['devices'] else ''
        applications = ', '.join(cve_data[cve_id]['applications']) if cve_data[cve_id]['applications'] else ''
        
        # Добавляем запись в требуемом формате
        results.append({
            'Узел': devices,
            'CVE-идентификатор': cve_id,
            'Дата публикации информации об уязвимости': published_date,
            'Оценка уязвимости CVSSv3': base_score if isinstance(base_score, (int, float)) else 'N/A',
            'Оценка критичности согласно CVSSv3': severity,
            'Оценка критичности согласно внутренней методики': severity,  # Копируем из CVSSv3
            'Наличие exploit/workaround': exploit_info,
            'Дата обнаружения': today_date,
            'Дата устранения (фактическая или запланированная)': '',  # Оставляем пустым
            'Комментарий': applications  # Вписываем имя ПО
        })
        
        # Обновляем прогресс-бар и статистику
        progress_prefix = f"Обработка CVE: {stats['critical']} критич, {stats['high']} высок, {stats['medium']} средн, {stats['low']} низк, {stats['errors']} ошибок"
        print_progress_bar(i + 1, len(cve_list), prefix=progress_prefix, suffix=f'Обработано: {i+1}/{len(cve_list)}')
        
        # Пауза для соблюдения лимитов API
        time.sleep(0.5)
    
    # Завершаем прогресс-бар
    print()
    
    # Создаем DataFrame с результатами
    results_df = pd.DataFrame(results)
    
    # Создаем путь для выходного файла
    output_dir = os.path.dirname(file_path)
    output_file = os.path.join(output_dir, "CVE_Analysis_Report.xlsx")
    
    # Сохраняем результаты в новый файл в требуемом формате
    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        results_df.to_excel(writer, sheet_name='CVE Report', index=False)
        
        # Настраиваем ширину колонок для лучшего отображения
        worksheet = writer.sheets['CVE Report']
        column_widths = {
            'A': 25,  # Узел
            'B': 20,  # CVE-идентификатор
            'C': 25,  # Дата публикации
            'D': 15,  # Оценка CVSSv3
            'E': 25,  # Критичность CVSSv3
            'F': 30,  # Критичность внутренняя
            'G': 35,  # Наличие exploit
            'H': 20,  # Дата обнаружения
            'I': 30,  # Дата устранения
            'J': 40   # Комментарий
        }
        
        for col, width in column_widths.items():
            worksheet.column_dimensions[col].width = width
    
    # Добавляем цветовое форматирование
    add_color_formatting(output_file)
    
    print(f"Результаты сохранены в файл: {output_file}")
    return results_df, stats

def add_color_formatting(file_path):
    """
    Добавляет цветовое форматирование на основе CVSS оценок
    """
    try:
        wb = load_workbook(file_path)
        ws = wb.active
        
        # Определяем цвета для разных уровней серьезности
        critical_fill = PatternFill(start_color='FF0000', end_color='FF0000', fill_type='solid')  # Красный
        high_fill = PatternFill(start_color='FFA500', end_color='FFA500', fill_type='solid')      # Оранжевый
        medium_fill = PatternFill(start_color='FFFF00', end_color='FFFF00', fill_type='solid')    # Желтый
        low_fill = PatternFill(start_color='00FF00', end_color='00FF00', fill_type='solid')       # Зеленый
        na_fill = PatternFill(start_color='CCCCCC', end_color='CCCCCC', fill_type='solid')        # Серый для N/A
        
        for row in range(2, ws.max_row + 1):  # Пропускаем заголовок
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
                else:
                    # Для текстовых значений (N/A, ошибки)
                    score_cell.fill = na_fill
                    
            except (ValueError, TypeError):
                # Если значение не число, пропускаем
                score_cell.fill = na_fill
        
        wb.save(file_path)
        print("Цветовое форматирование применено успешно")
    except Exception as e:
        print(f"Ошибка при применении форматирования: {e}")

def get_file_path():
    """
    Запрашивает путь к файлу у пользователя
    """
    default_path = r"C:\Users\cu-nazarov-na\Desktop\kasper_cve_IKB3.0\av01\vulners av-01.xlsx"
    
    print("Введите путь к файлу Excel с CVE данными:")
    print(f"Нажмите Enter для использования пути по умолчанию: {default_path}")
    
    user_input = input("Путь к файлу: ").strip()
    
    if user_input == "":
        file_path = default_path
    else:
        file_path = user_input
    
    # Обрабатываем пути в кавычках (если пользователь перетащил файл в консоль)
    if file_path.startswith('"') and file_path.endswith('"'):
        file_path = file_path[1:-1]
    
    return file_path

def main():
    # Получаем путь к файлу от пользователя
    file_path = get_file_path()
    
    # Проверяем существование файла
    if not os.path.exists(file_path):
        print(f"Файл не найден: {file_path}")
        return
    
    print("Начинаем анализ CVE уязвимостей...")
    print(f"Исходный файл: {file_path}")
    print(f"API ключ: {NVD_API_KEY}")
    print("=" * 60)
    
    results, stats = process_cve_list(file_path)
    
    if results.empty:
        print("Не удалось получить результаты анализа")
        return
    
    # Выводим итоговую статистику
    print("\n" + "=" * 60)
    print("ИТОГОВАЯ СТАТИСТИКА АНАЛИЗА")
    print("=" * 60)
    print(f"Всего обработано CVE: {len(results)}")
    print(f"Критические (9.0-10.0): {stats['critical']}")
    print(f"Высокие (7.0-8.9): {stats['high']}")
    print(f"Средние (4.0-6.9): {stats['medium']}")
    print(f"Низкие (0.1-3.9): {stats['low']}")
    print(f"Ошибки/не найдено: {stats['errors'] + stats['not_found']}")
    
    # Показываем топ-5 самых критичных уязвимостей (исправленная версия)
    try:
        # Создаем копию DataFrame и преобразуем столбец с оценками в числовой тип
        numeric_scores_df = results.copy()
        numeric_scores_df.loc[:, 'Оценка уязвимости CVSSv3'] = pd.to_numeric(
            numeric_scores_df['Оценка уязвимости CVSSv3'], errors='coerce'
        )
        
        # Удаляем строки с NaN значениями
        numeric_scores_df = numeric_scores_df.dropna(subset=['Оценка уязвимости CVSSv3'])
        
        if not numeric_scores_df.empty:
            # Сортируем по убыванию оценки и берем топ-5
            top_critical = numeric_scores_df.nlargest(5, 'Оценка уязвимости CVSSv3')
            print("\nТОП-5 САМЫХ КРИТИЧНЫХ УЯЗВИМОСТЕЙ:")
            for _, row in top_critical.iterrows():
                print(f"  {row['CVE-идентификатор']}: {row['Оценка уязвимости CVSSv3']} ({row['Оценка критичности согласно CVSSv3']})")
    except Exception as e:
        print(f"Ошибка при формировании топа уязвимостей: {e}")
    
    # Показываем несколько примеров с ошибками
    error_samples = results[results['Оценка уязвимости CVSSv3'].apply(
        lambda x: isinstance(x, str) and ('Error' in x or 'Not Found' in x or x == 'N/A')
    )].head(3)
    
    if not error_samples.empty:
        print("\nПРИМЕРЫ ОШИБОК:")
        for _, row in error_samples.iterrows():
            print(f"  {row['CVE-идентификатор']}: {row['Оценка уязвимости CVSSv3']}")
    
    print("\nАнализ завершен!")

if __name__ == "__main__":
    main()