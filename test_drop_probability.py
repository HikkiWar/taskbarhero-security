#!/usr/bin/env python3
"""
F-12: Drop Probability Scan & Modify
Ищет таблицу весов дропа в памяти игры
"""

import struct
import ctypes
import time
from ctypes import windll, c_int, c_float, POINTER, pointer

# Windows API для доступа к памяти процесса
ReadProcessMemory = windll.kernel32.ReadProcessMemory
WriteProcessMemory = windll.kernel32.WriteProcessMemory
GetCurrentProcess = windll.kernel32.GetCurrentProcess

def scan_memory_for_floats(pid, target_values):
    """
    Сканирует память процесса на наличие последовательности float значений
    target_values: список float значений для поиска (напр. [0.7, 0.25, 0.05])
    """
    print(f"[*] Сканирование памяти процесса {pid}...")
    print(f"[*] Ищу последовательность: {target_values}")

    matches = []

    try:
        h_process = windll.kernel32.OpenProcess(0x0010 | 0x0020, False, pid)  # PROCESS_VM_READ | PROCESS_VM_WRITE
        if not h_process:
            print("[-] Не удалось открыть процесс. Проверьте PID.")
            return matches

        # Примерный диапазон поиска (может быть большим)
        # Обычно игровые данные в куче
        scan_start = 0x0000000000400000  # Начало для x64
        scan_end = 0x00007FFFFFFFFFFF    # Конец пользовательского пространства

        print("[*] Это может занять несколько минут...")

        # Конвертируем float в bytes для поиска
        target_bytes = b''.join(struct.pack('<f', v) for v in target_values)
        print(f"[*] Ищу байты: {target_bytes.hex()}")

        # Примечание: реальный скан требует перебора памяти блоками
        # Это упрощённая версия для концепции

        print("[!] Для полного скана нужен Cheat Engine или специальный сканер")
        print("[*] Альтернатива: Cheat Engine > Scan for Float > 0.7 > 0.25 > 0.05")

        return matches

    except Exception as e:
        print(f"[-] Ошибка: {e}")
        return matches

def modify_weight_at_address(pid, address, new_value):
    """
    Модифицирует значение float по адресу в памяти процесса
    """
    try:
        h_process = windll.kernel32.OpenProcess(0x0010 | 0x0020, False, pid)

        new_bytes = struct.pack('<f', new_value)
        bytes_written = ctypes.c_ulong(0)

        result = WriteProcessMemory(h_process, address, new_bytes, len(new_bytes),
                                   ctypes.byref(bytes_written))

        if result:
            print(f"[+] Записано: {address:#x} = {new_value}")
            return True
        else:
            print(f"[-] Ошибка записи в {address:#x}")
            return False

    except Exception as e:
        print(f"[-] Ошибка: {e}")
        return False

def read_float_at_address(pid, address):
    """
    Читает float значение по адресу
    """
    try:
        h_process = windll.kernel32.OpenProcess(0x0010, False, pid)

        buffer = ctypes.create_string_buffer(4)
        bytes_read = ctypes.c_ulong(0)

        result = ReadProcessMemory(h_process, address, buffer, 4,
                                  ctypes.byref(bytes_read))

        if result and bytes_read.value == 4:
            value = struct.unpack('<f', buffer.raw)[0]
            return value
        else:
            return None

    except Exception as e:
        print(f"[-] Ошибка: {e}")
        return None

def main():
    print("=" * 70)
    print("F-12: DROP PROBABILITY — поиск и модификация таблицы весов")
    print("=" * 70)
    print()

    print("[ШАГИ ТЕСТИРОВАНИЯ]")
    print()
    print("1️⃣ Найти таблицу весов в памяти:")
    print("   • Запустить TaskBarHero")
    print("   • Открыть Cheat Engine")
    print("   • Scan for Float > 0.7 (вес обычных)")
    print("   • Refine > 0.25 (вес редких)")
    print("   • Refine > 0.05 (вес эпических)")
    print("   • Должно остаться 1-3 адреса")
    print()

    print("2️⃣ Получить адрес таблицы:")
    print("   Результат: [АДРЕС] (напр. 0x7FFB38A60000 + смещение)")
    print()

    print("3️⃣ Вставить адрес здесь и запустить модификацию:")
    print()

    # Интерактивная часть
    try:
        pid_input = input("   Введите PID процесса TaskBarHero (например 12345): ").strip()
        if not pid_input.isdigit():
            print("[-] PID должен быть числом")
            return

        pid = int(pid_input)

        addr_input = input("   Введите адрес таблицы весов (hex, напр 0x7FFB38A60000): ").strip()
        if not addr_input.startswith('0x'):
            print("[-] Адрес должен начинаться с 0x")
            return

        address = int(addr_input, 16)

        print()
        print("[*] Текущие значения:")
        for i, offset in enumerate([0, 4, 8, 12]):  # Если это массив из 4 float
            val = read_float_at_address(pid, address + offset)
            if val is not None:
                print(f"   +{offset:#x}: {val:.4f}")

        print()
        print("[*] МОДИФИКАЦИЯ: Устанавливаем редкие на 100%, обычные на 0%")

        # Предполагаемая структура:
        # [0] = вес_обычных (0.7) -> 0.0
        # [4] = вес_редких (0.25) -> 1.0
        # [8] = вес_эпических (0.05) -> 0.0

        modify_weight_at_address(pid, address + 0, 0.0)   # обычные = 0
        time.sleep(0.1)
        modify_weight_at_address(pid, address + 4, 1.0)   # редкие = 100%
        time.sleep(0.1)
        modify_weight_at_address(pid, address + 8, 0.0)   # эпические = 0

        print()
        print("[+] Модификация завершена!")
        print()
        print("4️⃣ ТЕСТИРОВАНИЕ В ИГРЕ:")
        print("   • Откройте 10-20 сундуков подряд")
        print("   • Подсчитайте: сколько выпало РЕДКИХ?")
        print("   • Если > 50% редких → УЯЗВИМО (F-12 = HIGH)")
        print("   • Если все обычные → ЗАЩИТА работает (F-12 = protected)")
        print()
        print("5️⃣ ПРОВЕРКА СОХРАНЕНИЯ:")
        print("   • Дождаться 3 минут (автосейв)")
        print("   • Полностью закрыть игру")
        print("   • Перезагрузить")
        print("   • Если редкие остались → сохранилось на сервере")

    except KeyboardInterrupt:
        print("\n[-] Отменено пользователем")
    except Exception as e:
        print(f"[-] Ошибка: {e}")

if __name__ == '__main__':
    main()
