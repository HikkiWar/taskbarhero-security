#!/usr/bin/env python3
"""
F-11: RARE BOX ROLLS — Подмена типа сундука
F-07 доказал, что сундуки хранятся в памяти с известными адресами
Тест: изменить тип сундука (910651=обычный -> 920651=редкий)
"""

import struct
import ctypes
import json
import time
from ctypes import windll

ReadProcessMemory = windll.kernel32.ReadProcessMemory
WriteProcessMemory = windll.kernel32.WriteProcessMemory

def modify_int32_at_address(pid, address, new_value):
    """
    Модифицирует int32 значение по адресу в памяти
    """
    try:
        h_process = windll.kernel32.OpenProcess(0x0010 | 0x0020, False, pid)

        new_bytes = struct.pack('<i', new_value)
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

def read_int32_at_address(pid, address):
    """
    Читает int32 значение по адресу
    """
    try:
        h_process = windll.kernel32.OpenProcess(0x0010, False, pid)

        buffer = ctypes.create_string_buffer(4)
        bytes_read = ctypes.c_ulong(0)

        result = ReadProcessMemory(h_process, address, buffer, 4,
                                  ctypes.byref(bytes_read))

        if result and bytes_read.value == 4:
            value = struct.unpack('<i', buffer.raw)[0]
            return value
        else:
            return None

    except Exception as e:
        print(f"[-] Ошибка: {e}")
        return None

def load_box_queue():
    """
    Загружает очередь сундуков из box_queue_prediction.json
    """
    try:
        with open('./test-results/box_queue_prediction.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data
    except FileNotFoundError:
        print("[-] Файл box_queue_prediction.json не найден")
        return None
    except json.JSONDecodeError:
        print("[-] Ошибка парсинга JSON")
        return None

def main():
    print("=" * 70)
    print("F-11: RARE BOX ROLLS — Подмена типа сундука")
    print("=" * 70)
    print()

    print("[КОНТЕКСТ ИЗ F-07]")
    print("  • Содержимое сундуков известно заранее и хранится в памяти")
    print("  • Структура BoxData хорошо известна (раскладка из F-07)")
    print("  • Адреса плывут из-за ASLR, но можно пересканировать")
    print()

    print("[ГИПОТЕЗА]")
    print("  • Если изменить тип сундука в памяти (910651 → 920651)")
    print("  • Может ли сервер принять изменённый тип и выдать редкую награду?")
    print()

    print("[СТРУКТУРА BoxData ИЗ F-07]")
    print("  +0x10  ItemId (защ.)           — ID сундука (напр. 12030)")
    print("  +0x20  UniqueKey (защ.)        — ТУРА РАРНОСТИ (910651 обычный, 920651 редкий)")
    print("  +0x28  ClaimableAt (защ.)")
    print("  +0x30  RewardItemId (защ.)     — то, что выпадет")
    print("  +0x40  RewardItemUniqueID (защ.)")
    print("  +0x48  IsGet")
    print()

    # Загруз очередь если есть
    box_queue = load_box_queue()
    if box_queue:
        print("[KNOWN BOXES ИЗ box_queue_prediction.json]")
        print(f"  Снято: {box_queue['снято']}")
        print(f"  Неоткрытые: {box_queue['неоткрытые_у_игрока']}")
        print(f"  Уже открытые: {box_queue['уже_открытые'][:3]}...")
        print()

    print("[ШАГИ ТЕСТИРОВАНИЯ]")
    print()
    print("1️⃣ Найти адреса BoxData в памяти:")
    print("   • Запустить TaskBarHero")
    print("   • Открыть Cheat Engine")
    print("   • Скан по ID из box_queue_prediction.json (напр. 12030)")
    print("   • Scan for int32 > 12030")
    print("   • Найти соответствующий адрес")
    print()

    print("2️⃣ Пересчитать адреса на новый ASLR (если нужно):")
    print("   • Из equip_chain.md известна база GameAssembly.dll")
    print("   • Адреса = база + смещение")
    print()

    print("3️⃣ МОДИФИКАЦИЯ:")
    print()

    try:
        pid_input = input("   Введите PID процесса TaskBarHero: ").strip()
        if not pid_input.isdigit():
            print("[-] PID должен быть числом")
            return

        pid = int(pid_input)

        # Адрес типа сундука (обычно +0x20 от начала BoxData)
        addr_type_input = input("   Введите адрес поля TYPE сундука (hex): ").strip()
        if not addr_type_input.startswith('0x'):
            print("[-] Адрес должен начинаться с 0x")
            return

        addr_type = int(addr_type_input, 16)

        # Адрес награды (обычно +0x30)
        addr_reward_input = input("   Введите адрес поля REWARD_ITEM_ID (hex): ").strip()
        if not addr_reward_input.startswith('0x'):
            print("[-] Адрес должен начинаться с 0x")
            return

        addr_reward = int(addr_reward_input, 16)

        print()
        print("[*] Текущие значения:")
        box_type = read_int32_at_address(pid, addr_type)
        reward_id = read_int32_at_address(pid, addr_reward)

        print(f"   Тип сундука: {box_type} (910651=обычный, 920651=редкий)")
        print(f"   Награда: {reward_id}")

        if box_type != 910651:
            print("[-] Это не обычный сундук. Попробуйте другой адрес.")
            return

        print()
        print("[*] МОДИФИКАЦИЯ 1: Изменяем ТИП сундука")
        print(f"   {box_type} (обычный) → 920651 (редкий)")

        modify_int32_at_address(pid, addr_type, 920651)

        print()
        print("[*] МОДИФИКАЦИЯ 2: Меняем НАГРАДУ на редкий предмет (опционально)")
        print(f"   Текущая награда: {reward_id}")

        change_reward = input("   Изменить награду? (y/n): ").strip().lower()
        if change_reward == 'y':
            new_reward = input("   Введите ID редкого предмета (напр. 520014): ").strip()
            if new_reward.isdigit():
                modify_int32_at_address(pid, addr_reward, int(new_reward))

        print()
        print("[+] Модификация завершена!")
        print()

        print("[TEST PROTOCOL]")
        print("=" * 70)
        print()
        print("4️⃣ В ИГРЕ:")
        print("   • Откройте инвентарь сундуков")
        print("   • Найдите модифицированный сундук (ID из адреса)")
        print("   • Нажмите ОТКРЫТЬ")
        print()
        print("   ✅ УЯЗВИМО, если:")
        print("      - Выпал РЕДКИЙ предмет (вместо обычного)")
        print("      - Награда == новый ID редкого предмета")
        print("      - Сундук не был переоткрыт, выпал правильный редкий")
        print()
        print("   ❌ ЗАЩИТА, если:")
        print("      - Выпал ОБЫЧНЫЙ предмет (оригинальная награда)")
        print("      - Сервер игнорирует локальные изменения типа")
        print()

        print("5️⃣ ПРОВЕРКА СОХРАНЕНИЯ (КРИТИЧНО):")
        print("   • Если выпал редкий предмет:")
        print("     a) Дождаться 3 минут (автосейв)")
        print("     b) Полностью закрыть игру")
        print("     c) Перезагрузить")
        print("     d) Проверить инвентарь:")
        print("        - Если редкий предмет остался ↑ → F-11 = HIGH (УЯЗВИМО)")
        print("        - Если предмет заменился на обычный ↓ → ЗАЩИТА")
        print()

        print("6️⃣ РАСШИРЕННЫЙ ТЕСТ (если базовый не сработал):")
        print()
        print("   ВАРИАНТ 2 — Копирование всей структуры:")
        print("      • Найти РЕДКИЙ сундук в памяти (тип 920651)")
        print("      • Скопировать 48 байт этого сундука")
        print("      • Вставить в место ОБЫЧНОГО сундука")
        print("      • Открыть → проверить награду")
        print()

        print("=" * 70)
        print()
        print("[ОЖИДАЕМЫЙ РЕЗУЛЬТАТ]")
        print("  ✅ УЯЗВИМО (F-11 = HIGH):   Редкий сундук выпал, сохранился на сервере")
        print("  ❌ ЗАЩИЩЕНО (F-11 = safe): Выпал оригинальный обычный предмет")

    except KeyboardInterrupt:
        print("\n[-] Отменено пользователем")
    except Exception as e:
        print(f"[-] Ошибка: {e}")

if __name__ == '__main__':
    main()
