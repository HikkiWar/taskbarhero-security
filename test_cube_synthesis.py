#!/usr/bin/env python3
"""
F-10: Cube Synthesis — Проверка отрицательной цены
Аналогично F-01, но для синтеза кубов
"""

import struct
import ctypes
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

def main():
    print("=" * 70)
    print("F-10: CUBE SYNTHESIS — Проверка отрицательной цены")
    print("=" * 70)
    print()

    print("[ГИПОТЕЗА]")
    print("Синтез кубов может быть уязвим как F-01:")
    print("  • Стоимость хранится как int32 без защиты")
    print("  • Отрицательная цена = прибыль ресурсов вместо траты")
    print()

    print("[ШАГИ ТЕСТИРОВАНИЯ]")
    print()
    print("1️⃣ Найти CubeRecipeSaveData в памяти:")
    print("   • Запустить TaskBarHero с доступом к синтезу")
    print("   • Открыть Cheat Engine")
    print("   • Найти известный ID рецепта (напр. 1001)")
    print("   • Scan for int32 > 1001")
    print("   • Соседние значения - это структура рецепта:")
    print("     +0x00: ID рецепта")
    print("     +0x04: уровень синтеза (или стоимость_1)")
    print("     +0x08: стоимость (обычно 100-10000)")
    print()

    print("2️⃣ Найти поле СТОИМОСТИ:")
    print("   Должно быть положительное число")
    print("   Примеры: 500, 1000, 2000 для разных рецептов")
    print()

    print("3️⃣ Модифицировать цену:")
    print()

    try:
        pid_input = input("   Введите PID процесса TaskBarHero: ").strip()
        if not pid_input.isdigit():
            print("[-] PID должен быть числом")
            return

        pid = int(pid_input)

        addr_input = input("   Введите адрес поля СТОИМОСТИ (hex, напр 0x7FFB38A60000): ").strip()
        if not addr_input.startswith('0x'):
            print("[-] Адрес должен начинаться с 0x")
            return

        address = int(addr_input, 16)

        print()
        print("[*] Текущее значение:")
        current = read_int32_at_address(pid, address)
        if current is not None:
            print(f"   Стоимость = {current}")
        else:
            print("   [-] Не удалось прочитать")
            return

        print()
        print("[*] МОДИФИКАЦИЯ 1: Отрицательная цена")
        print(f"   {current} → {-current}")

        modify_int32_at_address(pid, address, -current)

        print()
        print("[+] Модификация завершена!")
        print()

        print("[TEST PROTOCOL]")
        print("=" * 70)
        print()
        print("4️⃣ В ИГРЕ:")
        print("   • Откройте окно синтеза куба")
        print("   • Выберите рецепт с модифицированной ценой")
        print("   • Попытайтесь синтезировать")
        print()
        print("   ✅ УЯЗВИМО, если:")
        print("      - Синтез прошёл")
        print("      - Ресурсы ДОБАВИЛИСЬ вместо траты")
        print("      - Баланс увеличился на |цена|")
        print()
        print("   ❌ ЗАЩИТА, если:")
        print("      - Ошибка 'недостаточно материалов'")
        print("      - Синтез заблокирован")
        print()

        print("5️⃣ ПРОВЕРКА СОХРАНЕНИЯ (КРИТИЧНО):")
        print("   • Если синтез прошёл:")
        print("     a) Дождаться 3 минут (автосейв)")
        print("     b) Полностью закрыть игру")
        print("     c) Расшифровать сейв (используя core.py)")
        print("     d) Проверить поле ресурсов:")
        print("        - Если ресурсы остались ↑ → F-10 = HIGH (УЯЗВИМО)")
        print("        - Если откатились ↓ → ЗАЩИТА (перепроверить)")
        print()

        print("6️⃣ РАСШИРЕННЫЙ ТЕСТ (если базовый не сработал):")
        print()
        print("   ВАРИАНТ 2 — Нулевой уровень синтеза:")
        print("      • Найти поле уровня (соседнее с ценой)")
        print("      • Текущее: требуется уровень 5")
        print("      • Изменить: 5 → 0")
        print("      • Попытаться синтезировать закрытый рецепт")
        print()
        print("   ВАРИАНТ 3 — Чужой материал:")
        print("      • Найти ID требуемого материала")
        print("      • Изменить на ID несуществующего предмета (999999)")
        print("      • Попытаться синтезировать")
        print("      • Если прошёл → УЯЗВИМО")
        print()

        print("=" * 70)
        print()
        print("[ОЖИДАЕМЫЙ РЕЗУЛЬТАТ]")
        print("  ✅ УЯЗВИМО (F-10 = HIGH):   Отрицательная цена добавляет ресурсы")
        print("  ❌ ЗАЩИЩЕНО (F-10 = safe): Синтез отклонён, ресурсы не изменились")

    except KeyboardInterrupt:
        print("\n[-] Отменено пользователем")
    except Exception as e:
        print(f"[-] Ошибка: {e}")

if __name__ == '__main__':
    main()
