#!/usr/bin/env python3
"""
F-01: Negative Rune Balance — Подтверждённая уязвимость (CONFIRMED HIGH)
Таблица стоимости рун не защищена: отрицательная цена = прирост золота
"""

import struct
import ctypes
from ctypes import windll

k32 = windll.kernel32

PROCESS_VM_READ  = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OP    = 0x0008

# Параметры таблицы рун из FINDINGS.md (F-01)
# 672 строки, шаг 0x50, формат: RuneKey | Level | currencyKey | cost
RUNE_TABLE_ROW_STEP  = 0x50
RUNE_TABLE_ROW_COUNT = 672

# Смещения внутри строки таблицы (относительно начала строки)
OFFSET_RUNE_KEY      = 0x00  # int32
OFFSET_RUNE_LEVEL    = 0x04  # int32
OFFSET_CURRENCY_KEY  = 0x08  # int32
OFFSET_COST          = 0x0C  # int32  ← цена улучшения


def open_proc(pid, access):
    h = k32.OpenProcess(access, False, pid)
    if not h:
        raise RuntimeError(f"OpenProcess failed: error {k32.GetLastError()}")
    return h


def mem_read_i32(h, addr):
    buf = ctypes.create_string_buffer(4)
    n   = ctypes.c_ulong(0)
    if not k32.ReadProcessMemory(h, addr, buf, 4, ctypes.byref(n)) or n.value != 4:
        return None
    return struct.unpack('<i', buf.raw)[0]


def mem_write_i32(h, addr, value):
    data = struct.pack('<i', value)
    n    = ctypes.c_ulong(0)
    ok   = k32.WriteProcessMemory(h, addr, data, 4, ctypes.byref(n))
    return bool(ok) and n.value == 4


def scan_rune_table(h, table_base):
    """
    Читает до RUNE_TABLE_ROW_COUNT строк из таблицы и возвращает список:
      (row_index, rune_key, level, currency_key, cost, cost_addr)
    """
    rows = []
    for i in range(RUNE_TABLE_ROW_COUNT):
        base = table_base + i * RUNE_TABLE_ROW_STEP
        rk   = mem_read_i32(h, base + OFFSET_RUNE_KEY)
        lv   = mem_read_i32(h, base + OFFSET_RUNE_LEVEL)
        ck   = mem_read_i32(h, base + OFFSET_CURRENCY_KEY)
        cost = mem_read_i32(h, base + OFFSET_COST)
        if None in (rk, lv, ck, cost):
            break
        rows.append((i, rk, lv, ck, cost, base + OFFSET_COST))
    return rows


def main():
    print("=" * 70)
    print("F-01: NEGATIVE RUNE BALANCE  [CONFIRMED — HIGH]")
    print("=" * 70)
    print()
    print("[СТАТУС НАХОДКИ]")
    print("  ✅ ПОДТВЕРЖДЕНО на живом аккаунте")
    print("  Источник: FINDINGS.md → F-01")
    print()
    print("[МЕХАНИЗМ]")
    print("  Таблица цен рун: 672 строки, шаг 0x50")
    print("  Формат строки: RuneKey | Level | currencyKey | cost (int32)")
    print("  Поле cost НЕ защищено (обычная r/w память)")
    print()
    print("  Отрицательная цена → транзакция переворачивается:")
    print("  улучшение руны НАЧИСЛЯЕТ золото вместо траты.")
    print()
    print("  Золото приходит через штатный код покупки игры,")
    print("  попадает в защищённое хранилище и переживает рестарт.")
    print("  Прямая запись баланса отбивается — этот путь нет.")
    print()
    print("[ШАГИ ВОСПРОИЗВЕДЕНИЯ]")
    print()
    print("1️⃣  Найти таблицу рун в памяти (Cheat Engine):")
    print("    • Сканировать int32 = известный RuneKey (напр. 110011)")
    print("    • Применить фильтр: соседние значения должны быть Level (3-10)")
    print("    • Проверить шаг: следующая строка через +0x50")
    print()
    print("2️⃣  Запустить этот скрипт с адресом НАЧАЛА таблицы рун")
    print()

    try:
        pid_in = input("  PID процесса TaskBarHero: ").strip()
        if not pid_in.isdigit():
            print("[-] PID — целое число")
            return
        pid = int(pid_in)

        addr_in = input("  Адрес начала таблицы рун (0x...): ").strip()
        if not addr_in.lower().startswith("0x"):
            addr_in = "0x" + addr_in
        table_base = int(addr_in, 16)

        h = open_proc(pid, PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OP)

        print()
        print("[*] Читаю таблицу рун...")
        rows = scan_rune_table(h, table_base)

        if not rows:
            print("[-] Таблица не прочитана. Проверьте адрес.")
            return

        print(f"[+] Прочитано строк: {len(rows)}")
        print()
        print("  Первые 10 строк таблицы:")
        print(f"  {'#':>3}  {'RuneKey':>8}  {'Lv':>4}  {'CurKey':>8}  {'Cost':>8}  {'CostAddr':>18}")
        print("  " + "-"*65)
        for idx, rk, lv, ck, cost, caddr in rows[:10]:
            print(f"  {idx:>3}  {rk:>8}  {lv:>4}  {ck:>8}  {cost:>8}  {caddr:#018x}")

        print()
        rune_in = input("  Номер строки для инверсии цены (или Enter для первой положительной): ").strip()

        target_row = None
        if rune_in == "":
            for r in rows:
                if r[4] > 0:
                    target_row = r
                    break
        elif rune_in.isdigit():
            idx = int(rune_in)
            for r in rows:
                if r[0] == idx:
                    target_row = r
                    break

        if target_row is None:
            print("[-] Строка не найдена")
            return

        i, rk, lv, ck, cost, caddr = target_row
        print()
        print(f"[*] Цель: строка {i} | RuneKey={rk} | Level={lv} | Cost={cost}")
        print(f"    Адрес cost: {caddr:#x}")
        print(f"    Изменение: {cost} → {-cost}")
        print()

        ok = mem_write_i32(h, caddr, -cost)
        if ok:
            print(f"[+] Записано: cost = {-cost}")
        else:
            print("[-] Ошибка записи")
            return

        print()
        print("[TEST PROTOCOL]")
        print("=" * 70)
        print()
        print("3️⃣  В ИГРЕ:")
        print("    • Откройте экран рун")
        print(f"    • Найдите руну с ключом {rk} на уровне {lv}")
        print("    • Нажмите «Улучшить»")
        print()
        print("    ✅ УЯЗВИМО (F-01 = HIGH), если:")
        print("       - Улучшение прошло")
        print(f"       - Золото ВЫРОСЛО на ~{abs(cost)}")
        print()
        print("    ❌ ЗАЩИТА, если:")
        print("       - «Недостаточно золота» (цена видна как отрицательная UInt)")
        print("       - Улучшение заблокировано")
        print()
        print("4️⃣  ПРОВЕРКА СОХРАНЕНИЯ (после успешного улучшения):")
        print("    a) Подождать 3 мин (автосейв)")
        print("    b) Закрыть игру полностью")
        print("    c) Расшифровать сейв через core.py")
        print("    d) Найти поле gold — должно содержать прирост")
        print()
        print("5️⃣  МАСШТАБИРОВАНИЕ (если базовый тест прошёл):")
        print("    • Инвертировать ВСЕ строки с положительной ценой:")
        print("      cost_addr += 0x50 * N для каждой строки N")
        print("    • Каждое улучшение приносит золото")
        print("    • 146 рун на нуле: разблокировка = Level 0→1 = одна запись")
        print()
        print("=" * 70)
        print()
        print("[РЕЗУЛЬТАТ ПРЕДЫДУЩЕГО ИСПЫТАНИЯ (FINDINGS.md)]")
        print("  Было проверено на живом аккаунте, ~40 минут:")
        print("  Золото: 124 722 → 693 486 (+568 000)")
        print("  Всё заработала сама игра через штатный код покупки.")

    except KeyboardInterrupt:
        print("\n[-] Отменено")
    except Exception as e:
        print(f"[-] Ошибка: {e}")


if __name__ == '__main__':
    main()
