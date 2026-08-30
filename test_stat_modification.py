#!/usr/bin/env python3
"""
F-02/F-04: Character Stat Modification — Подтверждённая уязвимость (CONFIRMED HIGH)
attributeSaveDatas и боевые статы принимаются от клиента без серверной проверки
"""

import struct
import ctypes
from ctypes import windll

k32 = windll.kernel32

PROCESS_VM_READ  = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OP    = 0x0008

# Известные атрибуты из FINDINGS.md (F-02)
KNOWN_ATTRS = {
    101001: "Атака",
    101002: "HP (макс.)",
    101003: "Закрытый узел #3",
    101004: "Скорость",
    101005: "Крит. шанс",
}

# Смещения боевых статов (F-04): float массив, шаг 0x10 от якоря (МАКС. HP)
COMBAT_STAT_OFFSETS = {
    -0x40: "Урон (base)",
    -0x30: "Скорость атаки",
    -0x20: "Шанс крита",
    -0x10: "Крит. урон",
    0x000: "МАКС. HP (якорь)",
    0x010: "Сила защиты",
    0x2A0: "Усиление опыта (множитель)",
    0x2B0: "Доп. опыт (flat)",
    0x350: "HP за убийство",
}


def open_proc(pid, access):
    h = k32.OpenProcess(access, False, pid)
    if not h:
        raise RuntimeError(f"OpenProcess failed: {k32.GetLastError()}")
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
    return bool(k32.WriteProcessMemory(h, addr, data, 4, ctypes.byref(n)))


def mem_read_f32(h, addr):
    buf = ctypes.create_string_buffer(4)
    n   = ctypes.c_ulong(0)
    if not k32.ReadProcessMemory(h, addr, buf, 4, ctypes.byref(n)) or n.value != 4:
        return None
    return struct.unpack('<f', buf.raw)[0]


def mem_write_f32(h, addr, value):
    data = struct.pack('<f', value)
    n    = ctypes.c_ulong(0)
    return bool(k32.WriteProcessMemory(h, addr, data, 4, ctypes.byref(n)))


def main():
    print("=" * 70)
    print("F-02/F-04: CHARACTER STAT MODIFICATION  [CONFIRMED — HIGH]")
    print("=" * 70)
    print()
    print("[СТАТУС НАХОДКИ]")
    print("  ✅ ПОДТВЕРЖДЕНО на живом аккаунте (FINDINGS.md → F-02, F-04)")
    print()
    print("[F-02 — Характеристики (attributeSaveDatas)]")
    print("  132 атрибута, хранилище БЕЗ защиты Obscured")
    print("  Запись напрямую → сохраняется после рестарта")
    print()
    print("  Проверено ранее:")
    print("    attr 101002 (HP)  : 8  → 58  — сохранилось")
    print("    attr 101001 (атака): 3  → 6   — сохранилось")
    print("    attr 101003 (закрытый узел): 0 → 1 — разблокировалось")
    print()
    print("[F-04 — Боевые статы (float массив)]")
    print("  Не хранятся в сейве — пересчитываются при загрузке.")
    print("  Изменение в памяти действует до рестарта.")
    print("  Но XP, набранный с модифицированным множителем,")
    print("  начисляется кодом игры и СОХРАНЯЕТСЯ.")
    print()
    print("[ШАГИ ТЕСТИРОВАНИЯ]")
    print()
    print("═══ ЧАСТЬ 1: attributeSaveDatas (постоянные) ═══")
    print()
    print("1️⃣  Найти attributeSaveDatas в памяти (Cheat Engine):")
    print("    • Scan for int32 = текущий уровень атрибута (напр. 8 для HP)")
    print("    • После изменения в игре → 'Changed value'")
    print("    • Искать рядом массив: RuneKey=101002, Level=8 рядом")
    print("    • Или: сканировать последовательность 101001 | value | 101002 | value")
    print()

    print("2️⃣  Введите адрес и атрибут для модификации:")
    print()

    try:
        pid_in = input("  PID процесса TaskBarHero: ").strip()
        if not pid_in.isdigit():
            print("[-] PID — целое число")
            return
        pid = int(pid_in)

        h = open_proc(pid, PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OP)

        print()
        print("  Режим тестирования:")
        print("  [1] F-02 — Запись уровня атрибута (attributeSaveDatas)")
        print("  [2] F-04 — Запись боевого стата (float, временно)")
        print("  [3] F-04 — Запись множителя опыта (float, сохранится через XP)")
        print()

        mode = input("  Режим (1-3): ").strip()

        if mode == "1":
            print()
            print("  Известные атрибуты:")
            for key, name in KNOWN_ATTRS.items():
                print(f"    {key}: {name}")
            print()
            addr_in = input("  Адрес ПОЛЯ УРОВНЯ атрибута (0x...): ").strip()
            if not addr_in.lower().startswith("0x"):
                addr_in = "0x" + addr_in
            addr = int(addr_in, 16)

            cur = mem_read_i32(h, addr)
            print(f"  [*] Текущее значение: {cur}")

            new_in = input(f"  Новое значение (Enter = {(cur or 0) + 50}): ").strip()
            new_val = int(new_in) if new_in else (cur or 0) + 50

            ok = mem_write_i32(h, addr, new_val)
            print()
            if ok:
                print(f"  [+] Записано: {cur} → {new_val}")
            else:
                print("  [-] Ошибка записи")
                return

            print()
            print("[TEST PROTOCOL — F-02]")
            print("=" * 70)
            print()
            print("3️⃣  В ИГРЕ:")
            print("    • Откройте экран персонажа")
            print("    • Найдите изменённый атрибут")
            print()
            print("    ✅ УЯЗВИМО (F-02 = HIGH), если значение отобразилось:")
            print(f"       {cur} → {new_val}")
            print()
            print("4️⃣  ПРОВЕРКА СОХРАНЕНИЯ (критично):")
            print("    a) Подождать 3 мин (автосейв)")
            print("    b) Полностью закрыть игру")
            print("    c) Снова открыть — атрибут должен остаться")
            print("    d) Либо расшифровать сейв через core.py")
            print("       и проверить поле attributeSaveDatas[RuneKey=101002].level")

        elif mode == "2":
            print()
            print("  Боевые статы — float массив, якорь = адрес МАКС. HP:")
            print()
            for off, name in sorted(COMBAT_STAT_OFFSETS.items()):
                sign = "+" if off >= 0 else ""
                print(f"    якорь {sign}{off:#05x}: {name}")
            print()
            anchor_in = input("  Адрес якоря (МАКС. HP, 0x...): ").strip()
            if not anchor_in.lower().startswith("0x"):
                anchor_in = "0x" + anchor_in
            anchor = int(anchor_in, 16)

            print()
            print("  [*] Текущие значения:")
            for off, name in sorted(COMBAT_STAT_OFFSETS.items()):
                val = mem_read_f32(h, anchor + off)
                print(f"      {name:30s}: {val}")

            print()
            off_in = input("  Смещение для изменения (десятичное, напр. 0): ").strip()
            offset = int(off_in, 16) if off_in.startswith("0x") else int(off_in)

            cur_f = mem_read_f32(h, anchor + offset)
            new_in = input(f"  Новое значение float (текущее: {cur_f}): ").strip()
            new_f = float(new_in)

            ok = mem_write_f32(h, anchor + offset, new_f)
            print()
            if ok:
                stat_name = COMBAT_STAT_OFFSETS.get(offset, f"offset {offset:#x}")
                print(f"  [+] {stat_name}: {cur_f} → {new_f}")
            else:
                print("  [-] Ошибка записи")
                return

            print()
            print("[TEST PROTOCOL — F-04]")
            print("=" * 70)
            print("  Изменение временно (сейв не содержит эти поля).")
            print("  Рестарт сбросит к базовым значениям.")
            print("  НО: урон / опыт, набранный за сессию, сохраняется.")

        elif mode == "3":
            print()
            print("  Множитель опыта (F-04 / +0x2A0 от якоря МАКС. HP)")
            print()
            anchor_in = input("  Адрес якоря (МАКС. HP, 0x...): ").strip()
            if not anchor_in.lower().startswith("0x"):
                anchor_in = "0x" + anchor_in
            anchor = int(anchor_in, 16)

            xp_addr = anchor + 0x2A0
            cur_xp = mem_read_f32(h, xp_addr)
            print(f"  Текущий множитель опыта: {cur_xp}")

            mul_in = input("  Новый множитель (напр. 10.0): ").strip()
            new_mul = float(mul_in)

            ok = mem_write_f32(h, xp_addr, new_mul)
            print()
            if ok:
                print(f"  [+] Множитель опыта: {cur_xp} → {new_mul}")
            else:
                print("  [-] Ошибка записи")
                return

            print()
            print("[TEST PROTOCOL — F-04 (XP multiplier)]")
            print("=" * 70)
            print()
            print("  ✅ Механизм: прямая запись HeroExp откатывается,")
            print("     но XP через умноженный множитель начисляет САМА ИГРА")
            print("     и этот XP сохраняется.")
            print()
            print("  3️⃣  Убейте нескольких мобов → проверьте прирост опыта")
            print("     (должен быть в {new_mul}× раз больше обычного)")
            print("  4️⃣  Подождите автосейв (3 мин)")
            print("  5️⃣  Расшифруйте сейв → проверьте heroExp")

        else:
            print("[-] Некорректный режим")
            return

        print()
        print("=" * 70)
        print("[РЕЗУЛЬТАТЫ ПРЕДЫДУЩЕГО ИСПЫТАНИЯ (FINDINGS.md)]")
        print("  Опыт героя 101: 1 164 600 → 2 142 469 (+978 000) — через множитель")
        print("  Опыт героя 401: 581 846   → 1 567 669 (+986 000) — через множитель")
        print("  Герой 201: LV21 → LV22 (целый уровень)")
        print("  maxCompletedStage: 1 207 → 1 306 (+99 стадий)")
        print("  Золото: 124 722 → 693 486 (+568 000)")
        print()
        print("  Ни одно значение не писалось напрямую — всё начислила игра.")

    except KeyboardInterrupt:
        print("\n[-] Отменено")
    except Exception as e:
        print(f"[-] Ошибка: {e}")


if __name__ == '__main__':
    main()
