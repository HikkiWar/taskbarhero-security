"""
core.py — общее ядро: чтение сейва (ES3) и доступ к памяти процесса игры.

Ничего специфичного для GUI здесь нет, чтобы разработчик мог читать логику отдельно
от интерфейса.
"""
import ctypes, ctypes.wintypes as w, struct, subprocess, os, json, hashlib, time, math

# ─────────────────────────── ES3 ────────────────────────────────────────────
SAVE_PATH = os.path.expandvars(
    r"%LOCALAPPDATA%\..\LocalLow\TesseractStudio\TaskbarHero\SaveFile_Live.es3")
GAME_EXE  = r"D:\Games\steam\steamapps\common\TaskbarHero\TaskBarHero.exe"

# Восстановлен из памяти процесса. Идентичен между сессиями и установками.
ES3_PASSWORD = "emuMqG3bLYJ938ZDCfieWJ"


def es3_decrypt(blob: bytes) -> bytes:
    """salt = IV = первые 16 байт файла; key = PBKDF2-HMAC-SHA1(pwd, salt, 100, 16)."""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    salt = blob[:16]
    key = hashlib.pbkdf2_hmac("sha1", ES3_PASSWORD.encode(), salt, 100, dklen=16)
    return unpad(AES.new(key, AES.MODE_CBC, salt).decrypt(blob[16:]), 16)


def load_save(path=SAVE_PATH):
    """Вернуть (outer, inner). PlayerSaveData.value — сам по себе JSON-строка."""
    outer = json.loads(es3_decrypt(open(path, "rb").read()).decode("utf-8"))
    return outer, json.loads(outer["PlayerSaveData"]["value"])


def save_mtime(path=SAVE_PATH):
    return os.path.getmtime(path)


# ─────────────────────────── процесс ────────────────────────────────────────
k32 = ctypes.windll.kernel32
PROCESS_ALL = 0x1F0FFF


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", w.DWORD), ("__a", w.DWORD),
                ("RegionSize", ctypes.c_size_t), ("State", w.DWORD),
                ("Protect", w.DWORD), ("Type", w.DWORD), ("__b", w.DWORD)]


def game_pid(name="TaskBarHero.exe"):
    r = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {name}", "/FO", "CSV", "/NH"],
                       capture_output=True, text=True,
                       creationflags=subprocess.CREATE_NO_WINDOW)
    for line in r.stdout.strip().splitlines():
        if "TaskBarHero" in line:
            try:
                return int(line.split(",")[1].strip().strip('"'))
            except (IndexError, ValueError):
                pass
    return None


class Proc:
    """Тонкая обёртка над Read/WriteProcessMemory."""

    def __init__(self, pid):
        self.pid = pid
        self.h = k32.OpenProcess(PROCESS_ALL, False, pid)
        if not self.h:
            raise OSError(f"OpenProcess({pid}) failed: {ctypes.GetLastError()}")

    def close(self):
        if self.h:
            k32.CloseHandle(self.h)
            self.h = None

    def regions(self):
        """Закоммиченные приватные read/write регионы — там живёт управляемая куча."""
        addr, out = 0, []
        mbi = MEMORY_BASIC_INFORMATION()
        while addr < 0x7FFFFFFFFFFF:
            if not k32.VirtualQueryEx(self.h, ctypes.c_void_p(addr),
                                      ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            if mbi.State == 0x1000 and mbi.Type == 0x20000 and mbi.Protect in (0x04, 0x40):
                out.append((mbi.BaseAddress or 0, mbi.RegionSize))
            nxt = (mbi.BaseAddress or 0) + mbi.RegionSize
            if nxt <= addr:
                break
            addr = nxt
        return out

    def read(self, addr, size):
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(self.h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)):
            return buf.raw[:got.value]
        return b""

    def write_i32(self, addr, value):
        old = w.DWORD(0)
        got = ctypes.c_size_t(0)
        k32.VirtualProtectEx(self.h, ctypes.c_void_p(addr), 4, 0x40, ctypes.byref(old))
        ok = k32.WriteProcessMemory(self.h, ctypes.c_void_p(addr),
                                    struct.pack("<i", value), 4, ctypes.byref(got))
        k32.VirtualProtectEx(self.h, ctypes.c_void_p(addr), 4, old, ctypes.byref(old))
        return bool(ok)

    def read_i32(self, addr):
        d = self.read(addr, 4)
        return struct.unpack("<i", d)[0] if len(d) == 4 else None


# ────────────────── поиск объектов прогрессии (F-01 / F-02) ─────────────────
# IL2CPP object (x64):
#   +0x00 klass  +0x08 monitor  +0x10 Key/RuneKey (int32)  +0x14 Level (int32)
#
# Фильтр по заголовку отсекает статические таблицы игры от настоящих объектов.

def find_level_objects(proc: Proc, key: int, level_max=100000):
    """[(level_addr, current_level)] для объектов вида {Key, Level}."""
    needle = struct.pack("<i", key)
    hits = []
    for base, size in proc.regions():
        if size > 256 * 1024 * 1024:
            continue
        data = proc.read(base, size)
        if not data:
            continue
        off = data.find(needle)
        while off != -1:
            if off >= 0x10 and off + 8 <= len(data):
                klass = struct.unpack_from("<Q", data, off - 0x10)[0]
                monitor = struct.unpack_from("<Q", data, off - 0x08)[0]
                level = struct.unpack_from("<i", data, off + 4)[0]
                if klass > 0x10000000000 and monitor == 0 and 0 <= level <= level_max:
                    hits.append((base + off + 4, level))
            off = data.find(needle, off + 1)
    return hits


def scan_many(proc: Proc, keys, level_max=100000, progress=None):
    """Найти сразу несколько ключей за ОДИН проход по памяти.

    ReadProcessMemory — самая дорогая операция, поэтому регион читается один раз,
    а поиск всех иголок идёт уже по прочитанному буферу. Для N ключей это
    N поисков вместо N полных проходов по куче.

    Вернуть {key: [(level_addr, level), …]}.
    """
    keys = list(keys)
    needles = {struct.pack("<i", k): k for k in keys}
    out = {k: [] for k in keys}
    regions = proc.regions()
    for i, (base, size) in enumerate(regions):
        if progress and i % 40 == 0:
            progress(i, len(regions))
        if size > 256 * 1024 * 1024:
            continue
        data = proc.read(base, size)
        if not data:
            continue
        for needle, key in needles.items():
            off = data.find(needle)
            while off != -1:
                if off >= 0x10 and off + 8 <= len(data):
                    klass = struct.unpack_from("<Q", data, off - 0x10)[0]
                    monitor = struct.unpack_from("<Q", data, off - 0x08)[0]
                    level = struct.unpack_from("<i", data, off + 4)[0]
                    if klass > 0x10000000000 and monitor == 0 and 0 <= level <= level_max:
                        out[key].append((base + off + 4, level))
                off = data.find(needle, off + 1)
    if progress:
        progress(len(regions), len(regions))
    return out


def detect_klass(proc: Proc, keys, min_share=0.5):
    """Определить klass-указатель коллекции {Key, Level}.

    Образцом берутся САМЫЕ ДЛИННЫЕ ключи: короткие (1, 10, 24 …) как int32
    совпадают с мусором по всей памяти, и klass определяется неверно.
    Каждый кандидат проверяется: годным считается тот, по которому находится
    хотя бы половина ожидаемых ключей.
    """
    keys = list(keys)
    for sample in sorted(keys, reverse=True)[:4]:
        for level_addr, _ in find_level_objects(proc, sample, level_max=10 ** 9):
            raw = proc.read(level_addr - 0x14, 8)      # level_addr = obj + 0x14
            if len(raw) != 8:
                continue
            klass = struct.unpack("<Q", raw)[0]
            if klass < 0x10000000000:
                continue
            found = scan_by_klass(proc, klass, keys)
            if len(found) >= len(keys) * min_share:
                return klass, found
    return None, {}


def scan_by_klass(proc: Proc, klass: int, valid_keys, progress=None):
    """Найти ВСЕ объекты одного класса за один проход.

    Все AttributeSaveData делят один klass-указатель, все RuneSaveData — другой.
    Поэтому вместо N иголок по числу ключей ищется одна: сам klass. Для 329
    ключей это разница между пятью минутами и парой секунд.

    Вернуть {key: [(level_addr, level), …]} только для ключей из valid_keys.
    """
    valid = set(valid_keys)
    needle = struct.pack("<Q", klass)
    out = {}
    regions = proc.regions()
    for i, (base, size) in enumerate(regions):
        if progress and i % 40 == 0:
            progress(i, len(regions))
        if size > 256 * 1024 * 1024:
            continue
        data = proc.read(base, size)
        if not data:
            continue
        off = data.find(needle)
        while off != -1:
            if off + 0x18 <= len(data):
                monitor = struct.unpack_from("<Q", data, off + 0x08)[0]
                key, level = struct.unpack_from("<ii", data, off + 0x10)
                if monitor == 0 and key in valid:
                    out.setdefault(key, []).append((base + off + 0x14, level))
            off = data.find(needle, off + 1)
    if progress:
        progress(len(regions), len(regions))
    return out


def addr_still_valid(proc: Proc, level_addr: int, key: int) -> bool:
    """Проверить, что по адресу всё ещё лежит тот же объект.

    Поле Key находится на 4 байта раньше Level. После перезапуска игры
    адреса становятся мусором, и эта проверка это ловит.
    """
    return proc.read_i32(level_addr - 4) == key


def patch_level(proc: Proc, key: int, new_level: int, addrs=None):
    """Записать Level. Если переданы addrs — использовать их (без пересканирования).

    Вернуть (patched, total, before, addrs).
    """
    if addrs:
        addrs = [a for a in addrs if addr_still_valid(proc, a, key)]
    if not addrs:
        hits = find_level_objects(proc, key, level_max=10 ** 9)
        addrs = [a for a, _ in hits]
        before = hits[0][1] if hits else None
    else:
        before = proc.read_i32(addrs[0])
    done = sum(1 for a in addrs if proc.write_i32(a, new_level))
    return done, len(addrs), before, addrs


# ────────────────── таблица цен рун (F-04) ──────────────────────────────────
# Строка: <int RuneKey><int Level><int currencyKey=100001><int cost>, шаг 0x50

CURRENCY_KEY = 100001


def find_cost_rows(proc: Proc, rune_keys=None):
    """[(cost_addr, rune_key, level, cost)]

    rune_keys — реальный набор ключей рун из сейва. Раньше здесь стоял числовой
    диапазон 1000..99999999, из-за чего 88 рун с короткими ключами (1, 10, 11,
    20, 24 …) в выборку не попадали и их цены оставались нетронутыми.
    Набор из сейва и точнее, и заодно убирает ложные срабатывания.
    """
    if rune_keys is None:
        try:
            _, inner = load_save()
            rune_keys = {r["RuneKey"] for r in inner["RuneSaveData"]}
        except Exception:
            rune_keys = None
    valid = set(rune_keys) if rune_keys else None

    needle = struct.pack("<i", CURRENCY_KEY)
    rows = []
    for base, size in proc.regions():
        if size > 256 * 1024 * 1024:
            continue
        data = proc.read(base, size)
        if not data:
            continue
        off = data.find(needle)
        while off != -1:
            if off >= 8 and off + 8 <= len(data):
                rk, lv = struct.unpack_from("<ii", data, off - 8)
                cost = struct.unpack_from("<i", data, off + 4)[0]
                ok_key = (rk in valid) if valid else (1000 <= rk <= 99999999)
                if ok_key and 1 <= lv <= 10 and 0 < cost < 10 ** 9:
                    rows.append((base + off + 4, rk, lv, cost))
            off = data.find(needle, off + 1)
    return rows


# ────────────────── контрольная группа: защищённые значения ─────────────────
# Валюта: +0x00 Key(int64)=100001, +0x08 Quantity(int64)

def find_currency(proc: Proc):
    """[(qty_addr, quantity)] — для демонстрации того, что защита РАБОТАЕТ."""
    needle = struct.pack("<q", CURRENCY_KEY)
    hits = []
    for base, size in proc.regions():
        if size > 256 * 1024 * 1024:
            continue
        data = proc.read(base, size)
        if not data:
            continue
        off = data.find(needle)
        while off != -1:
            if off >= 0x10 and off + 16 <= len(data):
                klass = struct.unpack_from("<Q", data, off - 0x10)[0]
                monitor = struct.unpack_from("<Q", data, off - 0x08)[0]
                qty = struct.unpack_from("<q", data, off + 8)[0]
                if klass > 0x10000000000 and monitor == 0 and 0 < qty < 10 ** 12:
                    hits.append((base + off + 8, qty))
            off = data.find(needle, off + 1)
    return hits


# ────────────────── вычисленные боевые статы (сессионные) ──────────────────
# Массив float с шагом 0x10 относительно Макс. HP:
#   -0x40 урон  -0x30 скор.атаки  -0x20 крит.шанс  -0x10 крит.урон
#    0x00 МАКС. HP   +0x10 сила защиты
# В сейве этих значений НЕТ — они считаются из атрибутов и снаряжения,
# поэтому правка живёт до перезапуска.

STAT_OFFSETS = [("Урон от атаки", -0x40), ("Скорость атаки", -0x30),
                ("Шанс крита", -0x20), ("Крит. урон", -0x10),
                ("Макс. HP", 0x00), ("Сила защиты", 0x10)]

# Блок «Прочее» того же массива. Опознан пометкой слотов уникальными числами
# и сверкой с панелью в игре у нескольких героев.
MISC_OFFSETS = [("Усиление Опыт", 0x2A0),        # норма 1.0 -> в панели 100%
                ("Доп. опыт", 0x2B0),            # норма 0
                ("Длительность умений", 0x2E0),  # норма 1.0 + бонус
                ("HP за убийство", 0x350)]

ALL_OFFSETS = STAT_OFFSETS + MISC_OFFSETS

MAX_SANE_BLOCKS = 24    # предохранитель против сломанного фильтра


def _f32(blob, i):
    """float по смещению; None если не конечное число.

    ВАЖНО: NaN нельзя отсеивать сравнением — любое сравнение с NaN даёт False,
    поэтому фильтр вида `if abs(v-want) > tol: continue` пропускает NaN дальше.
    Нужен явный isfinite.
    """
    if i < 0 or i + 4 > len(blob):
        return None
    v = struct.unpack_from("<f", blob, i)[0]
    return v if math.isfinite(v) else None


def find_stat_blocks(proc: Proc, max_hp: float, damage=None, defense=None):
    """Найти блоки боевых статов по значениям из окна STATUS.

    max_hp обязателен (он якорь), damage и defense — необязательные уточнения.
    Чем больше известных чисел, тем однозначнее результат: для другого героя
    достаточно указать Макс. HP и Урон от атаки.

    Интерфейс игры ОКРУГЛЯЕТ значения (21.345 показывается как «21»),
    поэтому сравнение идёт с допуском, а не на равенство.
    """
    try:
        import numpy as np
    except ImportError:
        np = None

    out = []
    for base, size in proc.regions():
        if size > 256 * 1024 * 1024:
            continue
        data = proc.read(base, size)
        if not data or len(data) < 0x100:
            continue

        if np is not None:
            # векторная маска вместо цикла по каждым 4 байтам
            a = np.frombuffer(data[:len(data) // 4 * 4], dtype=np.float32)
            n = len(a)
            if n < 40:
                continue
            lo, hi = 16, n - 4
            hp = a[lo:hi]
            dmg = a[lo - 16:hi - 16]
            aspd = a[lo - 12:hi - 12]
            crit = a[lo - 8:hi - 8]
            cdmg = a[lo - 4:hi - 4]
            dfn = a[lo + 4:hi + 4]
            with np.errstate(invalid="ignore", over="ignore", under="ignore"):
                m = ((np.abs(hp - max_hp) <= 0.5)
                     & (aspd > 0.2) & (aspd < 20)
                     & (crit >= 0) & (crit < 1)
                     & (cdmg >= 1.0) & (cdmg < 50)
                     & (dfn > 0) & (dfn < 1e7)
                     & (dmg >= 0))
                if damage is not None:
                    m &= np.abs(dmg - damage) <= 0.6
                if defense is not None:
                    m &= np.abs(dfn - defense) <= 0.6
            out.extend(base + (lo + int(k)) * 4 for k in np.nonzero(m)[0])
            continue

        for i in range(0x40, len(data) - 0x20, 4):
            hp = _f32(data, i)
            if hp is None or abs(hp - max_hp) > 0.5:
                continue
            dmg = _f32(data, i - 0x40)
            aspd = _f32(data, i - 0x30)     # скорость атаки, обычно 0.5..5
            crit = _f32(data, i - 0x20)     # шанс крита, доля 0..1
            cdmg = _f32(data, i - 0x10)     # крит. урон, множитель >= 1
            dfn = _f32(data, i + 0x10)      # сила защиты
            # структурная проверка — соседи обязаны быть правдоподобными статами
            if not (aspd is not None and 0.2 < aspd < 20
                    and crit is not None and 0 <= crit < 1
                    and cdmg is not None and 1.0 <= cdmg < 50
                    and dfn is not None and 0 < dfn < 1e7
                    and dmg is not None and dmg >= 0):
                continue
            # уточнения, если пользователь их указал
            if damage is not None and abs(dmg - damage) > 0.6:
                continue
            if defense is not None and abs(dfn - defense) > 0.6:
                continue
            out.append(base + i)
    return out


def _scan_hero_mask(data):
    """Позиции блоков героев в одном регионе.

    Цикл на Python по каждым 4 байтам занимал ~60 с на всю память: это сотни
    миллионов вызовов unpack_from. numpy делает то же самое векторно —
    буфер интерпретируется как массив float32, а условия превращаются
    в одну булеву маску. Разница примерно в сто раз.

    Смещения блока в единицах float32 (шаг 0x10 = 4 элемента):
      -16 урон   -12 скор.атаки   -8 крит   -4 крит.урон   0 HP   +4 защита
    """
    import numpy as np
    a = np.frombuffer(data[:len(data) // 4 * 4], dtype=np.float32)
    n = len(a)
    if n < 40:
        return []
    lo, hi = 16, n - 4
    hp = a[lo:hi]
    dmg = a[lo - 16:hi - 16]
    aspd = a[lo - 12:hi - 12]
    crit = a[lo - 8:hi - 8]
    cdmg = a[lo - 4:hi - 4]
    dfn = a[lo + 4:hi + 4]
    with np.errstate(invalid="ignore", over="ignore", under="ignore"):
        m = ((dfn >= 50) & (dfn < 1e5)            # у мобов защита = 1
             & (hp > 20) & (hp < 1e6)
             & (np.abs(hp - dfn) >= 0.5)          # HP == защита -> мусор
             & (cdmg >= 1.0) & (cdmg <= 10.0)
             & (crit >= 0.0) & (crit < 0.95)
             & (aspd > 0.3) & (aspd < 10.0)
             & (dmg >= 0.5) & (dmg < 1e6))
    return [(lo + int(k)) * 4 for k in np.nonzero(m)[0]]


def _scan_hero_slow(data):
    """Запасной вариант без numpy — тот же критерий, но медленно."""
    out = []
    for i in range(0x40, len(data) - 0x20, 4):
        dfn = struct.unpack_from("<f", data, i + 0x10)[0]
        if not (50.0 <= dfn < 1e5):
            continue
        hp = struct.unpack_from("<f", data, i)[0]
        if not (20.0 < hp < 1e6) or abs(hp - dfn) < 0.5:
            continue
        cdmg = struct.unpack_from("<f", data, i - 0x10)[0]
        if not (1.0 <= cdmg <= 10.0):
            continue
        crit = struct.unpack_from("<f", data, i - 0x20)[0]
        if not (0.0 <= crit < 0.95):
            continue
        aspd = struct.unpack_from("<f", data, i - 0x30)[0]
        if not (0.3 < aspd < 10.0):
            continue
        dmg = struct.unpack_from("<f", data, i - 0x40)[0]
        if not (0.5 <= dmg < 1e6):
            continue
        out.append(i)
    return out


def find_all_heroes(proc: Proc, progress=None):
    """Найти блоки всех героев без ввода чисел.

    Возвращает [(addr, {стат: значение})], без дублей по набору статов.
    """
    try:
        import numpy  # noqa: F401
        scan = _scan_hero_mask
    except ImportError:
        scan = _scan_hero_slow

    out, seen = [], set()
    regions = proc.regions()
    for ri, (base, size) in enumerate(regions):
        if progress and ri % 20 == 0:
            progress(ri, len(regions))
        if size > 256 * 1024 * 1024:
            continue
        data = proc.read(base, size)
        if not data or len(data) < 0x100:
            continue
        for off in scan(data):
            st = read_stats(proc, base + off)
            hp, dfn, dmg = (st.get("Макс. HP"), st.get("Сила защиты"),
                            st.get("Урон от атаки"))
            if None in (hp, dfn, dmg):
                continue
            sig = (round(hp), round(dfn), round(dmg, 1))
            if sig in seen:
                continue
            seen.add(sig)
            out.append((base + off, st))
    if progress:
        progress(len(regions), len(regions))
    out.sort(key=lambda x: -x[1].get("Сила защиты", 0))
    return out


def read_stats(proc: Proc, block_addr: int, offsets=None):
    """{имя: значение} для одного блока."""
    out = {}
    for name, off in (offsets or STAT_OFFSETS):
        raw = proc.read(block_addr + off, 4)
        if len(raw) == 4:
            v = struct.unpack("<f", raw)[0]
            out[name] = v if math.isfinite(v) else None
    return out


def write_f32(proc: Proc, addr, value):
    old = w.DWORD(0)
    got = ctypes.c_size_t(0)
    k32.VirtualProtectEx(proc.h, ctypes.c_void_p(addr), 4, 0x40, ctypes.byref(old))
    ok = k32.WriteProcessMemory(proc.h, ctypes.c_void_p(addr),
                                struct.pack("<f", float(value)), 4, ctypes.byref(got))
    k32.VirtualProtectEx(proc.h, ctypes.c_void_p(addr), 4, old, ctypes.byref(old))
    return bool(ok)


def write_i64(proc: Proc, addr, value):
    old = w.DWORD(0)
    got = ctypes.c_size_t(0)
    k32.VirtualProtectEx(proc.h, ctypes.c_void_p(addr), 8, 0x40, ctypes.byref(old))
    ok = k32.WriteProcessMemory(proc.h, ctypes.c_void_p(addr),
                                struct.pack("<q", value), 8, ctypes.byref(got))
    k32.VirtualProtectEx(proc.h, ctypes.c_void_p(addr), 8, old, ctypes.byref(old))
    return bool(ok)


# ────────────────── справочники для интерфейса ──────────────────────────────
HERO_NAMES = {101: "Рыцарь", 201: "Следопыт", 301: "Жрец",
              401: "Маг", 501: "Берсерк", 601: "Ассасин"}

# Суффикс ключа атрибута -> человекочитаемое имя (по наблюдаемому эффекту).
ATTR_SUFFIX = {
    1: "Атака", 2: "Здоровье", 3: "Защита", 4: "Скорость",
    11: "Крит. шанс", 12: "Крит. урон", 13: "Уклонение",
    21: "Ветка II · узел 1", 22: "Ветка II · узел 2", 23: "Ветка II · узел 3",
    31: "Ветка III · узел 1", 32: "Ветка III · узел 2", 33: "Ветка III · узел 3",
    41: "Ветка IV · узел 1", 42: "Ветка IV · узел 2", 43: "Ветка IV · узел 3",
    51: "Ветка V · узел 1", 52: "Ветка V · узел 2",
    61: "Ветка VI · узел 1", 62: "Ветка VI · узел 2",
    71: "Ветка VII · узел 1", 72: "Ветка VII · узел 2",
}


def attr_label(key: int) -> str:
    return ATTR_SUFFIX.get(key % 1000, f"узел {key % 1000}")
