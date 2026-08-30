"""
demo.py — наглядная демонстрация найденных уязвимостей TaskBarHero.

Слева  — инструменты, разделённые на две категории по характеру последствий.
Справа — что на это ответил сервер: проверка через собственный автосейв игры.

Утилита сама следит за перезапуском игры: адреса в памяти после рестарта
становятся мусором, поэтому при смене PID кэш сбрасывается, состояние
перечитывается, а применённые изменения при желании накладываются заново.

Запуск требует действующего ключа (см. licensing.py).
"""
import os, sys, time, threading, queue
import tkinter as tk
from tkinter import ttk, messagebox

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core
import licensing

# ── палитра ────────────────────────────────────────────────────────────────
BG, PANEL, EDGE = "#0E1315", "#151C1E", "#283537"
FG, MUT = "#E3EAEA", "#8FA0A2"
ACC, RED, ORANGE, GREEN = "#4EB0A9", "#E2685E", "#D6A244", "#63AF81"
FIELD = "#202B2E"          # фон полей ввода — светлее панели, иначе текст сливается
MONO, UI = ("Consolas", 11), ("Segoe UI", 11)
MONO_S = ("Consolas", 10)


# ══════════════════════════ окно ввода ключа ═══════════════════════════════
class LicenseDialog(tk.Toplevel):
    def __init__(self, master, fingerprint, error=None):
        super().__init__(master)
        self.title("Доступ")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.result = None
        self.grab_set()

        def lbl(t, fg=FG, font=UI, **kw):
            return tk.Label(self, text=t, bg=BG, fg=fg, font=font,
                            justify="left", anchor="w", **kw)

        lbl("Требуется ключ доступа", fg=ACC, font=("Segoe UI", 13, "bold")).pack(
            anchor="w", padx=18, pady=(16, 2))
        if error:
            lbl(error, fg=RED, font=("Segoe UI", 9), wraplength=520).pack(
                anchor="w", padx=18, pady=(0, 8))
        lbl("Отпечаток этой машины — передайте его тому, кто выпускает ключи:",
            fg=MUT, font=("Segoe UI", 9)).pack(anchor="w", padx=18, pady=(6, 2))

        row = tk.Frame(self, bg=BG)
        row.pack(anchor="w", padx=18, fill="x")
        e = tk.Entry(row, font=("Consolas", 14), bg=PANEL, fg=ACC,
                     relief="flat", width=20, justify="center")
        e.insert(0, fingerprint)
        e.configure(state="readonly", readonlybackground=PANEL)
        e.pack(side="left", pady=2)
        tk.Button(row, text="Копировать", font=("Segoe UI", 9), relief="flat",
                  bg=EDGE, fg=FG, cursor="hand2",
                  command=lambda: (self.clipboard_clear(),
                                   self.clipboard_append(fingerprint))
                  ).pack(side="left", padx=8)

        lbl("Вставьте ключ:", fg=MUT, font=("Segoe UI", 9)).pack(
            anchor="w", padx=18, pady=(14, 2))
        self.txt = tk.Text(self, height=5, width=68, font=("Consolas", 8),
                           bg=PANEL, fg=FG, insertbackground=FG,
                           relief="flat", wrap="char")
        self.txt.pack(padx=18)

        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=18, pady=14)
        tk.Button(bar, text="Продолжить", font=("Segoe UI", 10, "bold"), relief="flat",
                  bg=ACC, fg=BG, cursor="hand2", padx=18, pady=5,
                  command=self._ok).pack(side="left")
        tk.Button(bar, text="Выход", font=UI, relief="flat", bg=EDGE, fg=FG,
                  cursor="hand2", padx=14, pady=5, command=self._cancel).pack(side="left", padx=8)

        lbl("Ключ привязан к этой машине и к сетевому времени.\n"
            "Без интернета проверить срок нечем — утилита не запустится.",
            fg=MUT, font=("Segoe UI", 8)).pack(anchor="w", padx=18, pady=(0, 14))

        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.txt.focus_set()
        self.bind("<Control-Return>", lambda e: self._ok())

    def _ok(self):
        self.result = self.txt.get("1.0", "end").strip()
        self.destroy()

    def _cancel(self):
        self.result = None
        self.destroy()


# ══════════════════════════ основное окно ══════════════════════════════════
class Demo(tk.Tk):
    def __init__(self, license_info):
        super().__init__()
        self.deadline = time.time() + license_info["expires_in"]
        self.proc = None
        self.inner = None
        self.applied = []            # [{kind,key,label,before,target,addrs}]
        self.cache = {}              # key -> [addrs]
        self.cost_backup = None
        self.q = queue.Queue()
        self._last_pid = -1
        self._busy = False

        self.title("TaskBarHero — наглядный пример уязвимостей")
        self.configure(bg=BG)
        self.geometry("1480x900")
        self.minsize(1240, 780)

        self._style()
        self._build_top()
        self._build_body()

        self.after(150, self._pump)
        self.after(1000, self._tick)
        self.after(500, self._watchdog)

    # ── оформление ────────────────────────────────────────────────────────
    def _style(self):
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        # В состоянии readonly ttk берёт ДРУГИЕ цвета, чем заданные в configure,
        # из-за чего список выглядел тёмным текстом по тёмному фону. Нужен map().
        for w in ("TCombobox", "TSpinbox"):
            s.configure(w, fieldbackground=FIELD, background=FIELD, foreground=FG,
                        arrowcolor=ACC, bordercolor=EDGE, lightcolor=FIELD,
                        darkcolor=FIELD, insertcolor=FG, padding=4)
            s.map(w,
                  fieldbackground=[("readonly", FIELD), ("disabled", PANEL),
                                   ("focus", FIELD), ("!disabled", FIELD)],
                  foreground=[("readonly", FG), ("disabled", MUT), ("!disabled", FG)],
                  selectbackground=[("readonly", FIELD), ("!disabled", FIELD)],
                  selectforeground=[("readonly", FG), ("!disabled", FG)],
                  background=[("readonly", FIELD), ("active", FIELD), ("!disabled", FIELD)])
        s.configure("TCheckbutton", background=PANEL, foreground=FG, font=("Segoe UI", 10))
        s.map("TCheckbutton", background=[("active", PANEL)], foreground=[("active", ACC)])
        s.configure("TSeparator", background=EDGE)
        s.configure("Vertical.TScrollbar", background=EDGE, troughcolor=BG,
                    arrowcolor=MUT, bordercolor=BG)

        self.option_add("*TCombobox*Listbox.background", FIELD)
        self.option_add("*TCombobox*Listbox.foreground", FG)
        self.option_add("*TCombobox*Listbox.selectBackground", ACC)
        self.option_add("*TCombobox*Listbox.selectForeground", BG)
        self.option_add("*TCombobox*Listbox.font", MONO)

    def _btn(self, parent, text, cmd, color=ACC, small=False):
        return tk.Button(parent, text=text, command=cmd, relief="flat", cursor="hand2",
                         bg=color, fg=BG, activebackground=FG,
                         font=("Segoe UI", 9 if small else 10, "bold"),
                         padx=10 if small else 14, pady=3 if small else 5)

    # ── верх ──────────────────────────────────────────────────────────────
    def _build_top(self):
        top = tk.Frame(self, bg=PANEL, height=50)
        top.pack(fill="x")
        top.pack_propagate(False)

        self.lbl_game = tk.Label(top, text="игра: —", bg=PANEL, fg=MUT, font=MONO)
        self.lbl_game.pack(side="left", padx=(16, 12))
        self.lbl_save = tk.Label(top, text="сейв: —", bg=PANEL, fg=MUT, font=MONO)
        self.lbl_save.pack(side="left", padx=12)
        self.lbl_busy = tk.Label(top, text="", bg=PANEL, fg=ORANGE, font=MONO)
        self.lbl_busy.pack(side="left", padx=12)

        self.lbl_key = tk.Label(top, text="", bg=PANEL, fg=ACC, font=("Consolas", 12, "bold"))
        self.lbl_key.pack(side="right", padx=16)
        self._btn(top, "Обновить", self.refresh_state, small=True).pack(side="right", padx=6)

    # ── тело ──────────────────────────────────────────────────────────────
    def _build_body(self):
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True)

        # Левая колонка прокручиваемая: с боевыми статами она выше экрана
        # на ноутбуках, и нижние кнопки иначе недостижимы.
        outer = tk.Frame(body, bg=BG, width=660)
        outer.pack(side="left", fill="y", padx=(12, 6), pady=10)
        outer.pack_propagate(False)

        canvas = tk.Canvas(outer, bg=BG, highlightthickness=0, borderwidth=0)
        vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        left = tk.Frame(canvas, bg=BG)
        win = canvas.create_window((0, 0), window=left, anchor="nw")
        left.bind("<Configure>",
                  lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfigure(win, width=e.width))

        # Колесо мыши: bind_all пока курсор над колонкой, иначе события
        # съедают вложенные виджеты и прокрутка работает через раз.
        def wheel(e):
            canvas.yview_scroll(-1 if e.delta > 0 else 1, "units")
        outer.bind("<Enter>", lambda e: canvas.bind_all("<MouseWheel>", wheel))
        outer.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))
        self._scroll_canvas = canvas

        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True, padx=(6, 12), pady=10)

        self._build_red(left)
        self._build_orange(left)
        self._build_applied(left)
        self._build_footer(left)
        self._build_log(right)

    def _section(self, parent, color, title, subtitle):
        wrap = tk.Frame(parent, bg=PANEL, highlightbackground=color, highlightthickness=1)
        wrap.pack(fill="x", pady=(0, 8))
        head = tk.Frame(wrap, bg=color)
        head.pack(fill="x")
        tk.Label(head, text=title, bg=color, fg=BG, font=("Segoe UI", 10, "bold"),
                 anchor="w").pack(fill="x", padx=10, pady=3)
        tk.Label(wrap, text=subtitle, bg=PANEL, fg=MUT, font=("Segoe UI", 8),
                 justify="left", anchor="w", wraplength=540).pack(fill="x", padx=10, pady=(5, 2))
        inner = tk.Frame(wrap, bg=PANEL)
        inner.pack(fill="x", padx=10, pady=(2, 8))
        return inner

    def _picker(self, parent, row, label, apply_text, apply_cmd, color, default):
        """Строка выбора: фильтр + выпадающий список + уровень + кнопка."""
        tk.Label(parent, text=label, bg=PANEL, fg=FG, font=UI).grid(
            row=row, column=0, sticky="w", pady=(8, 2))
        flt = tk.Entry(parent, bg=FIELD, fg=ACC, insertbackground=ACC, relief="flat",
                       font=MONO, width=13, highlightthickness=1,
                       highlightbackground=EDGE, highlightcolor=ACC)
        flt.grid(row=row, column=1, sticky="w", padx=8, ipady=3)
        tk.Label(parent, text="фильтр", bg=PANEL, fg=MUT,
                 font=("Segoe UI", 8)).grid(row=row, column=2, sticky="w")

        cb = ttk.Combobox(parent, state="readonly", width=42, font=MONO)
        cb.grid(row=row + 1, column=0, columnspan=3, sticky="w", pady=3)

        # from_ отрицательный: игра принимает и минусовые уровни рун
        sp = ttk.Spinbox(parent, from_=-999999, to=999999, width=10, font=MONO)
        sp.set(default)
        sp.grid(row=row + 2, column=0, sticky="w", pady=(3, 5))
        btn = self._btn(parent, apply_text, apply_cmd, color, small=True)
        btn.grid(row=row + 2, column=1, columnspan=2, sticky="w", padx=8, pady=(2, 4))
        return flt, cb, sp

    # ── КРАСНЫЙ ───────────────────────────────────────────────────────────
    def _build_red(self, parent):
        f = self._section(parent, RED, "1 · СОХРАНЯЕТСЯ НА СЕРВЕРЕ",
                          "Изменение уходит в сейв и переживает полный перезапуск игры. "
                          "Сервер принимает его как легитимное.")

        tk.Label(f, text="Герой", bg=PANEL, fg=FG, font=UI).grid(row=0, column=0, sticky="w")
        self.cb_hero = ttk.Combobox(f, state="readonly", width=28, font=MONO)
        self.cb_hero.grid(row=0, column=1, columnspan=2, sticky="w", padx=8, pady=2)
        self.cb_hero.bind("<<ComboboxSelected>>", lambda e: self._fill_attrs())

        self.f_attr, self.cb_attr, self.sp_attr = self._picker(
            f, 1, "Характеристика", "Применить (F-01)", self.apply_attr, RED, 50)
        self.f_attr.bind("<KeyRelease>", lambda e: self._filter_attr())

        ttk.Separator(f, orient="horizontal").grid(row=4, column=0, columnspan=3,
                                                   sticky="ew", pady=6)

        self.f_rune, self.cb_rune, self.sp_rune = self._picker(
            f, 5, "Руна", "Применить (F-02)", self.apply_rune, RED, 5)
        self.f_rune.bind("<KeyRelease>", lambda e: self._filter_rune())

        tk.Label(f, text="Фильтр сужает список: наберите 0 — останутся закрытые руны.",
                 bg=PANEL, fg=MUT, font=("Segoe UI", 9), wraplength=520,
                 justify="left").grid(row=8, column=0, columnspan=3, sticky="w", pady=(4, 0))

    # ── ОРАНЖЕВЫЙ ─────────────────────────────────────────────────────────
    def _build_orange(self, parent):
        f = self._section(parent, ORANGE, "2 · ТОЛЬКО НА ЭТУ СЕССИЮ",
                          "Само изменение при перезапуске сбросится. Но всё, что игрок успел "
                          "получить за его счёт, начислено штатным кодом игры и остаётся навсегда.")

        # ── цены рун ──────────────────────────────────────────────────────
        tk.Label(f, text="Цены рун", bg=PANEL, fg=FG,
                 font=("Segoe UI", 11, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 2))
        self.lbl_costs = tk.Label(f, text="не найдена", bg=PANEL, fg=MUT, font=MONO)
        self.lbl_costs.grid(row=0, column=1, columnspan=2, sticky="w", padx=8)

        bar = tk.Frame(f, bg=PANEL)
        bar.grid(row=1, column=0, columnspan=3, sticky="w", pady=2)
        self.sp_cost = ttk.Spinbox(bar, from_=-10 ** 9, to=10 ** 9, width=11, font=MONO)
        self.sp_cost.set(-100)
        self.sp_cost.pack(side="left")
        self._btn(bar, "Переписать", self.apply_costs, ORANGE, small=True).pack(
            side="left", padx=6)
        self._btn(bar, "Вернуть", self.restore_costs, "#8A9A9C", small=True).pack(side="left")

        tk.Label(f, text="Отрицательная цена НАЧИСЛЯЕТ золото при улучшении руны. "
                         "Само золото уходит в защищённое хранилище как честно заработанное "
                         "и остаётся после перезапуска — проверено.",
                 bg=PANEL, fg=ORANGE, font=("Segoe UI", 9), wraplength=560,
                 justify="left").grid(row=2, column=0, columnspan=3, sticky="w", pady=(2, 8))

        ttk.Separator(f, orient="horizontal").grid(row=3, column=0, columnspan=3,
                                                   sticky="ew", pady=4)

        # ── боевые статы ──────────────────────────────────────────────────
        tk.Label(f, text="Боевые характеристики", bg=PANEL, fg=FG,
                 font=("Segoe UI", 11, "bold")).grid(row=4, column=0, sticky="w", pady=(6, 2))

        # ── способ 1: автопоиск всех героев ───────────────────────────────
        auto = tk.Frame(f, bg=PANEL)
        auto.grid(row=5, column=0, columnspan=3, sticky="w", pady=(2, 4))
        self._btn(auto, "Найти всех героев", self.scan_heroes, ACC, small=True).pack(side="left")
        self.cb_hero_block = ttk.Combobox(auto, state="readonly", width=46, font=MONO_S)
        self.cb_hero_block.pack(side="left", padx=8)
        self.cb_hero_block.bind("<<ComboboxSelected>>", self._pick_hero_block)

        # ── способ 2: точный поиск по числам из STATUS ────────────────────
        tk.Label(f, text="или впишите числа из окна STATUS вручную:",
                 bg=PANEL, fg=MUT, font=("Segoe UI", 9)).grid(
            row=6, column=0, columnspan=3, sticky="w", pady=(2, 2))

        anchor = tk.Frame(f, bg=PANEL)
        anchor.grid(row=7, column=0, columnspan=3, sticky="w", pady=(0, 6))

        def field(label, width=7):
            tk.Label(anchor, text=label, bg=PANEL, fg=MUT,
                     font=("Segoe UI", 10)).pack(side="left")
            e = tk.Entry(anchor, bg=FIELD, fg=ACC, insertbackground=ACC, relief="flat",
                         font=MONO, width=width, highlightthickness=1,
                         highlightbackground=EDGE, highlightcolor=ACC, justify="center")
            e.pack(side="left", padx=(6, 12), ipady=3)
            e.bind("<Return>", lambda ev: self.scan_stats())
            return e

        self.e_hp = field("Макс. HP")
        self.e_dmg = field("Урон")
        self.e_def = field("Защита")
        self._btn(anchor, "Найти", self.scan_stats, ORANGE, small=True).pack(side="left")
        self.lbl_stats = tk.Label(anchor, text="", bg=PANEL, fg=MUT, font=MONO)
        self.lbl_stats.pack(side="left", padx=8)

        # ── таблица статов ────────────────────────────────────────────────
        self.stat_rows = {}
        grid = tk.Frame(f, bg=PANEL)
        grid.grid(row=8, column=0, columnspan=3, sticky="w", pady=(2, 2))
        for r, (name, off) in enumerate(core.ALL_OFFSETS):
            if off == core.MISC_OFFSETS[0][1]:      # разделитель перед «Прочее»
                ttk.Separator(grid, orient="horizontal").grid(
                    row=r, column=0, columnspan=4, sticky="ew", pady=5)
                continue
            tk.Label(grid, text=name, bg=PANEL, fg=FG, font=("Segoe UI", 10),
                     width=19, anchor="w").grid(row=r, column=0, sticky="w", pady=1)
            cur = tk.Label(grid, text="—", bg=PANEL, fg=MUT, font=MONO, width=11, anchor="e")
            cur.grid(row=r, column=1, padx=6)
            ent = tk.Entry(grid, bg=FIELD, fg=FG, insertbackground=FG, relief="flat",
                           font=MONO, width=12, highlightthickness=1,
                           highlightbackground=EDGE, highlightcolor=ORANGE, justify="right")
            ent.grid(row=r, column=2, padx=4, ipady=2)
            self._btn(grid, "→", lambda n=name: self.apply_stat(n), ORANGE,
                      small=True).grid(row=r, column=3, padx=4)
            self.stat_rows[name] = (cur, ent)

        # строка «Усиление Опыт» рисуется отдельной строкой сетки выше,
        # поэтому просто добавим её вручную после разделителя
        r0 = len(core.ALL_OFFSETS)
        for extra, off in core.MISC_OFFSETS:
            if extra in self.stat_rows:
                continue
            tk.Label(grid, text=extra, bg=PANEL, fg=ORANGE, font=("Segoe UI", 10, "bold"),
                     width=19, anchor="w").grid(row=r0, column=0, sticky="w", pady=1)
            cur = tk.Label(grid, text="—", bg=PANEL, fg=MUT, font=MONO, width=11, anchor="e")
            cur.grid(row=r0, column=1, padx=6)
            ent = tk.Entry(grid, bg=FIELD, fg=FG, insertbackground=FG, relief="flat",
                           font=MONO, width=12, highlightthickness=1,
                           highlightbackground=EDGE, highlightcolor=ORANGE, justify="right")
            ent.grid(row=r0, column=2, padx=4, ipady=2)
            self._btn(grid, "→", lambda n=extra: self.apply_stat(n), ORANGE,
                      small=True).grid(row=r0, column=3, padx=4)
            self.stat_rows[extra] = (cur, ent)
            r0 += 1

        sbar = tk.Frame(f, bg=PANEL)
        sbar.grid(row=9, column=0, columnspan=3, sticky="w", pady=(8, 0))
        self._btn(sbar, "Применить все", self.apply_all_stats, ORANGE, small=True).pack(side="left")
        self._btn(sbar, "В исходное", self.restore_stats, "#8A9A9C", small=True).pack(
            side="left", padx=6)
        tk.Label(f, text="«Усиление Опыт» = множитель опыта за убийство: 1.0 это обычные 100%. "
                         "Поставь 50000 — один моб даст десятки тысяч опыта, и этот опыт "
                         "начислит сама игра, поэтому он сохранится.",
                 bg=PANEL, fg=ORANGE, font=("Segoe UI", 9), wraplength=580,
                 justify="left").grid(row=10, column=0, columnspan=3, sticky="w", pady=(8, 0))
        tk.Label(f, text="Боевых статов нет в сейве — они считаются из характеристик и "
                         "снаряжения, поэтому перезапуск их сбрасывает.",
                 bg=PANEL, fg=MUT, font=("Segoe UI", 9), wraplength=580,
                 justify="left").grid(row=11, column=0, columnspan=3, sticky="w", pady=(4, 0))

    # ── применённые изменения ─────────────────────────────────────────────
    def _build_applied(self, parent):
        wrap = tk.Frame(parent, bg=PANEL, highlightbackground=EDGE, highlightthickness=1)
        wrap.pack(fill="x", pady=(0, 8))
        head = tk.Frame(wrap, bg=PANEL)
        head.pack(fill="x", padx=10, pady=(6, 2))
        tk.Label(head, text="ПРИМЕНЕНО", bg=PANEL, fg=ACC,
                 font=("Segoe UI", 9, "bold")).pack(side="left")
        self.var_reapply = tk.BooleanVar(value=True)
        ttk.Checkbutton(head, text="переприменять после перезапуска игры",
                        variable=self.var_reapply).pack(side="right")

        self.lst = tk.Listbox(wrap, bg=FIELD, fg=FG, font=MONO_S, relief="flat",
                              selectbackground=ACC, selectforeground=BG,
                              activestyle="none", height=6, highlightthickness=0)
        self.lst.pack(fill="both", expand=True, padx=10, pady=2)

        bar = tk.Frame(wrap, bg=PANEL)
        bar.pack(fill="x", padx=10, pady=(2, 8))
        self._btn(bar, "Откатить выбранное", self.revert_selected, "#8A9A9C",
                  small=True).pack(side="left")
        self._btn(bar, "Откатить всё", self.revert_all, "#8A9A9C", small=True).pack(
            side="left", padx=6)

    def _refresh_applied(self):
        self.lst.delete(0, "end")
        for a in self.applied:
            self.lst.insert("end", f"{a['label']:<34} {a['before']} → {a['target']}")

    # ── низ ───────────────────────────────────────────────────────────────
    def _build_footer(self, parent):
        f = tk.Frame(parent, bg=BG)
        f.pack(fill="x")
        self._btn(f, "Проверить ответ сервера", self.verify, ACC).pack(side="left")
        tk.Label(parent, text="«Проверить» ждёт собственный автосейв игры (до ~3 мин), затем "
                              "перечитывает сейв. Это единственный корректный способ "
                              "подтвердить, что сервер принял изменение.",
                 bg=BG, fg=MUT, font=("Segoe UI", 9), wraplength=560,
                 justify="left").pack(anchor="w", pady=(6, 0))

    # ── правая колонка ────────────────────────────────────────────────────
    def _build_log(self, parent):
        head = tk.Frame(parent, bg=BG)
        head.pack(fill="x")
        tk.Label(head, text="ОТВЕТ СЕРВЕРА", bg=BG, fg=ACC,
                 font=("Segoe UI", 11, "bold")).pack(side="left")
        self._btn(head, "Показать защищённое (контроль)", self.control_group,
                  "#8A9A9C", small=True).pack(side="right")
        self._btn(head, "Очистить", lambda: self.log_w.delete("1.0", "end"),
                  "#8A9A9C", small=True).pack(side="right", padx=6)

        tk.Label(parent, text="Контроль показывает атаки на предметы, золото и стадию — их "
                              "защита отбивает. Это и есть механизм, который нужно "
                              "распространить на блок 1.",
                 bg=BG, fg=MUT, font=("Segoe UI", 9), wraplength=700,
                 justify="left").pack(anchor="w", pady=(4, 6))

        box = tk.Frame(parent, bg=BG)
        box.pack(fill="both", expand=True)
        self.log_w = tk.Text(box, bg="#0A0F10", fg=FG, insertbackground=FG, font=MONO,
                             wrap="word", relief="flat", borderwidth=0)
        sb = ttk.Scrollbar(box, command=self.log_w.yview)
        sb.pack(side="right", fill="y")
        self.log_w.pack(side="left", fill="both", expand=True)
        self.log_w.configure(yscrollcommand=sb.set)
        for tag, col in (("acc", ACC), ("red", RED), ("orange", ORANGE),
                         ("green", GREEN), ("mut", MUT)):
            self.log_w.tag_configure(tag, foreground=col)
        self.log_w.tag_configure("b", font=("Consolas", 11, "bold"))
        self.log("Слежу за игрой. Выберите изменение слева, затем «Проверить ответ сервера».\n", "mut")

    # ── журнал / потоки ───────────────────────────────────────────────────
    def log(self, text, tag=None):
        self.log_w.insert("end", text, tag or ())
        self.log_w.see("end")

    def _pump(self):
        try:
            while True:
                self.q.get_nowait()()
        except queue.Empty:
            pass
        self.after(150, self._pump)

    def post(self, fn):
        self.q.put(fn)

    def plog(self, text, tag=None):
        self.post(lambda: self.log(text, tag))

    def busy(self, text):
        self.post(lambda: self.lbl_busy.config(text=text))

    def bg(self, fn):
        """Фоновая задача с флагом занятости — чтобы не запускать две сразу."""
        if self._busy:
            self.log("  подождите, идёт другая операция\n", "orange")
            return

        def wrapper():
            self._busy = True
            try:
                fn()
            except Exception as e:
                self.plog(f"  ошибка: {type(e).__name__}: {e}\n", "red")
            finally:
                self._busy = False
                self.busy("")
        threading.Thread(target=wrapper, daemon=True).start()

    def _tick(self):
        left = int(self.deadline - time.time())
        if left <= 0:
            messagebox.showwarning("Ключ истёк", "Срок ключа закончился. Утилита закрывается.")
            self.destroy()
            return
        self.lbl_key.config(text=f"ключ: {left // 60:02d}:{left % 60:02d}",
                            fg=ORANGE if left < 300 else ACC)
        self.after(1000, self._tick)

    # ── сторож перезапуска игры ───────────────────────────────────────────
    def _watchdog(self):
        pid = core.game_pid()
        if pid != self._last_pid:
            prev, self._last_pid = self._last_pid, pid
            self._on_game_change(prev, pid)
        self.after(2000, self._watchdog)

    def _on_game_change(self, prev, pid):
        self.cache.clear()
        self.cost_backup = None
        self.lbl_costs.config(text="не сканировалась", fg=MUT)
        if self.proc:
            self.proc.close()
            self.proc = None

        if pid is None:
            self.lbl_game.config(text="игра: не запущена", fg=RED)
            if prev not in (-1, None):
                self.log("\n[!] игра закрыта — жду запуска\n", "orange")
            return

        try:
            self.proc = core.Proc(pid)
            self.lbl_game.config(text=f"игра: PID {pid}", fg=GREEN)
        except OSError as e:
            self.lbl_game.config(text="игра: нет доступа", fg=RED)
            self.log(f"\n[!] не удалось открыть процесс: {e}\n", "red")
            return

        if prev in (-1, None):
            self.log(f"[+] игра найдена, PID {pid}\n", "green")
        else:
            self.log(f"\n[!] игра перезапустилась (PID {prev} → {pid})\n", "orange")
            self.log("    адреса в памяти сброшены\n", "mut")

        self.refresh_state()
        # Ищем всё сразу, как только увидели игру — независимо от того,
        # был перезапуск или утилиту просто открыли при уже запущенной игре.
        self.bg(lambda: self._prescan(reapply=prev not in (-1, None)))

    def _prescan(self, reapply=False):
        """Найти ВСЕ объекты характеристик и рун за два прохода памяти.

        Все AttributeSaveData делят один klass-указатель, все RuneSaveData —
        другой. Поэтому ищутся две иголки вместо 329, и всё готово за секунды,
        а не за пять минут.
        """
        if not self.inner:
            return
        attr_keys = [a["Key"] for a in self.inner["attributeSaveDatas"]]
        rune_keys = [r["RuneKey"] for r in self.inner["RuneSaveData"]]

        self.busy("ищу характеристики…")
        _, fa = core.detect_klass(self.proc, attr_keys)
        self.busy("ищу руны…")
        _, fr = core.detect_klass(self.proc, rune_keys)

        for key, hits in list(fa.items()) + list(fr.items()):
            self.cache[key] = [addr for addr, _ in hits]
        self.plog(f"    готово: характеристики {len(fa)}/{len(attr_keys)}, "
                  f"руны {len(fr)}/{len(rune_keys)} — можно применять сразу\n", "green")

        self.busy("ищу таблицу цен…")
        rows = core.find_cost_rows(self.proc, rune_keys=set(rune_keys))
        self.cost_backup = [(a, c) for a, _, _, c in rows]
        self.post(lambda: self.lbl_costs.config(text=f"{len(rows)} строк", fg=ORANGE))
        self.plog(f"    таблица цен: {len(rows)} строк\n", "mut")
        self.busy("")

        if reapply and self.applied and self.var_reapply.get():
            self.plog(f"    переприменяю {len(self.applied)} изменени(й)\n", "mut")
            for a in self.applied:
                addrs = self.cache.get(a["key"])
                if not addrs:
                    self.plog(f"    {a['label']}: объект не найден\n", "red")
                    continue
                a["addrs"] = addrs
                done = sum(1 for addr in addrs if self.proc.write_i32(addr, a["target"]))
                self.plog(f"    {a['label']}: восстановлено {a['target']} "
                          f"({done}/{len(addrs)})\n", "green")

    # ── состояние ─────────────────────────────────────────────────────────
    def refresh_state(self):
        pid = core.game_pid()
        if pid and (not self.proc or self.proc.pid != pid):
            try:
                if self.proc:
                    self.proc.close()
                self.proc = core.Proc(pid)
                self._last_pid = pid
                self.lbl_game.config(text=f"игра: PID {pid}", fg=GREEN)
            except OSError:
                self.proc = None
        try:
            _, self.inner = core.load_save()
            n = len(self.inner["itemSaveDatas"])
            g = self.inner["currenySaveDatas"][0]["Quantity"]
            self.lbl_save.config(
                text=f"сейв: {n} предметов · {g:,} золота".replace(",", " "), fg=GREEN)
            self._fill_heroes()
            self._fill_runes()
        except Exception as e:
            self.lbl_save.config(text=f"сейв: ошибка ({e})", fg=RED)

    def _fill_heroes(self):
        hs = self.inner["heroSaveDatas"]
        keep = self.cb_hero.get()
        self.cb_hero["values"] = [
            f"{h['heroKey']}  {core.HERO_NAMES.get(h['heroKey'], '—')}  LV{h['HeroLevel']}"
            for h in hs]
        if keep in self.cb_hero["values"]:
            self.cb_hero.set(keep)
        elif hs:
            self.cb_hero.current(0)
        self._fill_attrs()

    def _fill_attrs(self):
        sel = self.cb_hero.get()
        if not sel or not self.inner:
            return
        hk = sel.split()[0]
        attrs = sorted((a for a in self.inner["attributeSaveDatas"]
                        if str(a["Key"]).startswith(hk)), key=lambda a: a["Key"])
        self._attr_all = [f"{a['Key']}  {core.attr_label(a['Key']):<20} = {a['Level']}"
                          for a in attrs]
        self._filter_attr()

    def _filter_attr(self):
        q = self.f_attr.get().strip().lower()
        vals = [v for v in getattr(self, "_attr_all", []) if q in v.lower()] or self._attr_all
        keep = self.cb_attr.get()
        self.cb_attr["values"] = vals
        if keep in vals:
            self.cb_attr.set(keep)
        elif vals:
            self.cb_attr.current(0)

    def _fill_runes(self):
        runes = sorted(self.inner["RuneSaveData"], key=lambda r: (-r["Level"], r["RuneKey"]))
        self._rune_all = [f"{r['RuneKey']:<9} = {r['Level']}"
                          + ("   (закрыта)" if r["Level"] == 0 else "") for r in runes]
        self._filter_rune()

    def _filter_rune(self):
        q = self.f_rune.get().strip().lower()
        vals = [v for v in getattr(self, "_rune_all", []) if q in v.lower()] or self._rune_all
        keep = self.cb_rune.get()
        self.cb_rune["values"] = vals
        if keep in vals:
            self.cb_rune.set(keep)
        elif vals:
            self.cb_rune.current(0)

    def _need(self):
        if not self.proc:
            messagebox.showerror("Игра не найдена",
                                 "Запустите TaskBarHero — утилита подхватит её сама.")
            return False
        return True

    # ── применение ────────────────────────────────────────────────────────
    def apply_attr(self):
        if not self._need() or not self.cb_attr.get():
            return
        key = int(self.cb_attr.get().split()[0])
        self._apply("attr", key, f"характеристика {key} ({core.attr_label(key)})",
                    int(self.sp_attr.get()))

    def apply_rune(self):
        if not self._need() or not self.cb_rune.get():
            return
        key = int(self.cb_rune.get().split()[0])
        self._apply("rune", key, f"руна {key}", int(self.sp_rune.get()))

    def _apply(self, kind, key, label, target):
        self.log(f"\n[{'F-01' if kind == 'attr' else 'F-02'}] {label} → {target}\n", "red")

        def work():
            cached = self.cache.get(key)
            if cached:
                self.busy("пишу…")
                self.plog("  адреса уже известны — пишу без пересканирования\n", "mut")
            else:
                self.busy("ищу объект…")
            done, total, before, addrs = core.patch_level(self.proc, key, target, cached)
            if total == 0:
                self.plog("  объект не найден\n", "red")
                return
            self.cache[key] = addrs
            # читаем обратно: подтверждаем, что запись действительно легла
            back = [self.proc.read_i32(a) for a in addrs]
            ok = all(v == target for v in back)
            self.plog(f"  объектов: {total}, записано: {done}\n", "mut")
            self.plog(f"  было {before} → стало {target}"
                      f"{'' if ok else '  (проверка: ' + str(back) + ')'}\n",
                      "b" if ok else "orange")
            if not ok:
                self.plog("  часть копий не приняла запись — игра могла их перечитать\n",
                          "orange")

            prev = next((a for a in self.applied if a["key"] == key), None)
            if prev:
                prev["target"] = target
                prev["addrs"] = addrs
            else:
                self.applied.append({"kind": kind, "key": key, "label": label,
                                     "before": before, "target": target, "addrs": addrs})
            self.post(self._refresh_applied)

            if kind == "attr":
                self._budget_note(key, before, target)
            self.plog("  → «Проверить ответ сервера»\n", "mut")

        self.bg(work)

    def _budget_note(self, key, before, target):
        hk = int(str(key)[:3])
        hero = next((h for h in self.inner["heroSaveDatas"] if h["heroKey"] == hk), None)
        if not hero:
            return
        spent = sum(a["Level"] for a in self.inner["attributeSaveDatas"]
                    if str(a["Key"]).startswith(str(hk)))
        proj = spent - (before or 0) + target
        if proj > hero["AllocatedHeroAbilityPoint"]:
            self.plog(f"  [F-03] сумма уровней {proj} > бюджета "
                      f"{hero['AllocatedHeroAbilityPoint']} — игра это не проверяет\n", "orange")

    # ── оранжевый ─────────────────────────────────────────────────────────
    def scan_costs(self):
        if not self._need():
            return
        self.log("\n[F-04] сканирую таблицу цен рун…\n", "orange")

        def work():
            self.busy("ищу таблицу…")
            # Реальные ключи рун из сейва: числовой диапазон терял 88 рун
            # с короткими ключами (1, 10, 11, 20, 24 …) и их цены не менялись.
            rk = {r["RuneKey"] for r in self.inner["RuneSaveData"]} if self.inner else None
            rows = core.find_cost_rows(self.proc, rune_keys=rk)
            self.cost_backup = [(a, c) for a, _, _, c in rows]
            self.post(lambda: self.lbl_costs.config(text=f"{len(rows)} строк", fg=ORANGE))
            self.plog(f"  найдено строк: {len(rows)}\n", "mut")
            for a, rk, lv, c in sorted(rows, key=lambda r: (r[1], r[2]))[:6]:
                self.plog(f"    руна {rk:<9} ур.{lv}  цена {c:,}\n".replace(",", " "), "mut")
            if len(rows) > 6:
                self.plog(f"    … ещё {len(rows) - 6}\n", "mut")
            self.plog("  таблица в обычной read/write памяти, без защиты\n", "b")
        self.bg(work)

    def apply_costs(self):
        if not self._need():
            return
        if not self.cost_backup:
            messagebox.showinfo("Сначала сканируйте", "Нажмите «Найти таблицу цен рун».")
            return
        new = int(self.sp_cost.get())
        self.log(f"\n[F-04] переписываю {len(self.cost_backup)} цен → {new}\n", "orange")

        def work():
            n = sum(1 for a, _ in self.cost_backup if self.proc.write_i32(a, new))
            self.plog(f"  записано: {n}/{len(self.cost_backup)}\n", "b")
            self.plog("  при перезапуске цены вернутся — но купленное останется\n", "orange")
        self.bg(work)

    def restore_costs(self):
        if not self._need() or not self.cost_backup:
            return
        self.log("\n[F-04] возвращаю исходные цены\n", "orange")

        def work():
            n = sum(1 for a, c in self.cost_backup if self.proc.write_i32(a, c))
            self.plog(f"  восстановлено: {n}/{len(self.cost_backup)}\n", "green")
        self.bg(work)

    # ── боевые статы (сессионные) ─────────────────────────────────────────
    def scan_stats(self):
        if not self._need():
            return
        def num(entry):
            t = entry.get().strip().replace(",", ".")
            try:
                return float(t) if t else None
            except ValueError:
                return None

        hp, dmg, dfn = num(self.e_hp), num(self.e_dmg), num(self.e_def)
        if hp is None:
            messagebox.showinfo("Нужен якорь",
                                "Впишите хотя бы Макс. HP из окна STATUS.\n"
                                "Урон и защиту можно добавить — тогда поиск точнее.")
            return
        extra = ", ".join(f"{n} ≈ {v:g}" for n, v in
                          (("урон", dmg), ("защита", dfn)) if v is not None)
        self.log(f"\n[Боевые статы] ищу: Макс. HP ≈ {hp:g}"
                 + (f", {extra}" if extra else "") + "\n", "orange")

        def work():
            self.busy("ищу блок статов…")
            blocks = core.find_stat_blocks(self.proc, hp, damage=dmg, defense=dfn)
            if not blocks:
                self.plog("  не найдено — проверьте число в окне STATUS\n", "red")
                self.post(lambda: self.lbl_stats.config(text="не найдено", fg=RED))
                return
            if len(blocks) > core.MAX_SANE_BLOCKS:
                # предохранитель: столько блоков быть не может, фильтр промахнулся
                self.plog(f"  ОТКАЗ: {len(blocks)} блоков — это не статы, не пишу\n", "red")
                return
            self.stat_blocks = blocks
            vals = core.read_stats(self.proc, blocks[0], core.ALL_OFFSETS)
            self.stat_orig = dict(vals)
            self.plog(f"  найдено блоков: {len(blocks)}\n", "mut")
            for n, v in vals.items():
                self.plog(f"    {n:<16} {v:.3f}\n", "mut")
            self.post(lambda: self._fill_stats(vals, len(blocks)))
        self.bg(work)

    def scan_heroes(self):
        """Найти блоки всех героев сразу, без ввода чисел."""
        if not self._need():
            return
        self.log("\n[Боевые статы] ищу блоки всех героев…\n", "orange")

        def work():
            self.busy("перебираю память…")
            res = core.find_all_heroes(
                self.proc,
                progress=lambda i, n: self.busy(f"поиск… {i * 100 // max(n, 1)}%"))
            if not res:
                self.plog("  не найдено\n", "red")
                return
            self.hero_blocks = res
            self.plog(f"  найдено вариантов: {len(res)}\n", "mut")
            items = []
            for a, st in res:
                items.append(f"HP {st['Макс. HP']:>7.0f} · защита {st['Сила защиты']:>5.0f} "
                             f"· урон {st['Урон от атаки']:>8.1f} · скор {st['Скорость атаки']:.2f}")
                self.plog(f"    {items[-1]}\n", "mut")
            self.post(lambda: self._fill_hero_list(items))
            self.plog("  выберите своего героя в списке — сверьтесь с окном STATUS\n", "b")
        self.bg(work)

    def _fill_hero_list(self, items):
        self.cb_hero_block["values"] = items
        if items:
            self.cb_hero_block.current(0)
            self._pick_hero_block()

    def _pick_hero_block(self, _evt=None):
        i = self.cb_hero_block.current()
        if i < 0 or not getattr(self, "hero_blocks", None):
            return
        addr, st = self.hero_blocks[i]
        # берём все копии этого блока — правку надо писать во все
        self.stat_blocks = core.find_stat_blocks(
            self.proc, st["Макс. HP"], damage=st["Урон от атаки"]) or [addr]
        st = core.read_stats(self.proc, addr, core.ALL_OFFSETS)
        self.stat_orig = dict(st)
        self.lbl_stats.config(text=f"{len(self.stat_blocks)} блок(а)", fg=ORANGE)
        self.e_hp.delete(0, "end"); self.e_hp.insert(0, f"{st['Макс. HP']:g}")
        self.e_dmg.delete(0, "end"); self.e_dmg.insert(0, f"{st['Урон от атаки']:g}")
        self._fill_stats(st, len(self.stat_blocks))
        self.log(f"  выбран блок 0x{addr:012X}\n", "green")

    def _fill_stats(self, vals, nblocks):
        self.lbl_stats.config(text=f"{nblocks} блок(а)", fg=ORANGE)
        for name, (cur, ent) in self.stat_rows.items():
            v = vals.get(name)
            cur.config(text=f"{v:.3f}" if v is not None else "—", fg=FG)
            ent.delete(0, "end")
            if v is not None:
                ent.insert(0, f"{v:g}")

    def _write_stat(self, name, value):
        off = dict(core.ALL_OFFSETS)[name]
        n = sum(1 for b in self.stat_blocks if core.write_f32(self.proc, b + off, value))
        return n, len(self.stat_blocks)

    def apply_stat(self, name):
        if not getattr(self, "stat_blocks", None):
            messagebox.showinfo("Сначала найдите блок", "Введите Макс. HP и нажмите «Найти».")
            return
        try:
            v = float(self.stat_rows[name][1].get().replace(",", "."))
        except ValueError:
            return
        n, tot = self._write_stat(name, v)
        self.log(f"[стат] {name} → {v:g}   ({n}/{tot})\n", "orange")
        self.stat_rows[name][0].config(text=f"{v:.3f}", fg=ORANGE)

    def apply_all_stats(self):
        if not getattr(self, "stat_blocks", None):
            messagebox.showinfo("Сначала найдите блок", "Введите Макс. HP и нажмите «Найти».")
            return
        self.log("\n[Боевые статы] применяю все\n", "orange")
        for name in self.stat_rows:
            try:
                v = float(self.stat_rows[name][1].get().replace(",", "."))
            except ValueError:
                continue
            n, tot = self._write_stat(name, v)
            self.log(f"  {name:<16} → {v:g}   ({n}/{tot})\n", "orange")
            self.stat_rows[name][0].config(text=f"{v:.3f}", fg=ORANGE)
        self.log("  перезапуск игры всё это сбросит — но добытое останется\n", "b")

    def restore_stats(self):
        if not getattr(self, "stat_blocks", None) or not getattr(self, "stat_orig", None):
            return
        self.log("\n[Боевые статы] возвращаю исходные\n", "green")
        for name, v in self.stat_orig.items():
            if v is None:
                continue
            n, tot = self._write_stat(name, v)
            self.log(f"  {name:<16} → {v:.3f}   ({n}/{tot})\n", "green")
        self._fill_stats(self.stat_orig, len(self.stat_blocks))

    # ── проверка ──────────────────────────────────────────────────────────
    def verify(self):
        if not self.applied:
            messagebox.showinfo("Нечего проверять", "Сначала примените изменение слева.")
            return
        self.log("\n── ожидание автосейва игры ─────────────────────────\n", "acc")
        self.bg(self._verify_work)

    def _wait_save(self, limit=330):
        m0 = core.save_mtime()
        t0 = time.time()
        while time.time() - t0 < limit:
            time.sleep(2)
            self.busy(f"жду автосейв… {int(time.time() - t0)} с")
            try:
                if core.save_mtime() != m0:
                    time.sleep(2)
                    return True
            except OSError:
                pass
        return False

    def _verify_work(self):
        if not self._wait_save():
            self.plog("  игра не сохранилась за 5.5 мин\n", "red")
            return
        self.plog(f"  игра записала сейв в {time.strftime('%H:%M:%S')}\n", "acc")
        try:
            _, inner = core.load_save()
        except Exception as e:
            self.plog(f"  ошибка чтения сейва: {e}\n", "red")
            return
        self.plog("  расшифровано, сверяю значения:\n", "mut")
        for a in self.applied:
            if a["kind"] == "attr":
                cur = next((x["Level"] for x in inner["attributeSaveDatas"]
                            if x["Key"] == a["key"]), None)
            else:
                cur = next((x["Level"] for x in inner["RuneSaveData"]
                            if x["RuneKey"] == a["key"]), None)
            ok = cur == a["target"]
            self.plog(f"    {a['label']}: было {a['before']}, ставили {a['target']}, "
                      f"в сейве {cur}   ", "mut")
            self.plog("ПРИНЯТО СЕРВЕРОМ\n" if ok else "откачено\n", "red" if ok else "green")
        self.plog("\n  Изменение записано самой игрой и переживёт перезапуск.\n"
                  "  Предупреждения о вмешательстве нет — клиент считает данные своими.\n", "b")
        self.post(self.refresh_state)

    # ── контроль ──────────────────────────────────────────────────────────
    def control_group(self):
        if not self._need():
            return
        self.log("\n── контроль: то, что защищено ──────────────────────\n", "acc")
        self.bg(self._control_work)

    def _control_work(self):
        self.busy("ищу валюту…")
        self.plog("Атакую золото тем же способом, что и характеристики.\n", "mut")
        hits = core.find_currency(self.proc)
        if not hits:
            self.plog("  объект валюты не найден\n", "red")
            return
        before = self.inner["currenySaveDatas"][0]["Quantity"]
        delta = 123456
        for a, q in hits:
            core.write_i64(self.proc, a, q + delta)
        self.plog(f"  найдено экземпляров: {len(hits)}, записал +{delta}\n", "mut")

        if not self._wait_save():
            self.plog("  игра не сохранилась\n", "red")
            return
        try:
            _, inner = core.load_save()
        except Exception as e:
            self.plog(f"  ошибка чтения: {e}\n", "red")
            return
        after = inner["currenySaveDatas"][0]["Quantity"]
        self.plog(f"  золото было {before:,} → в сейве {after:,}\n".replace(",", " "), "mut")
        if after - before < delta // 2:
            self.plog("  ЗАЩИТА СРАБОТАЛА — правка отброшена\n", "green")
            self.plog("  При сохранении игра создаёт новый объект с настоящим значением\n"
                      "  из защищённого хранилища и сериализует именно его.\n", "mut")
            self.plog("\n  Этот механизм у вас есть и он работает.\n"
                      "  К характеристикам и рунам он просто не применён.\n", "b")
        else:
            self.plog("  правка сохранилась — защита не сработала\n", "red")
        self.post(self.refresh_state)

    # ── откат ─────────────────────────────────────────────────────────────
    def revert_selected(self):
        sel = self.lst.curselection()
        if not sel or not self._need():
            return
        self._revert([self.applied[i] for i in sel])

    def revert_all(self):
        if self.cost_backup:
            self.restore_costs()
        if not self.applied or not self._need():
            return
        self._revert(list(self.applied))

    def _revert(self, items):
        self.log("\n── откат ───────────────────────────────────────────\n", "green")

        def work():
            for a in items:
                if a["before"] is None:
                    continue
                self.busy(f"откат {a['key']}…")
                done, total, _, addrs = core.patch_level(
                    self.proc, a["key"], a["before"], a.get("addrs"))
                self.cache[a["key"]] = addrs
                self.plog(f"  {a['label']}: {a['target']} → {a['before']}  ({done}/{total})\n",
                          "green")
                if a in self.applied:
                    self.applied.remove(a)
            self.post(self._refresh_applied)
            self.plog("  дождитесь автосейва, чтобы откат записался в сейв\n", "mut")
        self.bg(work)


# ══════════════════════════ запуск ═════════════════════════════════════════
def gate():
    root = tk.Tk()
    root.withdraw()
    try:
        fp = licensing.machine_fingerprint()
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось определить машину:\n{e}")
        return None

    key = licensing.load_key_file()
    err = None
    for _ in range(3):
        if key:
            try:
                info = licensing.check(key, fp)
                licensing.save_key_file(key)
                root.destroy()
                return info
            except licensing.LicenseError as e:
                err = str(e)
            except Exception as e:
                err = f"{type(e).__name__}: {e}"
        d = LicenseDialog(root, fp, err)
        root.wait_window(d)
        if not d.result:
            root.destroy()
            return None
        key = d.result
    root.destroy()
    messagebox.showerror("Доступ закрыт", "Ключ не принят.")
    return None


if __name__ == "__main__":
    info = gate()
    if info:
        Demo(info).mainloop()
