"""
keygen.py — выпуск ключей. Здесь лежит ПРИВАТНЫЙ ключ.

Эту папку не отдавать никому. Без приватного ключа выписать ключ невозможно,
поэтому утёкшая утилита бесполезна — в ней только публичная часть.

Первый запуск создаёт signing_key.pem и public_key.txt.
Значение из public_key.txt нужно вставить в licensing.py -> PUBLIC_KEY_HEX
(кнопка «Встроить публичный ключ в утилиту» делает это сама).
"""
import os, json, base64, time, sys
import tkinter as tk
from tkinter import ttk, messagebox

def app_dir():
    """Папка рядом с программой (в собранном exe — рядом с exe, не в распаковке)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


HERE = app_dir()
PRIV = os.path.join(HERE, "signing_key.pem")
PUB  = os.path.join(HERE, "public_key.txt")
LICENSING = os.path.join(os.path.dirname(HERE), "licensing.py")

BG, FG, MUT = "#12181A", "#E3EAEA", "#8FA0A2"
ACC, WARN = "#4EB0A9", "#D6A244"


# ─────────────────────────── ключи ──────────────────────────────────────────
def ensure_keypair():
    from Crypto.PublicKey import ECC
    if not os.path.exists(PRIV):
        k = ECC.generate(curve="ed25519")
        open(PRIV, "wt").write(k.export_key(format="PEM"))
        os.chmod(PRIV, 0o600)
    k = ECC.import_key(open(PRIV).read())
    # DER, а не raw: ECC.import_key принимает именно этот формат
    open(PUB, "w").write(k.public_key().export_key(format="DER").hex())
    return k


def public_hex():
    return open(PUB).read().strip()


GRACE = 90   # запас, чтобы свежий ключ был активен сразу, несмотря на расхождение часов


def issue(fingerprint, minutes, count, note=""):
    """Выпустить `count` последовательных окон по `minutes` минут."""
    from Crypto.Signature import eddsa
    key = ensure_keypair()
    signer = eddsa.new(key, "rfc8032")

    # Время берём из сети — тем же источником, которым его проверяет утилита.
    # Иначе часы генератора и проверяющей машины разъезжаются, и свежий ключ
    # оказывается "ещё не активен".
    sys.path.insert(0, os.path.dirname(HERE))
    try:
        import licensing
        start = licensing.network_time() or int(time.time())
    except Exception:
        start = int(time.time())
    start -= GRACE

    out = []
    for i in range(count):
        nbf = start + i * minutes * 60
        payload = json.dumps({
            "m": fingerprint.strip().upper(),
            "nbf": nbf,
            "exp": nbf + minutes * 60,
            "id": i + 1,
            "note": note.strip()[:60],
        }, separators=(",", ":"), ensure_ascii=False).encode()
        blob = payload + signer.sign(payload)
        out.append((i + 1, nbf, nbf + minutes * 60,
                    base64.b64encode(blob).decode()))
    return out


def embed_public_key():
    """Прописать публичный ключ в licensing.py собираемой утилиты."""
    ph = public_hex()
    src = open(LICENSING, encoding="utf-8").read()
    import re
    new, n = re.subn(r'PUBLIC_KEY_HEX\s*=\s*"[0-9a-fA-F]*"',
                     f'PUBLIC_KEY_HEX = "{ph}"', src, count=1)
    if not n:
        raise RuntimeError("не нашёл строку PUBLIC_KEY_HEX в licensing.py")
    open(LICENSING, "w", encoding="utf-8").write(new)
    return ph


# ─────────────────────────── интерфейс ──────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Генератор ключей — наглядный пример")
        self.configure(bg=BG)
        self.geometry("760x620")
        self.minsize(700, 560)

        st = ttk.Style(self)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure("TLabel", background=BG, foreground=FG, font=("Segoe UI", 10))
        st.configure("Hint.TLabel", foreground=MUT, font=("Segoe UI", 9))
        st.configure("H.TLabel", foreground=ACC, font=("Segoe UI", 12, "bold"))
        st.configure("TButton", font=("Segoe UI", 10))
        st.configure("TEntry", fieldbackground="#1B2325", foreground=FG)
        st.configure("TSpinbox", fieldbackground="#1B2325", foreground=FG)

        pad = {"padx": 14, "pady": 5}

        ttk.Label(self, text="Выпуск ключей доступа", style="H.TLabel").pack(anchor="w", **pad)
        ttk.Label(self, text="Приватный ключ хранится в этой папке и никуда не передаётся.",
                  style="Hint.TLabel").pack(anchor="w", padx=14)

        frm = tk.Frame(self, bg=BG)
        frm.pack(fill="x", **pad)

        ttk.Label(frm, text="Отпечаток машины (16 символов):").grid(row=0, column=0, sticky="w", pady=4)
        self.fp = ttk.Entry(frm, width=26, font=("Consolas", 11))
        self.fp.grid(row=0, column=1, sticky="w", padx=8)

        ttk.Label(frm, text="Минут на ключ:").grid(row=1, column=0, sticky="w", pady=4)
        self.mins = ttk.Spinbox(frm, from_=5, to=240, width=6, font=("Consolas", 11))
        self.mins.set(30)
        self.mins.grid(row=1, column=1, sticky="w", padx=8)

        ttk.Label(frm, text="Сколько ключей подряд:").grid(row=2, column=0, sticky="w", pady=4)
        self.cnt = ttk.Spinbox(frm, from_=1, to=48, width=6, font=("Consolas", 11))
        self.cnt.set(1)
        self.cnt.grid(row=2, column=1, sticky="w", padx=8)

        ttk.Label(frm, text="Пометка (необязательно):").grid(row=3, column=0, sticky="w", pady=4)
        self.note = ttk.Entry(frm, width=34)
        self.note.grid(row=3, column=1, sticky="w", padx=8)

        ttk.Label(self, text="Несколько ключей выдаются последовательными окнами: "
                             "второй начинает действовать, когда истёк первый.",
                  style="Hint.TLabel", wraplength=700).pack(anchor="w", padx=14, pady=(0, 4))

        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=14, pady=6)
        ttk.Button(bar, text="Выпустить ключи", command=self.on_issue).pack(side="left")
        ttk.Button(bar, text="Сохранить в файл…", command=self.on_save).pack(side="left", padx=6)
        ttk.Button(bar, text="Встроить публичный ключ в утилиту",
                   command=self.on_embed).pack(side="left", padx=6)

        self.out = tk.Text(self, bg="#0E1315", fg=FG, insertbackground=FG,
                           font=("Consolas", 9), wrap="none", relief="flat",
                           borderwidth=0, height=18)
        self.out.pack(fill="both", expand=True, padx=14, pady=(6, 4))
        self.out.tag_configure("hdr", foreground=ACC)
        self.out.tag_configure("warn", foreground=WARN)
        self.out.tag_configure("mut", foreground=MUT)

        self.status = ttk.Label(self, text="", style="Hint.TLabel")
        self.status.pack(anchor="w", padx=14, pady=(0, 8))

        try:
            ensure_keypair()
            self.log(f"Публичный ключ: {public_hex()}\n", "mut")
            embedded = 'PUBLIC_KEY_HEX = "%s"' % public_hex() in \
                       open(LICENSING, encoding="utf-8").read()
            if not embedded:
                self.log("Публичный ключ ещё НЕ встроен в утилиту — "
                         "нажмите «Встроить публичный ключ в утилиту».\n", "warn")
        except Exception as e:
            self.log(f"Ошибка инициализации: {e}\n", "warn")

    def log(self, text, tag=None):
        self.out.insert("end", text, tag or ())
        self.out.see("end")

    def on_issue(self):
        fp = self.fp.get().strip().upper()
        if len(fp) != 16 or any(c not in "0123456789ABCDEF" for c in fp):
            messagebox.showerror("Отпечаток", "Отпечаток — ровно 16 символов 0-9 A-F.\n"
                                              "Его печатает сама утилита при запуске без ключа.")
            return
        try:
            mins, cnt = int(self.mins.get()), int(self.cnt.get())
        except ValueError:
            messagebox.showerror("Параметры", "Минуты и количество — числа.")
            return

        keys = issue(fp, mins, cnt, self.note.get())
        self.issued = keys
        self.out.delete("1.0", "end")
        self.log(f"Машина {fp} · {cnt} ключ(ей) по {mins} мин\n", "hdr")
        self.log(f"Суммарное покрытие: {cnt*mins} мин\n\n", "mut")
        for n, nbf, exp, k in keys:
            self.log(f"── Ключ {n}  ", "hdr")
            self.log(f"{time.strftime('%H:%M', time.localtime(nbf))}"
                     f"–{time.strftime('%H:%M', time.localtime(exp))}\n", "mut")
            self.log(k + "\n\n")
        self.status.config(text=f"Выпущено {cnt} ключ(ей). "
                                f"Для одного ключа сохраните файл как license.key рядом с утилитой.")

    def on_save(self):
        if not getattr(self, "issued", None):
            messagebox.showinfo("Нечего сохранять", "Сначала выпустите ключи.")
            return
        from tkinter import filedialog
        if len(self.issued) == 1:
            p = filedialog.asksaveasfilename(initialfile="license.key",
                                             defaultextension=".key")
            if p:
                open(p, "w", encoding="utf-8").write(self.issued[0][3])
                self.status.config(text=f"Сохранено: {p}")
        else:
            d = filedialog.askdirectory(title="Папка для ключей")
            if d:
                for n, nbf, exp, k in self.issued:
                    open(os.path.join(d, f"license_{n:02d}.key"), "w",
                         encoding="utf-8").write(k)
                self.status.config(text=f"Сохранено {len(self.issued)} файлов в {d}")

    def on_embed(self):
        try:
            ph = embed_public_key()
            self.log(f"\nПубличный ключ встроен в licensing.py:\n{ph}\n", "hdr")
            self.status.config(text="Готово. Утилита теперь принимает ключи только этого генератора.")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))


if __name__ == "__main__":
    if "--cli" in sys.argv:
        fp = input("Отпечаток машины: ").strip().upper()
        mins = int(input("Минут на ключ [30]: ") or 30)
        cnt = int(input("Сколько ключей [1]: ") or 1)
        for n, nbf, exp, k in issue(fp, mins, cnt):
            print(f"\n── Ключ {n} "
                  f"({time.strftime('%H:%M', time.localtime(nbf))}"
                  f"–{time.strftime('%H:%M', time.localtime(exp))})\n{k}")
    else:
        App().mainloop()
