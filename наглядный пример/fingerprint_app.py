"""
fingerprint_app.py — показать отпечаток этой машины, чтобы передать его
тому, кто выпускает ключи.

Отдельная программа: тестировщику не нужно запускать саму утилиту, чтобы
узнать свой ID.
"""
import sys, os, threading
import tkinter as tk
from tkinter import ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import licensing

BG, PANEL, FG, MUT, ACC = "#0E1315", "#151C1E", "#E3EAEA", "#8FA0A2", "#4EB0A9"
RED, GREEN = "#E2685E", "#63AF81"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Отпечаток машины")
        self.configure(bg=BG)
        self.geometry("620x330")
        self.resizable(False, False)

        tk.Label(self, text="Отпечаток этой машины", bg=BG, fg=ACC,
                 font=("Segoe UI", 15, "bold")).pack(anchor="w", padx=24, pady=(22, 4))
        tk.Label(self, text="Передайте этот код тому, кто выпускает ключи доступа.\n"
                            "Ключ будет работать только на этом компьютере.",
                 bg=BG, fg=MUT, font=("Segoe UI", 10), justify="left").pack(
            anchor="w", padx=24)

        self.var = tk.StringVar(value="считаю…")
        self.ent = tk.Entry(self, textvariable=self.var, font=("Consolas", 26),
                            bg=PANEL, fg=ACC, relief="flat", justify="center",
                            width=18, readonlybackground=PANEL)
        self.ent.pack(pady=18, ipady=8)

        bar = tk.Frame(self, bg=BG)
        bar.pack()
        self.btn = tk.Button(bar, text="Копировать", command=self.copy, relief="flat",
                             bg=ACC, fg=BG, activebackground=GREEN, cursor="hand2",
                             font=("Segoe UI", 11, "bold"), padx=24, pady=7)
        self.btn.pack(side="left")
        tk.Button(bar, text="Закрыть", command=self.destroy, relief="flat",
                  bg="#283537", fg=FG, cursor="hand2",
                  font=("Segoe UI", 11), padx=18, pady=7).pack(side="left", padx=10)

        self.status = tk.Label(self, text="", bg=BG, fg=MUT, font=("Segoe UI", 9))
        self.status.pack(pady=(14, 0))

        threading.Thread(target=self._calc, daemon=True).start()

    def _calc(self):
        try:
            fp = licensing.machine_fingerprint()
            self.after(0, lambda: self._done(fp))
        except Exception as e:
            self.after(0, lambda: self._fail(str(e)))

    def _done(self, fp):
        self.var.set(fp)
        self.ent.configure(state="readonly")
        t = licensing.network_time()
        if t:
            import time
            self.status.config(
                text="сетевое время: "
                     + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)), fg=MUT)
        else:
            self.status.config(text="нет интернета — утилита без него не запустится", fg=RED)

    def _fail(self, msg):
        self.var.set("ошибка")
        self.status.config(text=msg, fg=RED)

    def copy(self):
        self.clipboard_clear()
        self.clipboard_append(self.var.get())
        self.status.config(text="скопировано в буфер обмена", fg=GREEN)


if __name__ == "__main__":
    App().mainloop()
