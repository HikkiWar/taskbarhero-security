"""
licensing.py — проверка ключа. Здесь ТОЛЬКО публичный ключ.

Схема:
    ключ = base64( payload_json || signature_64 )
    payload = {"m": <отпечаток машины>, "nbf": <unix>, "exp": <unix>, "id": <n>, "note": str}
    подпись = Ed25519(приватный ключ генератора) по payload_json

Что схема даёт и чего не даёт — честно:

  ДАЁТ  Ключ невозможно подделать без приватного ключа. Утёкшая копия утилиты
        не может выписать себе новый ключ: подписывать нечем. Это настоящая
        асимметричная криптография, а не сравнение строк в коде.

  ДАЁТ  Ключ бесполезен на другой машине и после истечения срока.

  НЕ ДАЁТ  Защиту от того, кто пропатчит саму проверку. Любое клиентское
        решение "продолжать или нет" — это условный переход в бинарнике.
        Утверждать обратное было бы враньём: ровно этот класс проблем
        и описан в нашем отчёте по игре.

  Вывод: задача лицензии — остановить того, кто СЛУЧАЙНО получил утёкшую копию.
  Для этого достаточно. Тот, кто способен снять проверку, способен и переписать
  утилиту с нуля по отчёту — возможности здесь не являются секретом.
"""
import os, sys, json, base64, time, hashlib, subprocess, urllib.request, statistics, calendar


def app_dir():
    """Папка рядом с программой.

    В собранном exe (--onefile) __file__ указывает во временную папку распаковки,
    которая удаляется при выходе. Ключ надо искать рядом с самим exe.
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))

# Публичный ключ генератора (Ed25519 в DER, hex).
# Подставляется из keygen/public_key.txt при выпуске сборки.
PUBLIC_KEY_HEX = "302a300506032b6570032100cd4b007060eddc26da69713d0c39a81d65fe6942938477599a5aaf8edb4ff395"

KEY_FILE = os.path.join(app_dir(), "license.key")
_CLOCK_SKEW_TOLERANCE = 6 * 3600   # локальные часы дальше этого от сети -> подозрительно


# ───────────────────────── отпечаток машины ─────────────────────────────────
def _wmi(cls, prop, where=None):
    q = f"(Get-CimInstance {cls}"
    if where:
        q += f" -Filter \"{where}\""
    q += f" | Select-Object -First 1).{prop}"
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", q],
                           capture_output=True, text=True, timeout=25,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        return r.stdout.strip()
    except Exception:
        return ""


def machine_fingerprint() -> str:
    """Отпечаток из четырёх независимых источников. 16 hex-символов."""
    parts = []
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as k:
            parts.append(winreg.QueryValueEx(k, "MachineGuid")[0])
    except Exception:
        parts.append("")
    parts.append(_wmi("Win32_ComputerSystemProduct", "UUID"))
    parts.append(_wmi("Win32_Processor", "ProcessorId"))
    parts.append(_wmi("Win32_LogicalDisk", "VolumeSerialNumber", "DeviceID='C:'"))

    if not any(p for p in parts):
        raise RuntimeError("не удалось собрать отпечаток машины")
    blob = "|".join(p.strip() for p in parts).encode()
    return hashlib.sha256(blob).hexdigest()[:16].upper()


# ───────────────────────── сетевое время ────────────────────────────────────
def network_time():
    """Unix-время из сети. Медиана нескольких источников. None если сеть недоступна.

    Локальные часы намеренно не используются как источник истины: их можно
    перевести назад. Сеть обязательна.
    """
    os.environ.pop("SSLKEYLOGFILE", None)   # мешает ssl в этом окружении
    stamps = []

    # calendar.timegm, а НЕ mktime()-timezone: mktime трактует struct как локальное
    # время и учитывает DST, из-за чего результат уезжает на час и более.
    try:
        r = urllib.request.urlopen(
            "https://timeapi.io/api/Time/current/zone?timeZone=UTC", timeout=8)
        d = json.loads(r.read())
        stamps.append(calendar.timegm(time.strptime(d["dateTime"][:19], "%Y-%m-%dT%H:%M:%S")))
    except Exception:
        pass

    for url in ("https://www.cloudflare.com/cdn-cgi/trace",
                "https://www.microsoft.com",
                "https://www.google.com"):
        try:
            r = urllib.request.urlopen(url, timeout=8)
            hdr = r.headers.get("Date")          # RFC 7231, всегда GMT
            if hdr:
                stamps.append(calendar.timegm(
                    time.strptime(hdr, "%a, %d %b %Y %H:%M:%S %Z")))
        except Exception:
            pass

    if not stamps:
        return None
    # медиана устойчива к одному соврамшему источнику
    return int(statistics.median(stamps))


# ───────────────────────── проверка ключа ───────────────────────────────────
class LicenseError(Exception):
    pass


def _verify_signature(payload: bytes, sig: bytes):
    from Crypto.Signature import eddsa
    from Crypto.PublicKey import ECC
    if set(PUBLIC_KEY_HEX) <= {"0"}:
        raise LicenseError("сборка без публичного ключа — встройте его через keygen")
    pub = ECC.import_key(bytes.fromhex(PUBLIC_KEY_HEX))
    eddsa.new(pub, "rfc8032").verify(payload, sig)


def parse_key(key_text: str) -> dict:
    raw = base64.b64decode(key_text.strip().replace("\n", "").replace(" ", ""))
    if len(raw) <= 64:
        raise LicenseError("ключ повреждён")
    payload, sig = raw[:-64], raw[-64:]
    try:
        _verify_signature(payload, sig)
    except LicenseError:
        raise
    except Exception:
        raise LicenseError("подпись недействительна — ключ подделан или не от этого генератора")
    return json.loads(payload.decode())


def check(key_text: str, fingerprint: str = None) -> dict:
    """Полная проверка. Возвращает {'ok':True,'expires_in':сек,'payload':…} либо бросает."""
    data = parse_key(key_text)

    fp = fingerprint or machine_fingerprint()
    if data.get("m") != fp:
        raise LicenseError(f"ключ выписан для другой машины\n"
                           f"  в ключе : {data.get('m')}\n"
                           f"  эта ПК  : {fp}")

    now = network_time()
    if now is None:
        raise LicenseError("нет доступа к интернету — время проверить нечем.\n"
                           "Ключ привязан к сетевому времени и работать без него не будет.")

    local = int(time.time())
    if abs(local - now) > _CLOCK_SKEW_TOLERANCE:
        raise LicenseError(f"локальные часы разошлись с сетевым временем "
                           f"на {abs(local-now)//3600} ч — проверьте настройки времени")

    if now < data.get("nbf", 0):
        raise LicenseError(f"ключ ещё не активен, начнёт действовать через "
                           f"{(data['nbf']-now)//60} мин")
    if now >= data.get("exp", 0):
        raise LicenseError(f"срок ключа истёк "
                           f"{(now-data['exp'])//60} мин назад")

    return {"ok": True, "expires_in": data["exp"] - now, "payload": data, "now": now}


def load_key_file(path=KEY_FILE):
    if not os.path.exists(path):
        return None
    txt = open(path, encoding="utf-8").read().strip()
    return txt or None


def save_key_file(key_text, path=KEY_FILE):
    open(path, "w", encoding="utf-8").write(key_text.strip())


if __name__ == "__main__":
    print("Отпечаток этой машины:", machine_fingerprint())
    print("Передайте его тому, кто выпускает ключи.")
    t = network_time()
    print("Сетевое время:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) if t else "НЕДОСТУПНО")
