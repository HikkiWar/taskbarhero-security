#!/usr/bin/env python3
"""
F-09: NETWORK HIJACKING — Подмена переш cifрованного сейва
F-06 доказал: пароль ES3 СКОМПРОМЕТИРОВАН
Тест: расшифровать → модифицировать → переш cifровать → отправить
"""

import os
import json
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def decrypt_save(save_path, password):
    """
    Расшифровывает сейв используя PBKDF2-HMAC-SHA1 + AES-128-CBC
    (алгоритм из F-06)
    """
    try:
        with open(save_path, 'rb') as f:
            data = f.read()

        # Salt = IV = первые 16 байт
        salt = data[:16]
        encrypted = data[16:]

        print(f"[*] Расшифровка:")
        print(f"    Salt (hex): {salt.hex()[:32]}...")
        print(f"    Encrypted size: {len(encrypted)} байт")

        # Генерируем ключ
        key = PBKDF2(password, salt, 16, 100, 'sha1')
        print(f"    Key (hex): {key.hex()}")

        # Расшифровываем
        cipher = AES.new(key, AES.MODE_CBC, salt)
        decrypted = unpad(cipher.decrypt(encrypted), 16)

        print(f"[+] Успешно расшифровано: {len(decrypted)} байт")
        return decrypted, salt

    except Exception as e:
        print(f"[-] Ошибка расшифровки: {e}")
        return None, None

def encrypt_save(data, password, salt):
    """
    Переш cifрует сейв используя PBKDF2-HMAC-SHA1 + AES-128-CBC
    """
    try:
        print(f"[*] Переш cifровка:")
        print(f"    Size: {len(data)} байт")

        # Генерируем ключ (ТОТ ЖЕ, что при расшифровке)
        key = PBKDF2(password, salt, 16, 100, 'sha1')
        print(f"    Key (hex): {key.hex()}")

        # Переш cifруем
        padded = pad(data, 16)
        cipher = AES.new(key, AES.MODE_CBC, salt)
        encrypted = cipher.encrypt(padded)

        # Собираем файл: salt + encrypted
        result = salt + encrypted

        print(f"[+] Успешно переш cifровано: {len(result)} байт")
        return result

    except Exception as e:
        print(f"[-] Ошибка переш cifровки: {e}")
        return None

def find_value_in_binary(data, value, size=4):
    """
    Находит значение в бинарных данных
    """
    import struct

    if size == 4:
        pattern = struct.pack('<I', value)
    elif size == 8:
        pattern = struct.pack('<Q', value)
    else:
        return []

    positions = []
    start = 0
    while True:
        pos = data.find(pattern, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1

    return positions

def modify_value_in_binary(data, offset, new_value, size=4):
    """
    Модифицирует значение в бинарных данных
    """
    import struct

    data_list = bytearray(data)

    if size == 4:
        new_bytes = struct.pack('<I', new_value)
    elif size == 8:
        new_bytes = struct.pack('<Q', new_value)
    else:
        return data

    data_list[offset:offset + size] = new_bytes
    return bytes(data_list)

def main():
    print("=" * 70)
    print("F-09: NETWORK HIJACKING — Подмена переш cifрованного сейва")
    print("=" * 70)
    print()

    print("[КОНТЕКСТ ИЗ F-06]")
    print("  • Пароль ES3 СКОМПРОМЕТИРОВАН (извлечён в рантайме)")
    print("  • Алгоритм: PBKDF2-HMAC-SHA1(пароль, salt, 100, 16)")
    print("  • Шифр: AES-128-CBC + PKCS#7")
    print("  • Salt = IV = первые 16 байт файла")
    print()

    print("[ГИПОТЕЗА]")
    print("  Если можно расшифровать и переш cifровать сейв...")
    print("  ...то можно отправить модифицированные данные на сервер")
    print("  и сервер примет их как легитимный сейв?")
    print()

    print("[ШАГИ ТЕСТИРОВАНИЯ]")
    print()

    try:
        # Шаг 1: Загруз сейва
        save_path = input("1️⃣ Путь к сейву (напр. C:/Users/.../save.sav): ").strip()

        if not os.path.exists(save_path):
            print(f"[-] Файл не найден: {save_path}")
            return

        print(f"[*] Файл найден: {os.path.getsize(save_path)} байт")
        print()

        # Шаг 2: Пароль
        password_input = input("2️⃣ Пароль сейва ES3 (снято из F-06): ").strip()

        if not password_input:
            print("[-] Пароль не может быть пустым")
            return

        print()

        # Шаг 3: Расшифровка
        print("3️⃣ Расшифровка...")
        decrypted, salt = decrypt_save(save_path, password_input)

        if decrypted is None:
            return

        print()

        # Шаг 4: Анализ структуры
        print("4️⃣ Анализ расшифрованных данных:")
        print(f"    Размер: {len(decrypted)} байт")
        print(f"    Первые 64 байта (hex):")
        print(f"    {decrypted[:64].hex()}")
        print()

        # Шаг 5: Модификация
        print("5️⃣ МОДИФИКАЦИЯ значения:")
        print()
        print("   Известные позиции (из FINDINGS.md):")
        print("   • maxCompletedStage обычно в начале структуры")
        print("   • HeroExp для каждого героя")
        print("   • Gold (золото)")
        print()

        search_value = input("   Введите значение для поиска (напр. 1207 для maxCompletedStage): ")

        if search_value.isdigit():
            value = int(search_value)
            positions = find_value_in_binary(decrypted, value)

            print(f"   [*] Найдено {len(positions)} вхождений значения {value}")

            if positions:
                for i, pos in enumerate(positions[:5]):  # Показываем первые 5
                    print(f"      [{i+1}] Позиция: {pos:#x}")

                choice = input(f"   Выбрать позицию (1-{min(5, len(positions))}): ").strip()

                if choice.isdigit() and 1 <= int(choice) <= min(5, len(positions)):
                    pos_idx = int(choice) - 1
                    pos = positions[pos_idx]

                    new_value = input(f"   Новое значение (текущее {value}): ").strip()

                    if new_value.isdigit():
                        new_value = int(new_value)

                        print(f"   [*] Модифицируем: {pos:#x} = {value} → {new_value}")

                        modified = modify_value_in_binary(decrypted, pos, new_value)

                        # Сохраняем модифицированные данные
                        temp_path = save_path + ".modified"
                        with open(temp_path, 'wb') as f:
                            f.write(modified)

                        print(f"   [+] Сохранено: {temp_path}")
                        print()

                        # Шаг 6: Переш cifровка
                        print("6️⃣ Переш cifровка модифицированного сейва...")
                        encrypted = encrypt_save(modified, password_input, salt)

                        if encrypted is None:
                            return

                        # Сохраняем переш cifрованный сейв
                        hijacked_path = save_path + ".hijacked"
                        with open(hijacked_path, 'wb') as f:
                            f.write(encrypted)

                        print(f"   [+] Сохранено: {hijacked_path}")
                        print()

                        # Шаг 7: Инструкции
                        print("7️⃣ СЛЕДУЮЩИЕ ШАГИ:")
                        print("=" * 70)
                        print()
                        print(f"a) ЗАМЕНА ФАЙЛА:")
                        print(f"   • Найти папку сохранений TaskBarHero")
                        print(f"   • Обычно: C:\\Users\\<User>\\AppData\\LocalLow\\")
                        print(f"   • Скопировать {hijacked_path}")
                        print(f"   • На место оригинала {save_path}")
                        print()
                        print(f"b) В ИГРЕ:")
                        print(f"   • Запустить TaskBarHero")
                        print(f"   • Загрузить сейв")
                        print(f"   • Проверить: применилось ли изменение?")
                        print()
                        print(f"c) ПРОВЕРКА СОХРАНЕНИЯ:")
                        print(f"   • Дождаться 3 минут (автосейв)")
                        print(f"   • Полностью закрыть игру")
                        print(f"   • Расшифровать новый сейв (повторить скрипт)")
                        print(f"   • Проверить: осталось ли {value} → {new_value}?")
                        print()
                        print("[РЕЗУЛЬТАТ]")
                        print("  ✅ УЯЗВИМО (F-09 = CRITICAL):")
                        print(f"     Значение {value} → {new_value} пережило рестарт")
                        print("     Сервер принял подменённый сейв")
                        print()
                        print("  ❌ ЗАЩИТА (F-09 = safe):")
                        print("     Значение откатилось, сервер не принял")
                        print()
                        print("=" * 70)

                    else:
                        print("[-] Некорректное значение")

            else:
                print(f"[-] Значение {value} не найдено в сейве")

        else:
            print("[-] Введите цифру")

    except KeyboardInterrupt:
        print("\n[-] Отменено пользователем")
    except Exception as e:
        print(f"[-] Ошибка: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    print()
    print("[ТРЕБОВАНИЯ]")
    print("  pip install pycryptodome")
    print()

    main()
