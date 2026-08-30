#!/usr/bin/env python3
"""
TaskBarHero Security Testing — Master Test Runner
Запускает все 4 непроверённых вектора атак по приоритету
"""

import os
import sys
import subprocess
import time

TESTS = [
    {
        'num': 1,
        'name': 'Drop Probability',
        'file': 'test_drop_probability.py',
        'severity': 'MEDIUM',
        'time': '1-2ч',
        'description': 'Поиск и модификация таблицы весов дропа редких предметов'
    },
    {
        'num': 2,
        'name': 'Cube Synthesis',
        'file': 'test_cube_synthesis.py',
        'severity': 'HIGH',
        'time': '2-3ч',
        'description': 'Проверка отрицательной цены при синтезе кубов (как F-01)'
    },
    {
        'num': 3,
        'name': 'Rare Box Rolls',
        'file': 'test_rare_boxes.py',
        'severity': 'HIGH',
        'time': '2-3ч',
        'description': 'Подмена типа сундука (910651→920651)'
    },
    {
        'num': 4,
        'name': 'Network Hijacking',
        'file': 'test_network_hijacking.py',
        'severity': 'CRITICAL',
        'time': '3-4ч',
        'description': 'Подмена переш cifрованного сейва (F-06 пароль известен)'
    }
]

def print_header():
    print()
    print("=" * 80)
    print(" " * 15 + "TaskBarHero — SECURITY TESTING SUITE")
    print(" " * 20 + "Непроверённые векторы атак (F-09...F-12)")
    print("=" * 80)
    print()

def print_test_menu():
    print()
    print("📋 ДОСТУПНЫЕ ТЕСТЫ:")
    print()
    for test in TESTS:
        print(f"  [{test['num']}] {test['name']:25} | {test['severity']:8} | {test['time']}")
        print(f"      {test['description']}")
        print()

def print_test_info(test):
    print()
    print("=" * 80)
    print(f" [{test['num']}] {test['name'].upper()}")
    print("=" * 80)
    print()
    print(f"Severity:     {test['severity']}")
    print(f"Est. Time:    {test['time']}")
    print(f"Script:       {test['file']}")
    print()
    print(test['description'])
    print()

def run_test(test):
    """
    Запускает тестовый скрипт
    """
    script_path = os.path.join(os.path.dirname(__file__), test['file'])

    if not os.path.exists(script_path):
        print(f"[-] Скрипт не найден: {script_path}")
        return False

    print(f"[*] Запуск: python {test['file']}")
    print()

    try:
        subprocess.run([sys.executable, script_path], check=False)
        return True
    except Exception as e:
        print(f"[-] Ошибка при запуске: {e}")
        return False

def print_summary():
    print()
    print("=" * 80)
    print(" ИТОГИ ТЕСТИРОВАНИЯ")
    print("=" * 80)
    print()
    print("Документы для анализа результатов:")
    print("  • UNCHECKED_VECTORS.md        — Подробный анализ")
    print("  • TEST_PROTOCOL_UNCHECKED.md  — Полный протокол")
    print("  • QUICK_SUMMARY.txt           — Краткая сводка")
    print()
    print("Результаты заносить в FINDINGS.md как F-09, F-10, F-11, F-12")
    print()

def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    print_header()

    print("⚠️ РЕЖИМЫ ЗАПУСКА:")
    print()
    print("  [0] Меню (выбор тестов)")
    print("  [1] Все тесты по порядку (1→2→3→4)")
    print("  [2] Быстрый режим (только 1,2,4 - пропустить 3)")
    print("  [3] Выход")
    print()

    choice = input("Выберите режим (0-3): ").strip()

    if choice == '3':
        print("Выход.")
        return

    if choice == '0':  # Меню
        while True:
            print_test_menu()

            user_choice = input("Выберите тест (1-4, 0=назад): ").strip()

            if user_choice == '0':
                continue

            if user_choice.isdigit() and 1 <= int(user_choice) <= 4:
                test_num = int(user_choice) - 1
                test = TESTS[test_num]

                print_test_info(test)
                confirm = input("Запустить этот тест? (y/n): ").strip().lower()

                if confirm == 'y':
                    run_test(test)

                input("\nНажмите Enter для продолжения...")

            else:
                print("[-] Некорректный выбор")
                input("Нажмите Enter для продолжения...")

    elif choice == '1':  # Все тесты
        print("[*] Запуск ВСЕх тестов по порядку...")
        print()

        for test in TESTS:
            print_test_info(test)
            confirm = input("Запустить? (y/n/skip): ").strip().lower()

            if confirm == 'y':
                if run_test(test):
                    print(f"[+] {test['name']} завершён")
                else:
                    print(f"[-] {test['name']} завершился с ошибкой")

                input("\nНажмите Enter для следующего теста...")

            elif confirm == 'skip':
                print(f"[*] Пропущен: {test['name']}")
                continue

            else:
                print("Отменено")
                break

        print_summary()

    elif choice == '2':  # Быстрый режим
        print("[*] Быстрый режим: 1, 2, 4 (пропуск 3)")
        print()

        for test_num in [0, 1, 3]:  # 1, 2, 4
            test = TESTS[test_num]

            print_test_info(test)
            confirm = input("Запустить? (y/n): ").strip().lower()

            if confirm == 'y':
                if run_test(test):
                    print(f"[+] {test['name']} завершён")
                else:
                    print(f"[-] {test['name']} завершился с ошибкой")

                input("\nНажмите Enter для следующего теста...")
            else:
                print("Пропущен")

        print_summary()

    else:
        print("[-] Некорректный выбор")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Прервано пользователем")
    except Exception as e:
        print(f"\n[-] Ошибка: {e}")
        import traceback
        traceback.print_exc()
