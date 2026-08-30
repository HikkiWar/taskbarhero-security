# Цепочка экипировки TaskBarHero

Получена методом исключения: вооружили 2823 метода игрового кода одноразовыми точками останова, отсеяли 631 фоновый, затем одна смена снаряжения высветила 15 оставшихся.

## Что стабильно, а что нет

**Имена стабильны.** GUPS обфусцирует на этапе сборки, а не при запуске, поэтому `icd`, `hpu`, `lii` вшиты в бинарник и одинаковы между сессиями.

**Адреса плывут** из-за ASLR — храним смещения от базы `GameAssembly.dll`.

**Всё привязано к конкретной сборке игры.** При обновлении смещения и, возможно, имена изменятся. Контрольная сумма ниже позволяет это заметить.

- размер `GameAssembly.dll`: 107 678 720 байт
- sha256: `2a13147ee5a0fbe7c453b812dc1450b08a2187ab960e0d31fe7faddad40121ff`
- база при выгрузке таблицы: `0x7FFB38A60000`

## Порядок вызовов

| # | Метод | Смещение |
|---|---|---|
| 1 | `TaskbarHero.UI.ExtraStatDetail::lpv(p=1)` | `0xA1E1A0` |
| 2 | `TaskbarHero.Data.StatModInfoData::mlx(p=0)` | `0xA9F3C0` |
| 3 | `TaskbarHero.UI.InventorySlot::hre(p=0)` | `0xA0F040` |
| 4 | `TaskbarHero.DragData::.ctor(p=3)` | `0x846E00` |
| 5 | `TaskbarHero.DragData::hpu(p=2)` | `0x846ED0` |
| 6 | `TaskbarHero.SlotInteractionManager::icd(p=1)` | `0x878680` |
| 7 | `TaskbarHero.UI.GearSlot::hrf(p=0)` | `0xA0A980` |
| 8 | `TaskbarHero.ValidationResult::hzy(p=0)` | `0x882890` |
| 9 | `TaskbarHero.UI_Hero::hmp(p=0)` | `0x85A290` |
| 10 | `TaskbarHero.UI.GearSlot::lii(p=1)` | `0xA0AC70` |
| 11 | `TaskbarHero.UI.GearSlot::lil(p=1)` | `0xA0B380` |
| 12 | `TaskbarHero.UI.GearSlot::lin(p=0)` | `0xA0B640` |
| 13 | `TaskbarHero.UI_Hero::hng(p=1)` | `0x85C4C0` |
| 14 | `TaskbarHero.MoveResult::iaa(p=1)` | `0x875AF0` |
| 15 | `TaskbarHero.UI.GearSlot::lit(p=0)` | `0xA0BAD0` |
| 16 | `TaskbarHero.StageManager::ihp(p=2)` | `0x880A80` |
| 17 | `TaskbarHero.StageManager::ihm(p=1)` | `0x880740` |
| 18 | `TaskbarHero.Log.GetBoxLog::.ctor(p=2)` | `0x9B5F30` |
| 19 | `TaskbarHero.Log.GetBoxLog::khx(p=0)` | `0x9B6080` |
| 20 | `TaskbarHero.Data.LogColorSettings::mmw(p=1)` | `0xAE03B0` |
| 21 | `TaskbarHero.StageManager::ifk(p=6)` | `0x87AA60` |
| 22 | `TaskbarHero.StageManager::iga(p=0)` | `0x87C250` |
| 23 | `TaskbarHero.StageManager::igb(p=0)` | `0x87C2C0` |
| 24 | `TaskbarHero.Unit::guz(p=0)` | `0xBF7E10` |
| 25 | `TaskbarHero.WindowManager::hir(p=0)` | `0xC21A90` |
| 26 | `TaskbarHero.WindowManager::hjl(p=1)` | `0xC22ED0` |
| 27 | `TaskbarHero.WindowManager::hjm(p=1)` | `0xC22F10` |
| 28 | `TaskbarHero.WindowManager::hiu(p=2)` | `0xC21C10` |
| 29 | `TaskbarHero.WindowManager::hif(p=1)` | `0xC20A50` |
| 30 | `TaskbarHero.ToastManager::kfa(p=0)` | `0x9C4090` |
| 31 | `TaskbarHero.ToastMessage::hsd(p=1)` | `0x8552E0` |
| 32 | `TaskbarHero.UI.LogTopBottomChanger::mbf(p=0)` | `0xA56C80` |
| 33 | `TaskbarHero.UI.LogTopBottomChanger::mbg(p=1)` | `0xA56D00` |
| 34 | `TaskbarHero.UI.UI_Log::lsy(p=1)` | `0xA3B0D0` |
| 35 | `TaskbarHero.UI.UI_Log::lsz(p=1)` | `0xA3B110` |
| 36 | `TaskbarHero.WindowManager::his(p=0)` | `0xC21AB0` |
| 37 | `TaskbarHero.WindowManager::hjo(p=1)` | `0xC23770` |
| 38 | `TaskbarHero.WindowManager::hix(p=2)` | `0xC223A0` |
| 39 | `TaskbarHero.WindowManager::hiq(p=0)` | `0xC21990` |
| 40 | `TaskbarHero.WindowManager::hip(p=0)` | `0xC21830` |

## Как читается цепочка

Три класса обфускация не тронула, и они называют архитектуру сами:

```
DragData              захват предмета мышью
SlotInteractionManager обработка взаимодействия слотов
ValidationResult      решение, допустимо ли перемещение
MoveResult            применённый результат
```

Отсюда вывод, объясняющий все неудачные попытки правки: массив `equippedItemIds` — последнее звено, он лишь перерисовывается. Источник истины — обработанный запрос, а не массив.

Главный кандидат на вызов извне — `SlotInteractionManager::icd(p=1)`: один аргумент, срабатывает между захватом и валидацией.

## Как восстановить адреса в новой сессии

```python
current = module_base(pid, 'GameAssembly.dll')
addr = current + offset      # offset из таблицы выше
```

Если sha256 файла не совпал с записанной — игра обновилась, таблицу надо снимать заново (`dumpmethods.dll`).
