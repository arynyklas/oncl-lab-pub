# Тестовые векторы TUF (оракул python-tuf)

Каталог содержит TUF-репозитории, собранные **эталонной реализацией python-tuf** (`tuf==7.0.1`), а не
нашим кодом: Rust-верификатор `oncl-update` проверяется ими независимо от самого себя.

- `valid/` — корректный репозиторий в раскладке контракта (корень сайта `…/tuf/v1/`):
  `metadata/{1,2,3}.root.json`, `metadata/timestamp.json`, `metadata/2.snapshot.json`,
  `metadata/2.targets.json`, `targets/indexes/<sha256>.stable.json` и `….beta.json`
  (`consistent_snapshot: true`). Цели — `indexes/stable.json` и `indexes/beta.json`
  (маленькие синтетические индексы). Пакеты в репозиторий не входят.
- `<имя-атаки>/` — минимальные мутации `valid/` (полная копия с изменёнными файлами). В каждом лежит
  `expected.json`: шаг, на котором клиент обязан отказать (`must_fail_at`), класс ошибки словами
  (`error_class`), изменённые файлы (`changed_files_vs_valid`), предыдущее состояние клиента
  (`prior_state`) и вердикт python-tuf.
- `keys.json` — id, публичные ключи и сиды всех **синтетических тестовых ключей** (шесть репозитория
  `valid/` и шесть делегированных репозиториев). Они сгенерированы только для тестов, нигде не
  используются и не имеют отношения к реальным ключам проекта: `seed = sha256("oncl-tuf-oracle-v1/" + имя)`.
- `delegated-*/` и `cross-repo/` — репозитории с делегированными ролями издателей (раздел
  «Делегированные векторы» ниже).

## Контракт, который воспроизводят векторы

Ed25519 (`keytype`/`scheme` = `ed25519`); `keyid` — hex sha256 канонического JSON (OLPC) объекта
ключа `{keytype, scheme, keyval:{public}}`; подпись — над каноническим JSON объекта `signed`.

| Корень | root | targets | snapshot | timestamp |
|---|---|---|---|---|
| v1 | `root-a` | `targets` | `snapshot` | `timestamp-1` |
| v2 | `root-a` | `targets` | `snapshot` | `timestamp-2` (ротация) |
| v3 | `root-b` (ротация, подписан `root-a` и `root-b`) | `targets` | `snapshot` | `timestamp-2` |

Порог каждой роли — 1. Доверенный якорь клиента — `valid/metadata/1.root.json`. Все файлы подписаны
в `2026-11-15T00:00:00Z`; **часы проверки фиксированы**: `2026-11-16T00:00:00Z` (`now` в
`expected.json`). Сроки: root 365 дней, targets и snapshot 30, timestamp 7. `version` timestamp —
Unix-время подписи (`1794700800`); snapshot и targets в `valid/` версии 2 (версии 1 лежат только в
репозиториях откатов). В реальном репозитории `timestamp.json` не коммитится; здесь он есть, чтобы
вектор был самодостаточным. В метаданных `snapshot`/`timestamp` указаны только `version` (без `length`
и `hashes`).

Отрицательные репозитории с `prior_state` (откаты) проверяются так: сначала клиент полностью
принимает `valid/` на тех же часах, затем получает репозиторий атаки с тем же локальным состоянием.
Пара файлов откатов:

- `rollback-timestamp`: `metadata/timestamp.json` с версией `1794697200` (< `1794700800`).
- `rollback-snapshot`: `metadata/timestamp.json` версии `1794704400`, указывающий на snapshot v1, и
  `metadata/1.snapshot.json` (+ `1.targets.json`) после принятого snapshot v2.
- `rollback-targets`: `metadata/timestamp.json` версии `1794708000`, `metadata/3.snapshot.json` с
  записью `targets.json` версии 1 и `metadata/1.targets.json` после принятого targets v2.

## Перегенерация

```sh
python3 -m venv /mnt/d/oncl-tuf-venv        # WSL Ubuntu
/mnt/d/oncl-tuf-venv/bin/pip install tuf==7.0.1 cryptography==50.0.2
/mnt/d/oncl-tuf-venv/bin/python xtask/assets/tuf-oracle/gen.py
```

Скрипт детерминирован (ключи из фиксированных сидов, подписи Ed25519 детерминированы): повторный
запуск не меняет ни байта. Он пересоздаёт все каталоги репозиториев, затем прогоняет
`tuf.ngclient.Updater` через локальный `http.server` по каждому репозиторию и печатает таблицу
вердиктов. Код выхода ненулевой, если вердикт python-tuf отличается от ожидаемого.

## Вердикты python-tuf (`tuf==7.0.1`)

| Репозиторий | python-tuf | Где отказал |
|---|---|---|
| `valid` | принят, оба индекса скачаны | — |
| `expired-timestamp` | отказ | timestamp: `ExpiredMetadataError` |
| `expired-snapshot` | отказ | snapshot: `ExpiredMetadataError` |
| `expired-targets` | отказ | targets: `ExpiredMetadataError` |
| `rollback-timestamp` | отказ | `BadVersionNumberError` |
| `rollback-snapshot` | отказ | `BadVersionNumberError` |
| `rollback-targets` | отказ | targets: `BadVersionNumberError` |
| `bad-signature-targets` | отказ | `UnsignedMetadataError` |
| `threshold-not-met` | отказ | root: `UnsignedMetadataError` (1 из 2) |
| `wrong-keyid-in-root` | **принят** (расхождение с контрактом, см. ниже) | — |
| `tampered-unknown-field` | отказ | `UnsignedMetadataError` |
| `target-hash-mismatch` | отказ | цель: `LengthOrHashMismatchError` |
| `target-length-mismatch` | отказ | цель: `DownloadLengthMismatchError` |
| `root-version-gap` | отказ | root: `BadVersionNumberError` |
| `new-root-signed-only-by-new-keys` | отказ | root: `UnsignedMetadataError` |

## Чем python-tuf отличается от контракта

Прохождение python-tuf **не означает** прохождения контракта проекта. Python-tuf шире нашего клиента:

- **`keyid` не проверяется.** `wrong-keyid-in-root` python-tuf принимает; наш клиент обязан отказать
  (пересчитывает sha256 канонической формы и сверяет с ключом словаря `keys`). Для этого вектора
  ожидание — отказ по контракту, а не по python-tuf.
- Принимает RSA, ECDSA и другие `keytype`/`scheme` (в т. ч. устаревшие), наш клиент — только `ed25519`.
- Выполняет делегирования любой глубины и формы; наш клиент в профиле `Legacy` отказывает с явной
  ошибкой, если в targets есть `delegations`, а в профиле `Delegating` принимает только один уровень
  ролей `pub-<имя>` (раздел «Делегированные векторы»).
- Принимает хеши, кроме sha256, и `path_hash_prefixes`; наш клиент — только sha256, без префиксов.
- Не требует `consistent_snapshot: true` и принимает любые пороги у любых ролей.
- Не знает про индекс: `channel`, `seq` и срок `MAX_AGE` (который в режиме TUF у нас не применяется)
  вне его компетенции; пакеты и их sha256/размер он тоже не проверяет.
- Лимиты размеров и число ротаций root (`UpdaterConfig`) — свои, не наши.
- Часы подставляются из скрипта (`reference_time`); клиент по умолчанию берёт системные.
- Для откатов python-tuf может отказать на другом шаге, чем строго требует спецификация
  (`rollback-targets`: на шаге targets, а не snapshot); `must_fail_at` допускает оба.

## Делегированные векторы

Раскладка `tuf/v2` из `docs/design/publishers.md`. Свой корень (`delegated-valid/metadata/1.root.json`,
он же доверенный якорь каждого делегированного вектора): ключи `v2-root`, `v2-snapshot`,
`v2-timestamp` и общий с `valid/` ключ `targets`. Верхний `targets` версии 1 перечисляет оба индекса
и `publishers.json` и делегирует `pub-alpha` (ключ `pub-alpha`, `paths: ["plugins/alpha/*/*"]`) и
`pub-beta` (ключ `pub-beta`, `plugins/beta/*/*`), обе роли `terminating`, порог 1. Роль `pub-alpha`
версии 2 перечисляет `plugins/alpha/kz.alpha.signer/1.0.0.onclp`, `pub-beta` версии 1 —
`plugins/beta/kz.beta.tool/2.1.0.onclp` (с `custom.oncl`; пакеты в репозиторий не входят).
Snapshot версии 1 перечисляет `targets.json` и каждую роль с `version`, `length` и `hashes`.
Часы и сроки те же, что у `valid/`.

Эти файлы пишутся как JSON и подписываются по канонической форме самим скриптом, а не моделью
python-tuf: модель не построила бы повтор имени роли или имя верхней роли. python-tuf их только
читает: `Updater.refresh()`, скачивание целей верхнего `targets`, затем `get_targetinfo` по каждому
пути из `probes` в `expected.json`. В `expected.json` лежат `contract` (что обязан сделать наш
клиент, `refresh` и `delegated`) и `python_tuf` (что python-tuf сделал на самом деле).

| Вектор | python-tuf (`tuf==7.0.1`) | наш клиент (контракт) |
|---|---|---|
| `delegated-valid` | обе цели найдены | обе роли проверены |
| `delegated-bad-signature` | `pub-beta`: `UnsignedMetadataError` | `pub-beta` недоступна (подпись), `pub-alpha` проверена |
| `delegated-threshold-not-met` (2 из 2, подпись одна) | `pub-beta`: `UnsignedMetadataError` | `pub-beta` недоступна (подпись) |
| `delegated-version-mismatch` | `pub-beta`: `BadVersionNumberError` | `pub-beta` недоступна (версия) |
| `delegated-hash-mismatch` | `pub-beta`: `LengthOrHashMismatchError` | `pub-beta` недоступна (хеш) |
| `delegated-expired` | `pub-beta`: `ExpiredMetadataError` | `pub-beta` недоступна (срок) |
| `delegated-rollback` (двухшаговый, после `delegated-valid`) | `refresh`: `BadVersionNumberError` на snapshot | `refresh` отказывает на snapshot (откат `pub-alpha.json`, 5.5.5) |
| `delegated-not-in-snapshot` | `pub-beta`: `RepositoryError` | `pub-beta` недоступна (нет в снимке) |
| `delegated-removed` | цель `pub-beta` не найдена | роли `pub-beta` нет (издатель отозван) |
| `delegated-path-outside` | чужая цель не найдена, своя найдена | `pub-beta` недоступна (цель вне путей; строже) |
| `delegated-nested` | идёт вглубь, цель `pub-beta-sub` найдена | `pub-beta` недоступна (вложенные делегирования; строже) |
| `delegated-path-hash-prefixes` | цель найдена | `pub-beta` недоступна (строже) |
| `delegated-key-reuse` (`pub-beta` на ключе верхнего `targets`) | цель найдена | `pub-beta` недоступна (ключ корня; строже) |
| `delegated-glob-depth` (лишний сегмент пути) | цель с лишним сегментом не найдена | `pub-alpha` недоступна (цель вне путей) |
| `delegated-duplicate-role` | `refresh`: `DeserializationError` (`ValueError: Duplicate role pub-beta`) | `refresh` отказывает на targets (`Malformed`) |
| `delegated-top-level-name` (роль `timestamp`) | `refresh`: `DeserializationError` (`ValueError: Delegated roles cannot be empty or use top-level role names`) | `refresh` отказывает на targets (`Malformed`) |
| `cross-repo` (файлы `valid/` за корнем `delegated-valid`) | `refresh`: `UnsignedMetadataError` на timestamp | `refresh` отказывает по подписи timestamp, до сохранения |

Что векторы установили о python-tuf 7.0.1:

- `*` в `paths` сопоставляется по сегментам: путь и шаблон режутся по `/`, число сегментов обязано
  совпасть, каждый сегмент сравнивается `fnmatch` (`delegated-glob-depth`).
- Повтор имени роли и имя верхней роли в `delegations` отвергаются при разборе верхнего `targets`, и
  весь `refresh` падает (`DeserializationError`).
- Ошибка делегированной роли (подпись, порог, версия, хеш, срок, нет в снимке) не роняет `refresh`:
  она вылетает исключением из `get_targetinfo` той цели, чей поиск дошёл до этой роли; цели других
  ролей находятся. Роль, которой нет в `delegations`, не скачивается.
- Цель вне путей роли python-tuf молча не находит, вложенные делегирования проходит, `path_hash_prefixes`
  и ключ верхней роли в делегировании принимает: здесь наш клиент строже.
