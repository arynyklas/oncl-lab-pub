# Издателям плагинов

Как собрать плагин стороннего издателя так, чтобы OpenNCALayer принял выпуск. Устройство всей схемы описано в [`docs/design/publishers.md`](../design/publishers.md): почему пересборка обязательна, что подписывает издатель, какие проверки проходит PR.

## Выпуск шаг за шагом

Все команды — `cargo xtask vendor …` в клоне репозитория OpenNCALayer. Ниже издатель `ecc` с префиксом `kz.ecc.` и плагином `kz.ecc.market`; команды для bash. Что проверяет каждый шаг, описано в [`docs/design/publishers.md`](../design/publishers.md), разделы «Команды издателя» и «Автослияние PR издателя».

### 1. Ключ

```sh
cargo xtask vendor keygen --name ecc --out ~/oncl-keys
```

Команда спрашивает пароль (не короче 12 символов; `--passphrase-file` читает его из файла) и пишет зашифрованный ключ Ed25519 `~/oncl-keys/pub-ecc-<начало keyid>.key`. Каталог ключей должен лежать вне рабочего дерева git: файл, который git мог бы закоммитить, команда не пишет. Она печатает `keyid` и строку `[[keys]] public = "…"` для `publisher.toml`. Для порога больше 1 каждый держатель ключа делает свой ключ.

### 2. Подключение (один раз, PR сливает владелец)

```sh
cargo xtask vendor onboard --name ecc --prefix kz.ecc. \
  --module kz.ecc.market.Signer --bundle kz.ecc.market \
  --display-ru 'ТОО «…»' --display-kk '…' --display-en '…' \
  --github ecc-release --key <64 hex из keygen> --homepage https://ecc.kz/
```

Команда пишет `publishers/ecc/publisher.toml` и проверяет реестр с ним (`vendor check-onboarding`; в CI та же команда с `--base origin/main` ещё запрещает удалять и переименовывать записи `publishers/` и менять `publishers/builders.toml`). Двоичные файлы исходников больше 64 КиБ (шрифты, картинки) перечисляются в `binary_files = ["src/…"]` того же файла. PR открывается по шаблону подключения [`.github/PULL_REQUEST_TEMPLATE/publisher.md`](../../.github/PULL_REQUEST_TEMPLATE/publisher.md): допишите к адресу страницы нового PR `?template=publisher.md` (например, `https://github.com/arynyklas/OpenNCALayer/compare/main...<ваш логин>:<ветка>?expand=1&template=publisher.md`). Владелец проверяет домен, сливает и подписывает верхний `targets` (`tuf update`). Дальше выпуски идут без владельца.

### 3. Архив исходников

```sh
cargo xtask vendor source --git ../market --rev v1.2.0 --out dist/kz.ecc.market-1.2.0.src.tar.gz
```

Тот же код, что `oncl-pack source` в образе (раздел «Сборка в эталонном сборщике» ниже): архив ревизии git или (`--dir`) каталога. Команда печатает `archive_sha256` и `archive_length`. Выложите архив на анонимный HTTPS-адрес: его CI скачает один раз (проверка 13). Адрес — имя хоста, не IP-адрес и не имя локальной сети, перенаправления только на HTTPS, не дольше 120 секунд.

### 4. Сборка в эталонном образе

```sh
cargo xtask vendor build --source dist/kz.ecc.market-1.2.0.src.tar.gz --path crates/market --out dist/build
```

Команда делает шаги 2 и 3 раздела «Сборка в эталонном сборщике» сама (Docker, или Podman при `ONCL_CONTAINER=podman`): образ по последнему digest из `publishers/builders.toml` (или `--builder sha256:…`), скачивание зависимостей с сетью, `cargo metadata` и сборка без сети, пакет забирается `docker cp` и хешируется снаружи. В `dist/build` появляются пакет `<id>-<версия>.onclp`, `THIRD-PARTY.txt` (крейты модуля и их лицензии) и `BUILDINFO.json` (образ, хеши архива, `Cargo.lock` и пакета). Лицензия каждого крейта модуля должна быть из списка OSI (проверка 20), иначе сборка завершается ошибкой. `--image` собирает в образе, собранном локально; такой результат выпустить нельзя, у него нет digest.

### 5. Черновик роли

```sh
cargo xtask vendor add --name ecc --build dist/build \
  --fetch https://downloads.ecc.kz/oncl/kz.ecc.market-1.2.0.src.tar.gz \
  --vcs-url https://git.ecc.kz/oncl/market.git --vcs-rev <40 hex> \
  --channel beta --rollout 100
```

Черновик `target/vendor/ecc/role.json` начинается с последней версии роли в `tuf/v1`. `add` берёт длину и sha256 пакета, вычисляет `url` копии в наших Releases, заполняет `source` из `BUILDINFO.json`, а `id`, версию, `min_core`, модули, `replaces`, название и `capabilities` — из манифеста пакета; `id` и модули сверяются с `publisher.toml`. `--vcs-url`/`--vcs-rev` необязательны (проверка 25). Изменить уже выпущенную запись можно только командой `set` (`--channel stable`, `--rollout N`, `--revoke`, `--unrevoke`), убрать старую версию — `prune` (только если версия не отозвана и есть более новая неотозванная в том же или более широком канале).

### 6. Подпись

```sh
cargo xtask vendor sign --name ecc --keys ~/oncl-keys --expires-days 90
```

Пишет `tuf/v1/metadata/<N+1>.pub-ecc.json`, подписанный ключами издателя из каталога, и удаляет черновик. Срок — от 14 до 180 дней (проверка 5 требует не меньше 14 дней в запасе в момент проверки CI). При пороге больше 1 остальные держатели ключей добавляют подписи: `cargo xtask vendor cosign tuf/v1/metadata/<N+1>.pub-ecc.json --keys <их каталог>`.

### 7. Проверка и PR

```sh
git switch -c release/kz.ecc.market-1.2.0 origin/main
git add tuf/v1/metadata/<N+1>.pub-ecc.json && git commit -m "ecc: kz.ecc.market 1.2.0"
cargo xtask vendor check --name ecc            # с --offline без скачивания архивов
```

`check` делает те же проверки, что CI (`vendor check-pr`), кроме проверки автора (2), против `origin/main`. Затем PR с одним этим файлом от аккаунта из `github`. Бот пересобирает пакет, копирует его и архив в выпуск `pub-ecc-<sha256>` и сливает PR сам; не чаще раза в час.

## Сборка в эталонном сборщике

Пакет `.onclp`, который вы подписываете в своей роли, CI OpenNCALayer собирает заново из вашего архива исходников в эталонном сборщике и сравнивает побайтно (проверки 19 и 21 в [`publishers.md`](../design/publishers.md#проверки-pr-издателя-дополняют-111)). Совпадение обещано только внутри сборщика: это образ `ghcr.io/arynyklas/oncl-plugin-builder` с конкретным digest из [`publishers/builders.toml`](../../publishers/builders.toml). Этот digest вы пишете в `source.builder`. Сборка тем же `cargo` на своей машине годится для разработки, но её байты могут не совпасть.

В образе:

- Debian 13 slim, закреплённый по digest;
- Rust 1.99.1 с целью `wasm32-unknown-unknown`, без rustup: ваш `rust-toolchain.toml` не читается;
- gcc для build-скриптов и процедурных макросов, git;
- `oncl-pack`: делает канонический архив исходников, скачивает зависимости, собирает и проверяет пакет.

Образ работает от пользователя 10001. Каталог Cargo `/cargo` монтируйте томом, а рабочий каталог `/build` — свежим томом на каждый запуск: сборка распаковывает исходники в `/build/src` и не начнёт работу, если там что-то уже лежит.

### Что нужно

- Docker или Podman (в командах ниже `docker` можно заменить на `podman`). На Windows и macOS подойдёт Docker Desktop. Команды написаны для bash; в PowerShell замените `$PWD` на `${PWD}` и переносы строк `\` на `` ` ``.
- Крейт плагина: один `cdylib`, рядом `plugin.toml`, версия в нём равна версии крейта. `Cargo.lock` рабочего пространства лежит в архиве. Зависимости берутся только из crates.io и из git с закреплённым `rev`.
- В архиве нет `.cargo/config` и `.cargo/config.toml` ни в корне, ни по пути к крейту: такой файл мог бы подменить источники зависимостей или ход сборки, поэтому сборщик отказывается его читать.

Ниже `IMAGE` — образ по digest, например:

```sh
IMAGE=ghcr.io/arynyklas/oncl-plugin-builder@sha256:<digest из publishers/builders.toml>
```

### 1. Архив исходников

Архив должен быть ровно таким, какой делает `oncl-pack source`: один корневой каталог `src/`, только файлы и каталоги, записи по порядку путей, владелец 0, время 1980-01-01, режим 0644 или 0755, gzip сборщика. В именах нет `\`, `:`, управляющих символов, имён устройств Windows (`CON`, `NUL`, `COM1` и т. п.) и точки или пробела в конце. Полные правила — в разделе [«Архив исходников»](../design/publishers.md#архив-исходников). Архив, собранный другим `tar`, не пройдёт проверку, даже если файлы в нём те же.

Архив из ревизии git (рекомендуется: в архив попадает всё дерево ревизии, как его хранит git, без каталога `.git`):

```sh
docker run --rm --network=none --read-only \
  -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/repo \
  -v "$PWD:/repo:ro" -v "$PWD/dist:/out" \
  "$IMAGE" source --git /repo --rev v1.2.0 --out /out/kz.ecc.market-1.2.0.src.tar.gz
```

Переменные `GIT_CONFIG_*` разрешают git читать смонтированный репозиторий, владелец которого не пользователь 10001.

Архив из каталога: в архив попадает каждый файл каталога, кроме `.git`. Подходит для исходников вне git.

```sh
docker run --rm --network=none --read-only \
  -v "$PWD/sources:/sources:ro" -v "$PWD/dist:/out" \
  "$IMAGE" source --dir /sources --out /out/kz.ecc.market-1.2.0.src.tar.gz
```

Признак исполняемого файла берётся из файловой системы. Docker Desktop показывает файлы, смонтированные из Windows, с режимом 0777: архив из такого каталога получит у каждого файла режим 0755 и не совпадёт с архивом той же ревизии из git. Из Windows делайте архив с `--git`.

Команда печатает sha256 архива. Он и длина файла идут в `source.archive_sha256` и `source.archive_length`. Проверить готовый архив:

```sh
docker run --rm --network=none -v "$PWD/dist:/out:ro" "$IMAGE" check /out/kz.ecc.market-1.2.0.src.tar.gz
```

Команда печатает sha256 и длину архива или объясняет, почему архив не канонический.

### 2. Зависимости

Единственный шаг с сетью. Он распаковывает архив и скачивает в том `/cargo` всё, что перечисляет `Cargo.lock` (`cargo fetch --locked`); код из архива при этом не запускается. `--path` — каталог крейта внутри `src/`, то есть `source.path`; для крейта в корне архива укажите `--path=`.

Заводите отдельный том `/cargo` на каждый архив и удаляйте его после проверки: сборка видит его только для чтения, но один и тот же том для разных исходников не нужен.

```sh
docker volume create oncl-cargo-market-1.2.0
docker run --rm --read-only --cap-drop=ALL --security-opt no-new-privileges \
  -v oncl-cargo-market-1.2.0:/cargo --mount type=volume,dst=/build -v "$PWD/dist:/in:ro" \
  "$IMAGE" fetch --source /in/kz.ecc.market-1.2.0.src.tar.gz --path=crates/market
```

### 3. Сборка

Сборка выполняет код исходников (`build.rs`, процедурные макросы), поэтому идёт только без сети: `--network=none`, а `oncl-pack build` сам отказывается работать, если в контейнере есть сетевой интерфейс кроме `lo`. Файловая система образа и том `/cargo` только для чтения, каталоги хоста в контейнер на запись не попадают:

```sh
docker run --name oncl-build --network=none --read-only --cap-drop=ALL --security-opt no-new-privileges \
  --cpus 8 --memory 8g --pids-limit 4096 \
  -v oncl-cargo-market-1.2.0:/cargo:ro --mount type=volume,dst=/build -v "$PWD/dist:/in:ro" \
  "$IMAGE" build --source /in/kz.ecc.market-1.2.0.src.tar.gz --path=crates/market --out /build/out
docker cp oncl-build:/build/out ./out
docker rm -v oncl-build
ls -l out && sha256sum out/*.onclp
```

Пакет забирается `docker cp` после того, как контейнер завершился, и хешируется на вашей машине. Строкам, которые контейнер напечатал, не доверяйте: их печатает тот же процесс, в котором работал код исходников. В `out` должен оказаться ровно один обычный файл `<id>-<версия>.onclp`. `--mount type=volume,dst=/build` без имени тома даёт новый пустой том, `docker rm -v` удаляет его вместе с контейнером.

`oncl-pack build`:

1. проверяет, что архив канонический, в нём есть `src/<path>/Cargo.toml` и `src/<path>/plugin.toml` и нет `.cargo/config*` по пути к крейту;
2. собирает крейт для `wasm32-unknown-unknown` с `--release --frozen`. Окружение очищено (как после `env -i`), `SOURCE_DATE_EPOCH=315532800`, `CARGO_INCREMENTAL=0`. Профиль `release` дополняется настройками `codegen-units = 1`, `incremental = false`, `debug = false`, `strip = true`, а флаги `-Ccodegen-units=1 -Cdebuginfo=0 -Cstrip=symbols` идут rustc последними и перекрывают и настройки отдельных пакетов в вашем профиле; `opt-level`, `lto` и `panic` остаются вашими. Пути сборки заменяются в модуле постоянными именами: `/cargo`, `/rustc`, `/target`, `/workspace` и `/plugin`;
3. проверяет пакет так же, как демон перед установкой: манифест, версию крейта, ABI модуля, `min_core`;
4. собирает крейт второй раз и сравнивает. Обе сборки идут в одном контейнере, но каждая в своих каталогах `target` и `TMPDIR`, которые она создаёт сама и отказывается найти уже существующими. Если две сборки различаются, пакет не выдаётся: что-то в вашем крейте или его зависимостях собирается неповторяемо. Частые причины — порядок `HashMap` в процедурном макросе и время или случайные данные в `build.rs`.

Хеш и длину пакета, посчитанные на вашей машине, вы подписываете в своей роли. Опция `--jobs N` ограничивает параллельность Cargo; на байты пакета она не влияет.

На 8 ядрах порт `plugins/eot` этого репозитория скачивал зависимости 6 с, а обе сборки в одном контейнере заняли 20 с. Образ без сжатия занимает около 1,5 ГБ.

### 4. Проверка выпуска

Любой может пересобрать опубликованный выпуск и сравнить байты. Из выпуска `pub-<издатель>-<sha256 пакета>` в Releases OpenNCALayer скачайте `<id>-<версия>.src.tar.gz` в текущий каталог, затем: зависимости с сетью, проверка без неё.

```sh
docker volume create oncl-verify-cargo
docker run --rm --read-only --cap-drop=ALL --security-opt no-new-privileges \
  -v oncl-verify-cargo:/cargo --mount type=volume,dst=/build -v "$PWD:/in:ro" \
  "$IMAGE" fetch --source /in/kz.ecc.market-1.2.0.src.tar.gz --path=crates/market
docker run --rm --network=none --read-only --cap-drop=ALL --security-opt no-new-privileges \
  -v oncl-verify-cargo:/cargo:ro --mount type=volume,dst=/build -v "$PWD:/in:ro" \
  "$IMAGE" verify --source /in/kz.ecc.market-1.2.0.src.tar.gz --path=crates/market \
  --sha256 <sha256 пакета>
docker volume rm oncl-verify-cargo
```

Вместо `--sha256` можно указать сам пакет: `--package /in/<id>-<версия>.onclp`. Код выхода 0 означает, что пересборка дала те же байты. Иначе команда пишет оба хеша. `verify`, как и `build`, отказывается работать, если в контейнере есть сеть.

### Если не получилось

| Сообщение | Что делать |
|---|---|
| `the archive is not canonical` | Архив сделан не `oncl-pack source` или изменён после. Сделайте его заново командой из шага 1 |
| `the archive has src/….cargo/config…` | Уберите `.cargo/config*` из исходников; нужные настройки перенесите в `Cargo.toml` |
| `the reference build failed (were the crates fetched first…)` | Выполните шаг 2 с тем же томом `/cargo`; проверьте, что `Cargo.lock` в архиве актуален |
| `the network is on` | Запустите `build` или `verify` с `--network=none` |
| `two builds of the same sources differ` | Сборка неповторяема: ищите неустойчивый порядок или время в процедурных макросах и `build.rs` |
| `unpacking the archive (the work directory must be fresh)` | Монтируйте в `/build` новый том на каждый запуск |
| `detected dubious ownership` от git | Передайте переменные `GIT_CONFIG_*` из шага 1 |

## Образ сборщика

Это раздел для владельца проекта.

- Образ собирается из [`xtask/assets/plugin-builder/Dockerfile`](../../xtask/assets/plugin-builder/Dockerfile). Контекст сборки — корень репозитория, `oncl-pack` собирается из того же коммита. Базовый образ закреплён по digest, архивы тулчейна — по sha256 из `channel-rust-<версия>.toml`. Версия Rust в Dockerfile совпадает с `rust-toolchain.toml`, это проверяет тест.
- Публикует образ workflow [`plugin-builder.yml`](../../.github/workflows/plugin-builder.yml), его запускают вручную. Задание `test` без прав на запись собирает образ, дважды собирает в нём порт (тест `image` крейта `oncl-pack`) и сохраняет образ артефактом. Задание `publish` в окружении `plugin-builder` загружает этот образ, отправляет его в ghcr.io с тегом коммита, подписывает аттестацию происхождения и выводит в сводке готовую запись для `publishers/builders.toml`. Кода репозитория в нём не запускается.
- Окружение `plugin-builder` создаётся один раз и пропускает только `main`: запуск с другой ветки на нём останавливается. Через веб-интерфейс: Settings → Environments → New environment `plugin-builder` → Deployment branches and tags → Selected branches and tags → Add `main`. Или командами:

  ```sh
  gh api -X PUT repos/arynyklas/OpenNCALayer/environments/plugin-builder \
    -F 'deployment_branch_policy[protected_branches]=false' \
    -F 'deployment_branch_policy[custom_branch_policies]=true'
  gh api -X POST repos/arynyklas/OpenNCALayer/environments/plugin-builder/deployment-branch-policies \
    -f name=main -f type=branch
  ```

  Секретов у окружения нет: пакеты пишет `GITHUB_TOKEN` задания.
- Сборщиком образ становится только после PR владельца, который добавляет запись в конец `publishers/builders.toml`. Записи там не меняются и не удаляются, иначе старые выпуски нельзя будет пересобрать. Схему файла описывает `xtask/src/publishers/builders.rs`.
- Собрать и проверить образ локально:

  ```sh
  git archive HEAD | docker build -f xtask/assets/plugin-builder/Dockerfile -t oncl-plugin-builder -
  ONCL_BUILDER_IMAGE=oncl-plugin-builder cargo test -p oncl-pack --test image -- --ignored --nocapture
  ```

  Без `ONCL_BUILDER_IMAGE` тест сам собирает образ из `HEAD`. На машине с 8 ядрами сборка образа занимает около 2 минут, тест — около минуты.

## Проверки CI

Это раздел для владельца проекта и для workflow `publisher-pr.yml`. Каждая проверка — функция над данными в `xtask/src/vendor/checks.rs`; код из PR не собирается и не запускается.

| Команда | Job | Проверки | Выход |
|---|---|---|---|
| `vendor check-pr --base <main> --head <голова PR> --author <логин> --out <каталог>` | `publisher-check` | 1–9, 11–18, 23, 24 (сначала 1 и 2; при их провале остальные `skip`); `--author` обязателен, архивы скачиваются всегда | JSON на stdout и `verdict.json`; архивы `<id>-<версия>.src.tar.gz` в `--out` |
| `vendor provenance --base … --head … --archives <каталог> --network <сеть> [--builder sha256:…] --out <файл>` | `provenance` | 25 | отчёт JSON по каждой новой цели с `vcs`: `confirmed`, `unverified`, `mismatch` |
| `vendor rebuild --archive <файл> --path <крейт> --builder sha256:… --out <каталог>` | `rebuild` (matrix) | 17 (по выводу `cargo metadata`), 19, 20 | `rebuild.json`; пакет и `THIRD-PARTY.txt` только если все три прошли |
| `vendor verdict --base … --head … --author … --archives … --rebuilt … --provenance … --out <каталог>` | `verdict` | весь вердикт: заново 1–9, 11–18, 23, 24 (над переданными архивами), 17, 19, 20 из каждого `rebuild.json`, 21, 22, 25 | `verdict.json`, `<id>-<версия>/BUILDINFO.json` прошедших пакетов |
| `vendor src-diff [--old <архив> --old-sha256 <hex>] --new <архив> --out <файл>` | `verdict` | — | `<id>-<версия>.src.diff` (у первой версии плагина его нет, и `--old` workflow не передаёт) |

`provenance` и `verdict` заново читают файл роли из git и сверяют архивы и пакеты с подписанными хешами сами: выходам предыдущих jobs они не верят. Решение о слиянии принимается только по `ok` вердикта job `verdict`: он один сводит все проверки, и пакет без `rebuild.json` с пройденными 17, 19 и 20 рядом с ним не проходит. Код выхода не 0, если проверка не прошла.

Проверка 1 судит не diff ветки, а то, что даст слияние: у головы PR и `main` ровно одна база слияния, между ней и головой нет коммитов слияния, а дерево `git merge-tree --write-tree main <голова>` (тот же merge-ort, что у squash-слияния GitHub) отличается от `main` ровно одним новым файлом роли. Проверка 17 читает каждый `Cargo.lock` архива, а при пересборке — каждый `source` из вывода `cargo metadata`. `source.path` состоит из сегментов `[A-Za-z0-9._-]` и не начинается с `-` (проверка 12). Workflow всё равно передаёт любое значение из PR (`path`, `id`, версию, теги) в `run:` только через `env:`, никогда через `${{ … }}` внутри команды. Проверка 18 — эвристика: она узнаёт сигнатуры wasm, ELF, PE, Mach-O, `ar`, zip и gzip, но не zstd, xz, bzip2, 7z или текст в base64; от подложенного готового кода защищает сравнение пересборки (19, 21).

Вердикт `check-pr` (`schema` 1):

```json
{
  "schema": 1, "ok": true, "base": "<sha>", "head": "<sha>",
  "publisher": "ecc", "role_version": 3,
  "checks": [{"id": 1, "status": "pass", "messages": []}, {"id": 2, "status": "fail", "messages": ["mallory is not in github of publishers/ecc/publisher.toml"]}],
  "new_targets": [{"path": "plugins/ecc/kz.ecc.market/1.2.0.onclp", "id": "kz.ecc.market", "version": "1.2.0",
                   "length": 123456, "sha256": "<hex>", "tag": "pub-ecc-<hex>",
                   "package": "kz.ecc.market-1.2.0.onclp", "archive": "kz.ecc.market-1.2.0.src.tar.gz",
                   "source": {"…": "как в роли"},
                   "previous": {"version": "1.1.0", "archive_url": "https://github.com/…/kz.ecc.market-1.1.0.src.tar.gz", "archive_sha256": "<hex>"}}]
}
```

`status` — `pass`, `fail` или `skip`. `ok` истинно, только если ни одна проверка не провалилась и каждая проверка этого запуска прошла. `previous` — прошлая версия того же плагина в роли на `main`, от архива которой считается `.src.diff`.

Политика адресов скачивания (проверки 13 и 25): только `https://`, без учётных данных и фрагмента, имя хоста с точкой (не IP-адрес ни в какой записи, не `localhost`, `*.local`, `*.internal`, `*.home.arpa`, `*.lan`), каждое перенаправление проверяется так же, соединение только с публичными адресами, в которые имя разрешилось один раз.

| Проверка не прошла | Что делать издателю |
|---|---|
| 1 | PR меняет ровно один путь — новый файл своей роли |
| 2 | PR открывает аккаунт из `github` в `publisher.toml` |
| 3 | версия файла — следующая после последней на `main`: начните черновик заново (`rm target/vendor/<имя>/role.json`) |
| 4 | подпишите ключом из `publisher.toml`, порог — `cosign` |
| 5 | подпишите заново со сроком от 14 до 180 дней |
| 6 | запись не проходит правила каталога: модули, префикс, `capabilities`, `min_core` не ниже 0.1.3 (первая версия с каталогом издателей, Р39), не больше 8 новых пакетов |
| 7 | модуль или бандл уже обслуживает порт владельца или другой издатель |
| 8, 24 | выпущенную запись менять нельзя, кроме `rollout`, `name`, `revoked` и канала `beta` → `stable` |
| 9 | подождите час после прошлого выпуска |
| 11 | `cargo xtask tuf check` дерева `main` с вашим файлом; обычно это ошибка на стороне `main` |
| 12 | `source` по таблице, `builder` из `publishers/builders.toml`, лицензия из списка OSI |
| 13 | архив по `fetch` доступен анонимно и равен подписанному |
| 14 | архив сделан `vendor source` и не менялся |
| 15–18 | состав архива: крейт, `Cargo.lock`, лицензия, нет `.cargo/config*`, источники зависимостей, нет готовых бинарников |
| 19–22 | пересборка в образе не совпала с подписанным пакетом или манифест не совпал с записью |
| 23 | `url` — адрес копии, который вычисляет `vendor add` |
| 25 | ревизия `vcs` даёт другой архив; уберите `vcs` или укажите правильную ревизию |

### Workflow `publisher-pr.yml`

[`.github/workflows/publisher-pr.yml`](../../.github/workflows/publisher-pr.yml) запускается на `pull_request_target` для PR в `main`, которые меняют `tuf/v1/metadata/*.pub-*.json` (кроме черновиков PR). Описание workflow и весь код, который он собирает, берутся из `main`; голова PR скачивается в ref `refs/oncl/head` и читается только как данные. Jobs по порядку:

| Job | Права | Что делает |
|---|---|---|
| `publisher-check` | `contents: read` | `vendor check-pr`, автор — `user.login` из события; архивы и `verdict.json` — артефакт `archives` |
| `provenance` | нет | сеть `oncl-vcs` с правилами `DOCKER-USER` (раздел «Сеть проверки 25»), `vendor provenance`; отчёт — артефакт `provenance` |
| `rebuild` | нет | matrix по новым пакетам (не больше 8), `vendor rebuild`; пакет, `THIRD-PARTY.txt` и `rebuild.json` — артефакт `rebuilt-<n>` |
| `verdict` | `contents: read` | `vendor verdict`, затем `vendor src-diff` для каждого пакета с прошлой версией; `BUILDINFO.json`, `.src.diff` и `verdict.json` — артефакт `verdict`; выходы для `mirror` и `merge` |
| `mirror` | `contents: write`, `id-token: write`, `attestations: write` | выпуск `pub-<издатель>-<sha256>` на каждый новый пакет: черновик со всеми файлами, аттестация сборки пакета, сверка файлов черновика, публикация, проверка, что выпуск неизменяемый |
| `merge` | `contents: write`, `pull-requests: write`, `actions: write` | ждёт обязательных проверок головы не дольше 30 минут, `gh pr merge --squash --match-head-commit`, `gh workflow run pages.yml` |

Каждый job, который запускает xtask, собирает его сам (`cargo build --locked -p xtask`, без кэша) до того, как на раннере появятся голова PR или артефакты. `mirror` и `merge` не выгружают репозиторий и не запускают cargo. Значения из PR (автор, голова, издатель, `id`, версия, путь крейта, сборщик) попадают в команды только через `env:`. Правила закрепляет `xtask/tests/workflows_publishers.rs`.

Если запуск красный:

- `publisher-check`, `provenance`, `rebuild`, `verdict`: причина — в выводе проверки (таблица выше); издатель исправляет и пушит в тот же PR, новый запуск отменяет старый.
- `mirror`, «published with other bytes» или «published without …»: выпуск с этим тегом уже опубликован, но не с этими байтами. Его нельзя ни поправить, ни удалить с освобождением тега; владелец разбирается вручную, издатель пересобирает пакет (другие байты — другой тег).
- `mirror`, «not immutable»: в настройках репозитория выключены неизменяемые выпуски (`docs/dev/release.md`, раздел 1). Такой выпуск уже не станет неизменяемым, и бот его не примет: владелец включает настройку и разбирается с выпуском вручную, издатель выпускает пакет с другими байтами.
- `merge`, «main moved», «the pull request changed» или «no required check on the head»: `main` сдвинулся после проверок, у PR сменились база или голова, или CI ещё не запускался на голове (первый PR из форка ждёт одобрения запуска владельцем). Перезапуск jobs не поможет: он берёт прежние `main`, голову и выводы. Издатель пушит в PR ещё раз (подойдёт пустой коммит, `git commit --allow-empty`), и всё проверяется заново против нового `main`. Копии, которые уже в Releases, повторно не создаются.
- `mirror` отменён без ошибки в журнале: jobs `mirror` всех PR идут по одному, и когда ждут три и больше, GitHub отменяет ожидающий раньше. Издатель пушит ещё раз.

Бот проверяет и сливает только против того `main`, на котором шли проверки, так что выпуски нескольких издателей подряд могут требовать нового пуша, если `main` двигался во время прогона.

Остаточные риски, о которых владелец должен знать. Контейнер `fetch` пересборки (`cargo fetch` с сетью) идёт в сети Docker по умолчанию, без правил `oncl-vcs`: источники зависимостей ограничены crates.io и разрешёнными git-хостами, но от ошибки cargo на вредном крейте сеть раннера его не отделяет. Токен среды выполнения каждого job, и `rebuild` тоже, может записывать в кэш Actions с областью `main` (для `pull_request_target` ref — `main`): при выходе кода издателя из контейнера кэш, который восстанавливают `pages.yml`, `upstream.yml` и `ci.yml`, можно отравить. Клиентов защищают подписи TUF. `vendor check-onboarding` в PR подключения запускает xtask из самого PR, поэтому владелец ещё сам проверяет, что PR меняет только `publishers/<имя>/publisher.toml`.

### Лицензии

Список лицензий OSI — `xtask/assets/spdx/osi-licenses.txt` (SPDX 3.29.0, `isOsiApproved`, без устаревших), рядом `exceptions.txt` (исключения `WITH`) и `deprecated.txt` (устаревшие идентификаторы лицензий и исключений). Выражение с устаревшим идентификатором или с `LicenseRef-`, `DocumentRef-`, `AdditionRef-` отвергается целиком, даже как один из вариантов `OR`, и в `source.license`, и у зависимостей (Р40). Для зависимостей `/` читается как `OR`, как его когда-то понимал Cargo.

Список обновляет ручной PR владельца, когда это нужно (новая версия SPDX, просьба издателя). Новые правила действуют только на новые выпуски; принятые остаются, а `tuf check` предупреждает о них (`publisher-rules`, Р42). Как обновить:

1. Скачайте `json/licenses.json` и `json/exceptions.json` выпуска `vX.Y.Z` из <https://github.com/spdx/license-list-data> и запишите их sha256.
2. `osi-licenses.txt`: `licenseId` всех лицензий с `isOsiApproved: true` и без `isDeprecatedLicenseId`, по одному в строке, по возрастанию.
3. `exceptions.txt`: `licenseExceptionId` всех исключений без `isDeprecatedLicenseId`.
4. `deprecated.txt`: идентификаторы лицензий и исключений с `isDeprecatedLicenseId: true`.
5. В шапке каждого файла укажите версию списка и sha256 исходного JSON; в PR — что добавилось и что ушло. `cargo nextest run -p xtask -E 'test(/licenses/)'`.

`THIRD-PARTY.txt` пересборки — список крейтов модуля с лицензиями и источниками, затем полный текст каждого файла `LICENSE*`, `LICENCE*`, `COPYING*`, `NOTICE*`, `UNLICENSE*` каждого крейта (Р41). Файлы скачанных крейтов копируются `docker cp` из тома Cargo через контейнер, который не запускается; у крейтов из архива — из архива (каталог крейта или ближайший выше, где они есть). Крейт без файла лицензии — провал проверки 20: стандартный текст SPDX его не заменяет, издатель выбирает версию с файлом или просит автора крейта добавить его.

### Сеть проверки 25

`vendor provenance` запускает git только в контейнере образа сборщика: пользователь 10001, корень только для чтения, без capabilities, `https` только, без перенаправлений (`http.followRedirects=false`), без учётных данных; голый репозиторий забирается `docker cp` и читается как данные. Политика адресов проверяется до запуска, но git разрешает имя сам, поэтому сеть контейнера (`--network`) должна сама не пускать никуда, кроме интернета (Р43). Job `provenance` workflow `publisher-pr.yml` готовит её перед проверкой и удаляет после:

```sh
docker network create --driver bridge --opt com.docker.network.bridge.name=oncl-vcs \
  --subnet 172.31.250.0/24 oncl-vcs
# Только новые исходящие соединения в публичный интернет; ничего к раннеру и его сетям.
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 \
           127.0.0.0/8 0.0.0.0/8 224.0.0.0/4 240.0.0.0/4 168.63.129.16/32; do
  sudo iptables -I DOCKER-USER -i oncl-vcs -d "$net" -j DROP
done
sudo iptables -I INPUT -i oncl-vcs -j DROP          # и к самому раннеру
sudo ip6tables -I DOCKER-USER -i oncl-vcs -j DROP   # без IPv6
cargo xtask vendor provenance … --network oncl-vcs
```

Правило `DROP` для `172.16.0.0/12` закрывает и сети Docker самого раннера, `168.63.129.16` — служебный адрес хоста Azure (WireServer), публичный по форме. Job требует Docker 28 или новее: с ним dockerd обращается к вышестоящим резолверам хоста (на раннере это и `168.63.129.16`) из пространства имён хоста, а не контейнера, и DNS через `127.0.0.11` работает при этих правилах; старый Docker отправил бы запрос из контейнера, и правило его отбросило бы. DNS контейнер получает от встроенного резолвера Docker (через раннер), это единственный путь к нему. Без такой сети `--network bridge` даёт контейнеру доступ к сетям раннера: так запускать нельзя.

`--network` принимает только имя существующей пользовательской сети с драйвером `bridge` (`docker network inspect`): `host`, `bridge`, `default`, `none`, `slirp4netns`, `pasta`, `private` и всё с `:` (`container:…`, `ns:…`) отвергаются.

Пределы, которые держит xtask: не больше 64 файлов лицензий у крейта и 16 МиБ текстов лицензий в `THIRD-PARTY.txt` (иначе проверка 20 не проходит), голый репозиторий проверки 25 после копирования не больше 256 МиБ (иначе «не проверено»), а `Tree::from_git` дальше держит пределы архива (256 МиБ распакованного, 20 000 записей). Места на диске под тома Docker и объём вывода контейнеров xtask не ограничивает: `--storage-opt size=` работает не на всех драйверах хранилища. Поэтому jobs `provenance` и `rebuild` до первого обращения к Docker останавливают его и переносят `/var/lib/docker` и `/var/lib/containerd` на файловую систему 20 ГиБ в файле на самом свободном диске раннера (действие [`.github/actions/docker-disk`](../../.github/actions/docker-disk/action.yml)), а у каждого job есть тайм-аут. Сборка, заполнившая этот диск, роняет только свой job, а место для отчёта на раннере остаётся.
