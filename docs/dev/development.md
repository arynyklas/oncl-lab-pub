# Разработка и сборка

Как собрать OpenNCALayer, запустить тесты и проверить изменение перед PR.

## Коротко: от клона до зелёных тестов

1. Поставьте `rustup`, OpenSSL 3 и Python 3.12 или новее (в CI стоит 3.12). На Linux до `cargo test --workspace` нужны ещё пакеты разработки для окон из раздела [«Сборка и запуск»](#сборка-и-запуск): `libfontconfig1-dev libxkbcommon-dev libwayland-dev`. Подробности в разделе [«Что нужно для тестов»](#что-нужно-для-тестов).
2. Создайте для тестов отдельное окружение Python и укажите путь к нему:
   ```sh
   python3 -m venv .venv-oracle
   .venv-oracle/bin/python -m pip install --require-virtualenv -r xtask/assets/oracle/requirements.txt
   export ONCL_PYHANKO_PYTHON="$PWD/.venv-oracle/bin/python"
   ```
   В Windows интерпретатор лежит в `.venv-oracle\Scripts\python.exe`.
3. Скачайте тестовые данные: `cargo xtask fetch-fixtures`.
4. Запустите тесты: `cargo test --workspace`.
5. Перед PR выполните `cargo xtask privacy` и проверки из раздела [«Перед отправкой изменений»](#перед-отправкой-изменений).

Если какой-то шаг не сработал, напишите в [Issues](https://github.com/arynyklas/OpenNCALayer/issues): значит, ошибка в этой инструкции.

Другие документы для разработчиков: выпуск версии описан в [`release.md`](release.md), встраивание SDK в [`sdk-overview.md`](sdk-overview.md) и [`sdk.md`](sdk.md), сборка плагинов сторонних издателей в [`publishers.md`](publishers.md).

## Сборка и запуск

Нужен `rustup`. Версия Rust записана в `rust-toolchain.toml` и ставится автоматически.

На Linux для окон нужны пакеты разработки fontconfig, xkbcommon и Wayland. GTK не нужен: ни один крейт из `Cargo.lock` его не подключает. В Debian и Ubuntu:

```sh
sudo apt-get install -y libfontconfig1-dev libxkbcommon-dev libwayland-dev
```

Для запуска программы на Linux нужны ещё два компонента:
- `libxkbcommon-x11-0`. Без неё окна подписи не открываются, а `openncalayer run` завершается с ошибкой. Пакет `libxkbcommon-dev` её не ставит.
- `xdg-desktop-portal` с бэкендом (например, `xdg-desktop-portal-gtk`) или `zenity`, для кнопки «Обзор…». Без них диалог выбора файла не откроется (в журнале будет ошибка rfd), но путь к файлу ключа можно ввести вручную.

Сборка:

```sh
cargo build --release -p openncalayer
```

Программа появится в `target/release/openncalayer` (в Windows `openncalayer.exe`).

### Первый запуск

Проще всего настроить сертификат мастером «Сертификат для браузера…» в меню значка (раздел [«Мастер TLS»](../user/desktop.md#мастер-tls)). Из командной строки то же самое:

```sh
openncalayer tls init   # выпустить сертификат и напечатать, как установить CA
openncalayer run        # запустить сервер со значком; `openncalayer` без команды делает то же
```

1. Выпустите сертификат (мастером или `tls init`) и установите CA кнопкой мастера или по напечатанной инструкции. Подробности для каждой ОС в [`docs/user/tls.md`](../user/tls.md).
2. Запустите `openncalayer run` и откройте `https://127.0.0.1:13579/` (или `https://127.0.0.1:13579/openncalayer/selftest`). Страница должна открыться без предупреждения о сертификате.
3. На `https://127.0.0.1:13579/demo/` можно подписать текст или файл и скачать `.p7s`.
4. Проверьте подпись:

   ```sh
   oncl verify --profile cms --input signature.p7s --root <корневой сертификат НУЦ>
   ```

   - Демо-страница сохраняет `.p7s` в DER. `oncl verify` читает DER и BER, а PEM только с ключом `--pem` (один блок `CMS` или `PKCS7`, не больше 16 МиБ текста).
   - Корневые сертификаты автоматически не подставляются, их нужно передать через `--root`.
   - Для подписи без вложенных данных добавьте `--detached <файл данных>`.
   - `--offline` отключает проверку отзыва.
   - Команда проверяет подписи и метки времени, цепочки сертификатов подписанта и службы времени (по переданным корням), срок действия и отзыв, и печатает отчёт по каждой проверке. Код выхода 0 бывает, только если результат `Valid`.
   - Все ключи команды перечислены в [`docs/user/cli.md`](../user/cli.md).

### Коды выхода `openncalayer run`

| Код | Что случилось |
|---|---|
| 2 | TLS не настроен |
| 3 | порт занят, например оригинальным NCALayer |
| 4 | OpenNCALayer с тем же каталогом данных уже запущен в этом сеансе |

Коды 2 и 3 возможны, только когда `wss` выключен и значка нет. Значка нет в таких случаях:
- запуск с `--no-tray`;
- значок не удалось показать;
- значок пропал на первом проходе цикла окон (macOS);
- StatusNotifierWatcher не принял значок в течение минуты после запуска (Linux).

Если к этому моменту проблему устранили (оригинал остановили из уведомления, сертификат сохранили), программа продолжает работать без значка.

Если значок есть, программа при ненастроенном TLS или занятом порте не завершается. Она обслуживает расширение, значок показывает проблему, а `wss` запускается, когда мастер сохранит сертификат или порт освободится. Программа, которую запустил пользователь или автозапуск, показывает уведомление и сама занимает освободившийся порт (проверяет раз в 30 секунд).

С флагом `--allow-no-wss` программу запускает relay расширения. В этом режиме ошибка запуска `wss` (коды 1, 2 и 3) не останавливает программу: она пишет предупреждение в журнал и работает только для расширения. Освободившийся порт она сама не занимает и запускает `wss` только после действия пользователя в значке или мастере TLS (остановить оригинал, сохранить сертификат).

Оригинал и OpenNCALayer не могут одновременно работать по `wss`, потому что обоим нужен порт 13579. Расширению порт не нужен.

### Где лежат данные

| ОС | Каталог данных |
|---|---|
| Windows | `%APPDATA%\OpenNCALayer` |
| macOS | `~/Library/Application Support/OpenNCALayer` |
| Linux | `${XDG_DATA_HOME:-~/.local/share}/openncalayer` |

Внутри:
- `tls/`: сертификаты;
- `logs/openncalayer.YYYY-MM-DD.log`: журналы, новый файл каждый день;
- `settings.json`: настройки (`locale`, `autostart`, `proxy`) и путь к последнему выбранному файлу ключа;
- `original-autostart.json` и `original-autostart/`: журнал и перенесённые записи автозапуска оригинала;
- `installation.json`: какая версия и откуда установлена (раздел [«Установка»](../user/install.md#установка)).

Переменная `ONCL_DATA_DIR` задаёт другой каталог данных. При разработке укажите её (например, `ONCL_DATA_DIR=target/oncl-data`), чтобы не трогать свой рабочий профиль.

## Как не ждать сборку

Советы ниже основаны на замерах на машине разработки.

- Каталог `target` держите на SSD или NVMe, не на HDD. На HDD одна сборка нескольких клонов давала очередь в 31 запрос и 60 мс на операцию при 0 % простоя, а NVMe рядом был свободен на 98 %. Один каталог тестов `oncl-cli` занимает около 6 ГБ.
- Держите один общий `CARGO_TARGET_DIR` на клон и одну форму команды в нём. Новый каталог означает холодную сборку: весь workspace собирался на той машине около 12 минут. Если в том же каталоге сменить `-p oncl-cli` на `--workspace`, пересоберутся 107 сторонних и 42 своих крейта, которые уже были собраны, а при смене `-p oncl-pki` на `-p oncl-cli` и обратно 38 и 5. Смена линкера, тулчейна или `RUSTFLAGS` пересобирает всё.
- В Windows исключите каталог сборки из проверки Defender в реальном времени или собирайте на Dev Drive (на SSD) в режиме производительности. Во время сборки Defender занимал около 0,67 ядра. Сколько времени это даёт, не измерялось.

## Что нужно для тестов

Для сборки этот раздел не нужен. Часть тестов сверяет результат нашего кода с независимыми программами: OpenSSL, pyHanko, lxml и другими. Если нужной программы нет, такой тест (или одна его проверка) пропускается и считается пройденным, а в вывод `cargo test` попадает строка, где сказано, какой программы не хватило и где её искали:

```text
skipped: <имя теста> needs openssl (not found: tried `openssl`; ONCL_OPENSSL is not set); see docs/dev/development.md «Что нужно для тестов»
```

Молча тесты не пропускаются. Но зелёный прогон с такими строками проверил меньше, чем CI. Чтобы отсутствие программы было ошибкой, задайте `ONCL_REQUIRE_ORACLES=1`: тогда тест падает и пишет полное сообщение, то есть какие файлы пробовал, какой переменной указать путь и какой пакет поставить. Любое значение, кроме пустого и `0`, тоже включает эту проверку. В CI переменная задана для всех тестов.

`cargo nextest` по умолчанию не показывает вывод прошедших тестов, поэтому строк `skipped:` там не видно. Запускайте его с `--success-output final`, тогда они появятся в конце прогона. Или задайте `ONCL_REQUIRE_ORACLES=1`, и пропусков не будет вовсе.

Что поставить:

| Что | Зачем | Как проверить |
|---|---|---|
| Rust | сборка и запуск тестов (ставится сам через `rustup`) | `cargo --version` |
| Системные библиотеки на Linux | окна Slint | см. «Сборка и запуск» |
| OpenSSL 3 | многие тесты проверяют наши подписи командой `openssl` | `openssl version`. Ищется в `ONCL_OPENSSL`, затем в `PATH`; в Windows ещё `openssl.exe` из Git for Windows |
| `git` в `PATH` | тесты `xtask` и сборки встроенных модулей | `git --version` |
| JDK, `keytool` в `PATH` | тест JKS в `oncl-cli` | `keytool -help` |
| `python` в `PATH` | вспомогательные скрипты тестов (без сторонних пакетов) | `python --version` |
| `certutil` из NSS (только Linux; пакет `libnss3-tools` или `nss-tools`) | тесты записи сертификата в базы браузеров в `oncl-trust` | `certutil -H` |
| 7-Zip 25.01 или новее | тест `xtask` о том, что 7-Zip не пишет по символической ссылке за пределы каталога распаковки (`sevenzip_does_not_follow_a_link_out_of_the_output`) | `7z i` или `7zz i`. Ищется в `ONCL_7Z`, в Windows ещё в каталоге `7-Zip` внутри `Program Files`, затем `7z` в `PATH`. Пакеты Ubuntu (`7zip`, `p7zip`) старее: консольную версию `7zz` для Linux и macOS возьмите на [7-zip.org](https://www.7-zip.org/download.html) и укажите в `ONCL_7Z`. CI на Linux и macOS скачивает 26.06 со сверкой sha256, на Windows берёт 7-Zip из образа раннера |
| Отдельное окружение Python | независимая проверка подписей: pyHanko, lxml, cryptography, asn1crypto, gostcrypto | см. ниже |
| Тестовые данные NCANode | файлы для тестов | `cargo xtask fetch-fixtures` |

Docker, Node.js и браузеры для обычного `cargo test` не нужны, они используются только в отдельных проверках ниже.

### 1. OpenSSL

Нужен OpenSSL 3 с командами `cms` и `pkcs12 -legacy`. В CI он берётся так: на Linux тот, что уже есть в образе раннера, на Windows OpenSSL из Git for Windows, на macOS Homebrew (`openssl@3`).

Linux. Обычно OpenSSL уже установлен. Если нет: `sudo apt-get install -y openssl`.

macOS. Системный `openssl` на самом деле LibreSSL и не подходит. Поставьте OpenSSL 3 и поместите его каталог первым в `PATH`:

```sh
brew install openssl@3
export PATH="$(brew --prefix openssl@3)/bin:$PATH"
```

Windows. Установите OpenSSL и добавьте его каталог `bin` в `PATH`:

```powershell
winget install -e --id ShiningLight.OpenSSL.Light
```

Установщик кладёт OpenSSL в каталог `OpenSSL-Win64` внутри `Program Files`. Добавьте `<каталог OpenSSL>\bin` в `PATH` (Параметры, Система, О системе, Дополнительные параметры системы, Переменные среды) и откройте новое окно терминала. Проверка:

```powershell
openssl version
```

Тесты ищут OpenSSL сначала в переменной `ONCL_OPENSSL` (полный путь к `openssl`), потом в `PATH`, а в Windows ещё и среди файлов Git for Windows.

### 2. Отдельное окружение Python

Нужен Python 3.12 или новее (в CI стоит 3.12). Пакеты не ставьте в системный Python. Создайте для них venv, то есть изолированное окружение Python со своим интерпретатором и своим набором пакетов. Каталог `.venv-oracle` в корне репозитория коммитить не нужно. Список пакетов лежит в `xtask/assets/oracle/requirements.txt`.

Linux и macOS:

```sh
python3 -m venv .venv-oracle
.venv-oracle/bin/python -m pip install --require-virtualenv -r xtask/assets/oracle/requirements.txt
export ONCL_PYHANKO_PYTHON="$PWD/.venv-oracle/bin/python"
```

Windows (PowerShell):

```powershell
python -m venv .venv-oracle
.venv-oracle\Scripts\python.exe -m pip install --require-virtualenv -r xtask\assets\oracle\requirements.txt
$env:ONCL_PYHANKO_PYTHON = "$PWD\.venv-oracle\Scripts\python.exe"
```

Windows (Git Bash):

```sh
python -m venv .venv-oracle
.venv-oracle/Scripts/python.exe -m pip install --require-virtualenv -r xtask/assets/oracle/requirements.txt
export ONCL_PYHANKO_PYTHON="$PWD/.venv-oracle/Scripts/python.exe"
```

Вместо `python -m venv` можно использовать `uv`: `uv venv .venv-oracle`, затем `uv pip install --python .venv-oracle/bin/python -r xtask/assets/oracle/requirements.txt` (в Windows путь `.venv-oracle\Scripts\python.exe`).

С ключом `--require-virtualenv` `pip` откажется ставить пакеты, если случайно запущен не из окружения.

Проверьте, что пакеты встали:

```sh
"$ONCL_PYHANKO_PYTHON" -c "import pyhanko, lxml, cryptography, asn1crypto, gostcrypto"
```

(В PowerShell: `& $env:ONCL_PYHANKO_PYTHON -c "import pyhanko, lxml, cryptography, asn1crypto, gostcrypto"`.)

Переменная `ONCL_PYHANKO_PYTHON` действует только в том терминале, где её задали. Чтобы она сохранялась, задайте её в настройках среды: в Windows командой `setx ONCL_PYHANKO_PYTHON <путь к python.exe окружения>` (подействует в новых терминалах), в Linux и macOS строкой `export` в `~/.profile` или `~/.zshrc`.

Тесты не берут первый попавшийся `python` из `PATH`, потому что в нём обычно нет `lxml`. Им нужен интерпретатор окружения из `ONCL_PYHANKO_PYTHON`. Если переменная не задана или файла нет, тест пропускается со строкой `skipped: ...`, а с `ONCL_REQUIRE_ORACLES=1` падает и ссылается на этот раздел.

### 3. Тестовые данные

```sh
cargo xtask fetch-fixtures
```

Команда скачивает тестовые файлы [NCANode](https://github.com/ncanode-kz/NCANode) с закреплённого коммита в `target/fixtures/ncanode/` и проверяет их sha256. Файлы в репозиторий не попадают. Если они уже скачаны, повторный запуск ничего не загружает.

### 4. Консоль Windows, реестр cargo и порты

Эти тесты не падают, а пропускаются, если нужного нет, и пишут причину.

- **Консоль Windows.** Тесты Ctrl-Break в `oncl-cli` (`signal`, `batch_signal`, `remote_signal`) и тесты ConPTY (`terminal`) работают только там, где у cargo есть консоль. Если его запустили без консоли (среда разработки, служба, оболочка агента), тест пишет строку `skipped: <имя теста> needs a console to deliver CTRL_BREAK through; see …` (видна так же, как строки о недостающих программах выше) и завершается успешно. Запустите их из обычного окна терминала: `cargo test -p oncl-cli --all-features`. С `ONCL_REQUIRE_ORACLES=1` (так в CI) отсутствие консоли станет ошибкой.
- **Пакеты всех платформ.** Тесты `xtask` `sdk_delivery` и `licenses_fresh` читают из локального реестра cargo пакеты всех платформ, а обычная сборка скачивает только пакеты своей системы. Пока их нет, тесты пишут `not checked` (видно с `-- --nocapture`) и пропускаются. Чтобы проверить их, один раз выполните `cargo fetch --locked`, дальше сеть не нужна. В CI (задана `CI`) нехватка пакетов считается ошибкой.
- **Порты демона.** Демон слушает только порты 13579–13679 (`NCALAYERPORT`), поэтому порт 0 тестам не подходит. Тесты, которые запускают демон, берут порт из 13580–13679 через `oncl_testkit::ports::DaemonPort`: порт резервируется блокировкой файла `oncl-test-ports/<порт>.lock` в каталоге временных файлов. Поэтому порт не делят ни потоки `cargo test`, ни процессы `cargo nextest`, и отдельная группа в `.config/nextest.toml` этим тестам не нужна. Порт 13579 тесты не трогают, на нём может работать настоящий NCALayer. Если тест пишет `no free daemon port`, освободите порты этого диапазона.

## Разработка

### Тесты

```sh
cargo build --workspace
cargo xtask fetch-fixtures
cargo test --workspace --all-features
```

Сначала выполните шаги из раздела «Что нужно для тестов». Полный набор тестов большой, CI делит его на три части (раздел [«Что запускает CI»](#что-запускает-ci)).

Команда `cargo test -p <крейт>` не включает необязательные возможности (features), которые нужны тестам. Тест, которому нужна возможность, без неё отключён: модуль в `tests/all/main.rs` помечен `#[cfg(feature = …)]` или отдельная тестовая программа описана в `Cargo.toml` с `required-features`. Cargo такие тесты молча не собирает и не запускает: ошибки нет, просто тестов в выводе меньше. Так у `oncl-pki` без возможности `testing` выпадают 11 модулей `tests/all` и программа `cms_stream`. Так же у `oncl-api`, `oncl-core`, `oncl-flows`, `oncl-plugin`, `oncl-token`, `oncl-xml`, `oncl-winget-setup`, `oncl-cli` и `openncalayer`. Когда работаете над одним крейтом, запускайте с `--all-features`, как в CI:

```sh
cargo test -p oncl-pki --all-features
```

Если нужна одна возможность, укажите её: `cargo test -p oncl-pki --features testing`. `cargo test --workspace` включает эти возможности сам, потому что их просят другие крейты. Чередовать `-p <крейт>` и `--workspace` не стоит: наборы возможностей разные, и cargo каждый раз пересобирает зависящие крейты.

Тестовые ключи в `fixtures/synthetic/` синтетические, пароль у них `Qwerty12`. Их можно использовать на демо-странице. По умолчанию демо отправляет `chain: []`, и тогда подходят и синтетические ключи, и тестовые ключи NCANode. Вариант «синтетический тестовый корень» передаёт `root-gost2015`, и ключи других корней и промежуточного CA становятся недоступны.

#### Тесты с настоящими сервисами НУЦ

Тесты с префиксом `live_` обращаются к настоящим сервисам НУЦ, поэтому по умолчанию не запускаются:

```sh
cargo test --workspace --all-features -- --ignored live_
```

Их три:
- `live_test_tsa`: тестовая служба времени (TSP) НУЦ;
- `live_ocsp_nca_test_certificate`: тестовый OCSP НУЦ (нужен `cargo xtask fetch-fixtures`);
- `live_crl_nca_root_gost_2022`: CRL промышленного `crl.root.gov.kz`.

Они зависят от внешних сервисов, поэтому в CI их запускает только job `live` в `scheduled.yml`: по понедельникам (03:00 UTC) и вручную (Actions → Scheduled → Run workflow, `live`). Если такой тест один раз упал из-за сети, перезапустите его. Тестовый RSA-ответчик OCSP НУЦ отвечает `malformedRequest` на стандартные запросы, в том числе от OpenSSL, поэтому OCSP проверяется на ГОСТ-сертификате.

#### Встроенные модули без маркеров

Тесты встроенных модулей (`cargo test -p oncl-builtin-tests`) проходят и без маркеров. Обычно ядро заменяет длинные строки запроса маркерами. При `ONCL_TEST_NO_MARKERS=1` модуль читает строки как есть, и все тесты проходят так же. Тест `markers` сравнивает ответы с маркерами и без них для каждой строки запросов покрытых методов, увеличенной до 20 000 байт (и для пачки документов длиннее 1 МиБ).

#### Что собирается внутри сборки и тестов

Встроенные модули (WebAssembly) собирает скрипт сборки `openncalayer` и `oncl-builtin-tests`. Сборка одна на весь каталог `target`: модули лежат в `target/builtins-target` (или в `$CARGO_TARGET_DIR/builtins-target`), и оба крейта, все профили и `cargo check` берут их оттуда. Если два скрипта сборки запустились одновременно, второй ждёт первого. Пересобираются модули, только когда меняются `src`, `Cargo.toml` или `plugin.toml` в `crates/oncl-pdk`, `crates/oncl-protocol` и `crates/oncl-builtin-*` (кроме `crates/oncl-builtin-tests`), корневые `Cargo.toml`, `Cargo.lock` или `rust-toolchain.toml`. `cargo xtask builtins build` собирает в тот же `builtins-target`. Если файл блокировки взять нельзя (файловая система без блокировок), сборка идёт без неё и Cargo выводит предупреждение.

Модули можно собрать один раз и не собирать больше вовсе:

```sh
cargo xtask builtins build                      # → target/builtins
export ONCL_BUILTINS_DIR="$PWD/target/builtins"  # в PowerShell: $env:ONCL_BUILTINS_DIR = "$PWD\target\builtins"
```

С `ONCL_BUILTINS_DIR` скрипт сборки берёт готовые модули и сверяет их с исходниками. Если исходники модулей изменились, сборка падает с ошибкой «built from other sources»: пересоберите модули той же командой.

Отладочная сборка `openncalayer` пишет в окне «О программе» коммит `dev`. Коммит из git попадает только в сборку с `--release`: иначе после каждого коммита и `git checkout` крейт пересобирался бы вместе со своими тестами.

Тесты плагинов сами собирают пример `crates/oncl-pdk/example` и порты из `plugins/`, один раз на процесс, в `target/plugin-example` и `target/plugin-ports`. Пример собирается в `release`. Порты по умолчанию собираются в профиле `plugin-test`: это `release` без LTO, в 16 единицах компиляции и с `opt-level = 1`. Профиль описан в `plugins/Cargo.toml`, так что тесты, CI и сборка вручную (`cargo build --profile plugin-test --manifest-path plugins/Cargo.toml …`) собирают одно и то же. Импорты хоста у портов в нём те же, что в `release`. У примера без LTO импортов больше, чем объявлено в его `plugin.toml`, поэтому он остаётся в `release`.

Плагины выходят в релизы собранными в `release`. В CI тесты портов на такой сборке гоняет задача `plugins-release` (в `main` и ночью). Локально так:

```sh
ONCL_PORTS_PROFILE=release cargo test -p oncl-port-tests
# в PowerShell: $env:ONCL_PORTS_PROFILE = "release"; cargo test -p oncl-port-tests
```

Модули портов лежат в `target/plugin-ports/wasm32-unknown-unknown/<профиль>/`. Кроме `release` и `plugin-test`, другие значения `ONCL_PORTS_PROFILE` тесты не принимают.

### Расширение браузера

```sh
node --test "extension/test/*.test.mjs"   # тесты расширения, Node 22 и новее
cargo xtask ext build                     # → target/extension/
```

Сквозная проверка расширения в Chrome for Testing, Firefox и Firefox ESR 115 работает только на Linux. Браузеры и драйверы скачиваются в `target/browsers/`:

```sh
cargo build --release -p openncalayer --features e2e-prompter -p oncl-nmhost
cargo xtask ext build
cargo xtask ext-e2e --download
```

- Без `--download` пути к браузерам берутся из переменных `ONCL_CHROME`, `ONCL_CHROMEDRIVER`, `ONCL_FIREFOX`, `ONCL_FIREFOX_ESR` и `ONCL_GECKODRIVER`.
- Один браузер выбирается ключом `--browser chromium|firefox|firefox-esr`.
- Для Firefox ESR 115 нужна системная библиотека `libdbus-glib-1-2`.
- Браузеры запускаются с одноразовыми профилями в `target/ext-e2e/`, хост регистрируется там же (`nm install --sandbox`).
- Фича `e2e-prompter` заменяет окна подписи сценарием из файла `ONCL_E2E_PROMPTER`. В обычные сборки она не входит.
- Если шаг сценария не подходит к открывшемуся окну (например, ответ для окна ключа пришёл окну хранилища), вызов не падает. Окно отменяется, в журнал пишется строка `… the window is cancelled`, страница получает обычный ответ об отмене, и соединение остаётся открытым.
- Сценарий 8 удаляет расширение при открытой странице. Он работает только в Firefox, а в ESR 115 проверяет ограничение этой версии, описанное в [документации расширения](../user/browser-extension.md).

### Проверка подписей в NCANode

Проверка наших подписей XMLDSig и CMS в NCANode (Kalkan). Работает только на Linux, нужен Docker:

```sh
cargo xtask fetch-fixtures && cargo xtask interop-ncanode
```

Образ, порядок запуска и результат описаны в [`interop-ncanode.md`](interop-ncanode.md).

### Сборка для Windows 7

Собирается только в Windows, нужен закреплённый nightly Rust:

```sh
rustup toolchain install nightly-2026-08-12 --profile minimal --component rust-src
cargo xtask win7 --arch all   # → target/win7/x64/, target/win7/x86/
```

`cargo xtask win7` собирает `openncalayer.exe` и `nmhost.exe` для 64- и 32-битной Windows 7 со статическим CRT, поэтому VC++ redist не нужен. Рядом кладутся две DLL-заглушки, потому что в Windows 7 нет `combase.dll` и `api-ms-win-core-winrt-error-l1-1-0.dll`. Заглушки передают нужные вызовы в `ole32.dll` или ничего не делают. Windows 8 и новее эти копии не загружают.

Затем запускается проверка импортов (отдельно: `cargo xtask check-imports <exe>…`). Сборка не проходит, если:
- программа импортирует DLL или функцию из списка отсутствующих в Windows 7. Это чёрный список: импорт из Windows 8+, которого в списке нет, проверка пропустит;
- импорт из `combase.dll` или `api-ms-win-core-winrt-error-l1-1-0.dll` не подкреплён одноимённой DLL рядом с exe, которая экспортирует именно эту функцию;
- сами эти DLL другой разрядности, чем exe, или импортируют что-то кроме `kernel32.dll` и `ole32.dll`;
- `nmhost.exe` зависит от этих DLL. Он должен обходиться без них, потому что `nm install` копирует relay отдельно от программы.

После проверки в Windows `cargo xtask win7` запускает собранную программу: `--help`, `nm install` и `nm status` в песочнице, `tls init`, затем `run` до ответа на `GET /` по HTTPS. Данные при этом лежат во временном каталоге в `target/win7-smoke/`. В CI это обязательный job `win7` (x64 и x86 на Windows Server 2025). На настоящей Windows 7 CI ничего не проверяет.

Ключ `--target-dir <каталог>` задаёт каталог сборки вместо `target/`. Job `win7` кэширует его целиком: обычный кэш cargo выбрасывает стандартную библиотеку `-Zbuild-std`, и без неё всё пересобирается заново.

### Перед отправкой изменений

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
cargo xtask licenses --check   # сторонние лицензии для окна «О программе» свежие
```

Если менялись `updates/` или `tuf/` (проверки индексов и репозитория TUF описаны в разделах 3 и 10 [`release.md`](release.md)):

```sh
cargo xtask index check updates/v1 --offline --base origin/main
cargo xtask tuf check --no-timestamp --base origin/main
```

### Что запускает CI

Workflow `.github/workflows/ci.yml`. Обязательная проверка репозитория называется `check`: это последнее задание `ci.yml`. Оно падает, если упало или отменено любое задание, которое нужно этому запуску, или если такое задание пропущено. Задание, которое пропущено потому, что изменение его не касается, проверку не валит.

Полный запуск идёт на каждый пуш в `main`, каждую ночь (02:30 UTC), вручную (Actions → CI → Run workflow) и на PR с меткой `full-ci`. Метку можно повесить на открытый PR: CI сразу начнёт полный запуск заново. Любая другая метка тоже перезапускает CI на PR и отменяет запуск, который шёл. Ручной запуск не на `main` проверяет всё, но `check` в нём красный: обязательным статусом он быть не может.

Если у PR сменили базовую ветку, CI сам не перезапускается: отправьте новый коммит или снимите и снова повесьте метку.

`live` (тесты с настоящими сервисами НУЦ) и `bench` лежат в отдельном workflow `scheduled.yml`: `live` идёт по понедельникам, оба можно запустить вручную. В `check` они не входят.

Обычный PR проверяется так:

- `fmt`, `privacy` (`privacy.yml`), `index` (`index-check.yml`) и `actionlint` идут в каждом запуске. Тяжёлые задания ждут `fmt` и `privacy`, поэтому ошибка форматирования не занимает раннеры на час.
- Если PR меняет только документацию (`docs/`, кроме `docs/dev/sdk*.md`, а также `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, `AGENTS.md`, `CLAUDE.md`, `.agents/`, шаблоны issue и PR), сборки и тесты не запускаются. Если только `updates/` или `tuf/`, запускаются `index` и `site`.
- Сборка пакетов (`win7`, `windows-package`, `linux-appimage`) и `builtins-x86` идут, только если PR меняет то, из чего они собираются: `crates/`, `xtask/`, `web/`, `deploy/`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.cargo/`, `.gitattributes`, `.github/workflows/`, `.github/actions/`, `README.md`, `LICENSE`, `NOTICE`.
- На macOS идёт одно задание `test-macos`: тесты крейтов, где есть свой код для macOS, и `oncl-cli`. Весь набор на macOS и `macos-universal` идут только в полном запуске.

Как идут тесты:

- `prepare` один раз на Linux собирает встроенные модули (`cargo xtask builtins build`) и скачивает тестовые данные NCANode. Остальные задания берут модули из артефакта через `ONCL_BUILTINS_DIR`, как `release.yml`. Модули принимаются, только если собраны из тех же исходников тем же тулчейном.
- `test-build` на каждой ОС собирает все тесты один раз (`cargo nextest archive`). Задания `test (<ОС>, N/3)` запускают из архива по трети тестов (`--partition slice:N/3`). В архив не попадают файлы PDB, поэтому у упавшего в CI теста на Windows в backtrace нет номеров строк.
- Задания `test` ничего не собирают, поэтому перед запуском скачивают пакеты всех платформ: `cargo fetch --locked` для workspace и для `plugins/`. Их офлайн читают из реестра cargo тесты лицензий и тесты SDK (замыкание зависимостей и перечень лицензий). Без этого шага они падают на любой ОС.
- Настройки [cargo-nextest](https://nexte.st) лежат в `.config/nextest.toml`, профиль `ci`. Упавший тест перезапускается до двух раз. Если потом он прошёл, nextest помечает его FLAKY, а запуск всё равно красный. Тест дольше 30 минут снимается. Отчёт JUnit сохраняется артефактом `junit-<ОС>-<N>-<попытка>`.
- `no-markers` прогоняет тесты встроенных модулей с `ONCL_TEST_NO_MARKERS=1`. `linux-checks` запускает doctest-ы и проверки xtask: `check-release-features`, `sdk closure`, `plugin-ops-check` (на модулях профиля `plugin-test`), `plugin-version-check`, `interop-openssl`. На Windows и macOS doctest-ы идут только в полном запуске, в задании `doctests`.
- В `main` и ночью `plugins-release` прогоняет тесты портов с `ONCL_PORTS_PROFILE=release`, то есть на модулях, собранных так же, как они выходят, и проверяет на этих модулях `plugin-ops-check`.
- CI задаёт `ONCL_REQUIRE_ORACLES=1`: тест, которому не хватает внешней программы, в CI падает, а не пропускается.

Те же тесты локально через nextest (`cargo install cargo-nextest`):

```sh
cargo nextest run --workspace --all-features --profile ci --run-ignored all
```

Обычный `cargo test` работает как раньше.

### Клиент демо-страницы

`web/demo/vendor/ncalayer-client.js` взят без изменений из npm-пакета `ncalayer-js-client@1.6.1` (файл `package/ncalayer-client.js`, лицензия MIT, sha256 `bdf2015c3e422eed70ccf38eef3246af67a0d38639e6b70fe6b8655a2fa03489`). Тест `demo_assets_served` сверяет sha256 файла, который отдаёт сервер. Лицензия клиента лежит рядом: `/demo/vendor/LICENSE`.

## Форки сторонних крейтов

Три крейта с crates.io нужны нам с небольшими изменениями. Их исходников в репозитории нет: они берутся по git из форков в аккаунте `arynyklas`. Версия форка закреплена полным коммитом (`rev`) в корневом `Cargo.toml`.

- `i-slint-backend-winit` и `velopack` подменяются в `[patch.crates-io]`.
- `multer` указан с `git` и `rev` в `[workspace.dependencies]`, чтобы проект, который подключает сервер вне этого workspace, получил тот же исходник.
- Каждое изменение лежит отдельным подписанным коммитом в ветке форка `openncalayer/<крейт>-<версия>`. Ветка начинается с коммита апстрима, из которого опубликован крейт (он записан в `.cargo_vcs_info.json` пакета).
- Ветки не переписываются. Новая правка означает новый коммит и новый `rev`.

| Крейт | Форк и ветка | Откуда | Что изменено |
|---|---|---|---|
| `i-slint-backend-winit` 1.18.1 | [`arynyklas/slint`](https://github.com/arynyklas/slint), `openncalayer/i-slint-backend-winit-1.18.1` | [`slint-ui/slint`](https://github.com/slint-ui/slint), каталог `internal/backends/winit` | Функция `SystemParametersInfoForDpi` (есть с Windows 10 1607) не импортируется, а ищется через `GetProcAddress` (`windows_message_font_height` в `lib.rs`, её вызывает `bind_context`). Если функции нет, вызывается `SystemParametersInfoW(SPI_GETNONCLIENTMETRICS)`, и высота шрифта пересчитывается из системного DPI в 96. Так сборке для Windows 7 не нужна отсутствующая там функция, а на Windows 10/11 поведение прежнее. Для этого включена фича `Win32_System_LibraryLoader` крейта `windows`. Ещё три коммита касаются упаковки: внутренние крейты Slint и `vtable` указаны по версии, а не по пути (иначе git-зависимость принесла бы вторую копию с несовместимыми типами), а тексты лицензий в `LICENSES/` сделаны обычными файлами вместо symlink. |
| `velopack` 1.3.39-g8d2844f | [`arynyklas/velopack`](https://github.com/arynyklas/velopack), `openncalayer/velopack-1.3.39-g8d2844f` | [`velopack/velopack`](https://github.com/velopack/velopack), каталог `src/lib-rust` | В `UpdateSource` добавлен метод `verify_full_package` (по умолчанию проверяет размер и контрольную сумму, как сам Velopack). `download_updates` проверяет им полный пакет, уже лежащий на диске (непрошедший удаляется и скачивается заново), и пакет, собранный из дельты, до переименования и до извлечения `Squirrel.exe` (Update.exe). Непрошедший пакет заменяется скачанным полным. Наш `IndexSource` принимает файл, если он совпадает с полным пакетом из подписанного индекса по sha256 и размеру или содержит те же файлы (`contents_sha256` индекса). Ещё два коммита касаются упаковки: версия крейта (в репозитории `0.0.0-local`, релиз подставляет опубликованную) и файл `LICENSE` в каталоге крейта (в пакете crates.io его нет). |
| `multer` 3.1.0 | [`arynyklas/multer`](https://github.com/arynyklas/multer), `openncalayer/multer-3.1.0` | [`rwf2/multer`](https://github.com/rwf2/multer) | `Constraints::framing_observer`: необязательный наблюдатель за служебными байтами multipart (границы, заголовки частей, отступы), разбор он не меняет. Также `cfg(nightly)` для check-cfg и `u64::MAX` и проверенное сложение счётчика размера потока (`StreamSizeExceeded` вместо переполнения). |

Лицензии:
- `multer` и `velopack`: MIT;
- `i-slint-backend-winit`: Slint Royalty-free 2.0. Она разрешает изменять программу и распространять изменённую копию в составе приложения (разделы 1 и 2), уведомления о лицензии в файлах сохранены.

Полные тексты попадают в `THIRD-PARTY.txt` вместе с остальными зависимостями, подробности в `NOTICE`.

Тест `xtask/tests/forks.rs` падает, если:
- патч не используется (`Cargo.lock` снова берёт пакет с crates.io);
- `multer` взят не из форка;
- версия `i-slint-backend-winit` разошлась с версией Slint;
- `streebog` или `hmac` снова взяты не из crates.io.

Раньше форками были и `streebog`, и `hmac`: в них были варианты для секретного ввода. Теперь эти варианты — код самого `oncl-gost`. `src/streebog_secret.rs` — Streebog для секретов: таблица LPS не читается по секретному индексу, временные значения сжатия лежат в одной рабочей области и стираются после каждого блока, всё состояние выделено в куче одним блоком, а после вывода дайджеста обнуляется. `src/secret_hmac.rs` — HMAC поверх него для KDF из `wrap`: блок ключа, хеш длинного ключа и внутренний дайджест стираются, в том числе при панике. Откуда взят код и под какой он лицензией — в `NOTICE`. Публичные документы, PKCS#12 и PBKDF2 хешируются обычными `streebog` и `hmac` с crates.io.

`cargo deny check` разрешает только git-источники этих форков (`[sources] allow-git` в `deny.toml`).

Как обновить крейт:
1. Перенесите ветку форка на новый тег апстрима (`git rebase`).
2. Запушьте её под именем новой версии.
3. Поменяйте `rev` (и версию, если она закреплена, как у `velopack`).
4. Обновите `Cargo.lock` и этот раздел.

## Сайт проекта: локальная сборка

Сайт собирается командой `cargo xtask registry build`. Zola 0.23.6 скачивается в `target/tools/` и проверяется по sha256. Результат появляется в `target/site/public`, ссылки и правила страниц проверяются сразу после сборки. Отдельно проверить готовый каталог можно командой `cargo xtask registry check <каталог>`.

Посмотреть сайт в браузере:

```sh
target/tools/zola-v0.23.6/zola --root target/site/src serve
```

Тесты сборки сайта с Zola называются `zola_…` и по умолчанию не запускаются:

```sh
cargo test -p xtask --test registry_site -- --ignored zola_
```

В CI их запускает job `site`.

Исходники сайта (настройки, шаблоны, стили, тексты) лежат в `site/`. Страницы портов и издателей и `data/site.json` генерируются в `target/site/src` и не коммитятся. Издателей сайт берёт из `publishers/*/publisher.toml`, их плагины — из последнего файла роли каждого издателя в `tuf/v1/metadata/` (подписи проверяет `tuf check`, не сайт). Цель роли, которую клиент не принял бы, на сайт не попадает, сборка пишет о ней предупреждение. Другие каталоги задают `--publishers` и `--tuf`.
