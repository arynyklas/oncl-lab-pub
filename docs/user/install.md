# Установка и сборки

Где взять OpenNCALayer, что делают установщики и как удалить программу. Работа с программой после установки описана в [«Рабочем столе»](desktop.md), настройка сертификата в [`tls.md`](tls.md), расширение браузера в [`browser-extension.md`](browser-extension.md).

## Готовые сборки

В [Releases](https://github.com/arynyklas/OpenNCALayer/releases) лежат:
- установщики (раздел [«Установка»](#установка));
- архивы для Windows x64 и x86 (`x86_64-pc-windows-msvc`, `i686-pc-windows-msvc`);
- архивы для Windows 7 SP1 x64 и x86 (`win7-x64`, `win7-x86`). Вместе с программами в них лежат `combase.dll` и `api-ms-win-core-winrt-error-l1-1-0.dll`, держите их в одном каталоге;
- архив для Linux x64 (`x86_64-unknown-linux-gnu`). Он собран в контейнере с glibc 2.28 и работает с glibc 2.28 и новее;
- универсальный архив для macOS на Intel и Apple Silicon (`universal-apple-darwin`) с `openncalayer` и `nmhost`;
- пакет для Arch Linux (`openncalayer-bin-*-x86_64.pkg.tar.zst`);
- пакеты Velopack для автообновления (`OpenNCALayer-<версия>-<вариант>-full.nupkg` и дельты) и файлы каналов Velopack `RELEASES-<вариант>` и `releases.<вариант>.json`, где вариант означает сборку под конкретную систему (`win-x64`, `win7-x86`, `osx` и т. п.);
- расширения `openncalayer-chromium-<версия>.zip` и `openncalayer-firefox-<версия>.xpi`. XPI не подписан, поэтому в Firefox ставится только временно;
- SBOM `openncalayer-<версия>.cdx.json` (CycloneDX) и контрольные суммы `SHA256SUMS`;
- `builtins-SHA256SUMS`, суммы вшитых модулей (см. `openncalayer builtins`);
- `openncalayer-<версия>-win-x64-winget-setup.exe` и `…-win-x86-winget-setup.exe`. Это не обычный установщик, а файл для WinGet ([`docs/dev/winget.md`](../dev/winget.md)).

Для каждого файла есть аттестация происхождения сборки: `gh attestation verify <файл> --repo arynyklas/OpenNCALayer --signer-workflow arynyklas/OpenNCALayer/.github/workflows/release.yml`. Без `--signer-workflow` проверка пройдёт и для пакетов сторонних издателей из выпусков `pub-*`: их аттестует бот этого же репозитория, и она означает только то, что пакет пересобран CI проекта из архива исходников издателя, а не то, что это программа OpenNCALayer или что её код проверен. Версии с суффиксом (например, `-rc.1`) предварительные. Подпись кода включается секретами мейнтейнера ([`docs/dev/release.md`](../dev/release.md), раздел 1), поэтому программы и установщики могут быть не подписаны, и при первом запуске Windows SmartScreen или macOS Gatekeeper покажут предупреждение. Релиз собирается и публикуется автоматически по тегу `v<версия>` (`.github/workflows/release.yml`, см. [«Публикация»](../design/update-index.md#публикация)).

Распакованный архив запускается так же, как своя сборка: `openncalayer run`, а расширение ставится по разделу [«Расширение браузера»](browser-extension.md). Встроить распакованную копию в систему так, как это делает установщик, можно командой `openncalayer integration install`.

Последний релиз и предварительная версия с пояснением к каждому файлу есть на странице [«Загрузка»](https://arynyklas.github.io/OpenNCALayer/download/) сайта проекта.

## Установка

Установщики ставят OpenNCALayer для того пользователя, который их запускает, и не требуют прав администратора (кроме `.pkg` в `/Applications`). Сертификаты они не ставят и не удаляют, TLS настраивается мастером «Сертификат для браузера…» (раздел [«Мастер TLS»](desktop.md#мастер-tls)). Каталог данных (настройки, сертификаты TLS, журналы) хранится отдельно от программы и сохраняется при обновлении и удалении.

### Windows 10 и 11

Установщик `openncalayer-<версия>-win-x64-setup.exe`, для 32-битной системы `openncalayer-<версия>-win-x86-setup.exe`. Для Windows 7 SP1 есть `openncalayer-<версия>-win7-x64-setup.exe` и `openncalayer-<версия>-win7-x86-setup.exe` с DLL рядом с программой (см. [«Windows 7»](#windows-7)). Установщик проверяет систему заранее: `win-*` не ставится на Windows 7 и 8, `win7-*` требует Windows 7 SP1, 64-битный требует 64-битную Windows.

Программа ставится в `%LOCALAPPDATA%\OpenNCALayer`: версия в `current\`, relay браузеров `nmhost.exe` рядом, вне `current`. В меню «Пуск» появляется «OpenNCALayer», после установки программа запускается. Удалить её можно в «Параметры» → «Приложения» (или «Программы и компоненты»), при этом удаляется весь `%LOCALAPPDATA%\OpenNCALayer`.

### macOS

Одна универсальная программа для Intel и Apple Silicon. `openncalayer-<версия>-osx.pkg` ставит `OpenNCALayer.app` в `/Applications` или, при выборе «Установить только для меня», в `~/Applications`, встраивает её для вошедшего пользователя и запускает. `openncalayer-<версия>-osx.zip` содержит то же приложение без установщика: перетащите его в «Программы» и запустите.

Удаление: `"/Applications/OpenNCALayer.app/Contents/MacOS/openncalayer" integration uninstall` (при установке «только для меня» `"$HOME/Applications/OpenNCALayer.app/Contents/MacOS/openncalayer" integration uninstall`), затем переместите приложение в Корзину.

Сборка для macOS не подписана Apple и не нотаризована (подпись включается секретами мейнтейнера, [`docs/dev/release.md`](../dev/release.md), раздел 1). Gatekeeper откажется открыть скачанный в браузере `.pkg`, а затем и приложение, как программу неустановленного разработчика. Разрешите её в «Системные настройки» → «Конфиденциальность и безопасность» → «Всё равно открыть» («Open Anyway») и откройте снова. Этот путь на реальном Mac вручную не проверялся.

Что проверяется автоматически. Workflow `mac-smoke.yml` после выпуска каждого тега (и по запросу) ставит `.pkg` этого тега командой `installer -target CurrentUserHomeDirectory` на GitHub Actions, на Mac с Apple Silicon (`macos-15`) и с Intel (`macos-15-intel`). Он проверяет контрольную сумму из `SHA256SUMS` и аттестацию происхождения, версию (`openncalayer --version`), оба среза (`x86_64` и `arm64`) у `openncalayer` и `nmhost` (`lipo -archs`), встраивание (`installation.json`, LaunchAgent, `"autostart": true`, relay), `tls init` и запуск демона: порт 13579 слушает только 127.0.0.1, есть каталог данных и журнал, встроенные модули, страница `/openncalayer/selftest` по TLS, рукопожатие wss, приветствие, `--heartbeat--`, `getServices` и `getBundles`. Затем выполняются `integration uninstall` и удаление приложения, и проверяется, что каталог данных сохранился. Самообновление проверяет workflow `mac-selfupdate.yml`, который запускается вручную: он ставит опубликованный `.pkg`, ждёт, пока демон сам обновится по опубликованному индексу, и проверяет, что новая версия запустилась и слушает порт 13579. Не проверены нотаризация, окно Gatekeeper, значок в строке меню (демон в CI запускается с `--no-tray`), работа расширения в браузерах на Mac и подписание ключом на Mac.

### Linux

Нужен x86-64 и glibc 2.28 или новее: Debian 10, Ubuntu 18.10, RHEL/AlmaLinux/Rocky 8, Fedora 29, Arch и новее. Файл `openncalayer-<версия>-linux-x64.AppImage` положите туда, где он будет храниться (например, `~/Applications`), сделайте исполняемым (`chmod +x`) и запустите.

AppImage монтирует себя через FUSE 2, а в Ubuntu 22.04 и новее этой библиотеки по умолчанию нет, и файл напрямую не запустится. Поставьте её (`sudo apt install libfuse2`, в Ubuntu 24.04 пакет называется `libfuse2t64`) или запускайте AppImage с `--appimage-extract-and-run`: тогда он распаковывается во временный каталог и работает без FUSE. Программе нужен графический сеанс (X11 или Wayland). Без `DISPLAY` или `WAYLAND_DISPLAY` она сообщает об этом и завершается с кодом 1. Библиотеки xkbcommon, которых может не быть в системе, лежат внутри AppImage, остальное (glibc, fontconfig, X11 или Wayland) берётся из системы.

Удаление: `openncalayer-<версия>-linux-x64.AppImage integration uninstall`, затем удалите файл.

### Arch Linux

Подойдёт AppImage (он обновляется сам, см. выше) или пакет из [Releases](https://github.com/arynyklas/OpenNCALayer/releases). Скачайте `openncalayer-bin-*-x86_64.pkg.tar.zst` и `SHA256SUMS`, проверьте файл (`sha256sum -c --ignore-missing SHA256SUMS`) и поставьте: `sudo pacman -U ./openncalayer-bin-*.pkg.tar.zst`. Программы лежат в `/usr/lib/openncalayer/`, команда называется `openncalayer`, в меню появится «OpenNCALayer». Самообновление в пакете выключено, новые версии ставятся так же вручную. Перед удалением выполните `openncalayer integration uninstall` от имени каждого пользователя, который запускал программу, затем `sudo pacman -R openncalayer-bin`.

### WinGet

Пакета в WinGet пока нет. Команда `winget install --id arynyklas.OpenNCALayer --exact` заработает после того, как выйдет стабильный релиз (предварительные версии в WinGet не попадают), установка будет проверена на чистых Windows 10 и 11 и Microsoft примет манифест. Пакет рассчитан на Windows 10 1809 и новее, x64 и x86, установку для пользователя. Подготовка манифеста описана в [`docs/dev/winget.md`](../dev/winget.md). Пока ставьте `win-*-setup.exe` из [Releases](https://github.com/arynyklas/OpenNCALayer/releases).

### Что установка делает для пользователя

На Windows это делает установщик, на macOS `.pkg` для вошедшего пользователя. AppImage, пакет pacman, `.zip` и копии для пользователей, у которых установщик не запускался, делают то же при первом запуске программы:
- регистрирует relay браузеров, как `openncalayer nm install` (раздел [«Расширение браузера»](browser-extension.md));
- включает автозапуск OpenNCALayer (`HKCU\…\Run`, LaunchAgent `~/Library/LaunchAgents/io.github.arynyklas.openncalayer.plist`, `~/.config/autostart/openncalayer.desktop`) и записывает `"autostart": true` в `settings.json`;
- отключает автозапуск оригинального NCALayer у этого пользователя, не удаляя сам оригинал, так же как кнопка в настройках (раздел [«Оригинальный NCALayer»](desktop.md#оригинальный-ncalayer)). Общий для всех пользователей `HKLM\…\Run` не трогает;
- записывает в каталог данных `installation.json`: какая версия и откуда встроена.

Каждый шаг выполняется один раз и отмечается в `installation.json`. Повторный запуск установщика (того же или более нового `Setup.exe` или `.pkg`) и следующий запуск программы после неудачной установки доделывают несделанные шаги, а остальное обновляют так же, как при обновлении. Выбор, который пользователь сделал после первой установки, они не отменяют.

Обновление (самообновление, новый установщик, перенесённый AppImage, новый пакет pacman) заново копирует relay, если он зарегистрирован, и обновляет пути в его настройках и в нашем автозапуске. На Windows установщик поверх старой установки удаляет файлы relay, но не ключи реестра, поэтому relay ставится снова. То, что выключил пользователь, обновление не включает: выключенный автозапуск, удалённую регистрацию расширения, возвращённый оригинал.

Удаление убирает только то, что поставила программа: relay, его настройки, манифесты и ключи реестра браузеров, наш автозапуск. Автозапуск оригинала, который отключила установка, возвращается, если пользователь не вернул его раньше. Каталог данных остаётся.

Если шаг установки или обновления не удался, установщик Windows предупреждает, что установка не завершена, а `.pkg` сообщает об ошибке. Подробности пишутся в журнал программы (`logs/` каталога данных), а недоделанный шаг повторяется при следующем запуске установленной программы (это отмечено в `installation.json`). Для распакованного архива повторите `openncalayer integration install`.

При удалении в Windows ошибка шага только записывается в журнал: Velopack всё равно удаляет программу, и шаг не повторяется. Остатки уберите командой `openncalayer integration uninstall` из архива той же версии (`openncalayer-<версия>-x86_64-pc-windows-msvc.zip` и т. п.): она уберёт relay и наш автозапуск и вернёт автозапуск оригинала. Удаление стирает `installation.json` даже при ошибке, поэтому следующая установка выполнит все шаги заново, а оставшееся видно в `openncalayer integration status`.

Те же действия вручную: `openncalayer integration install`, `openncalayer integration uninstall`, состояние показывает `openncalayer integration status` (по шагам, с подсказкой, что делать; код 1, если установка не закончена или последнее обновление встраивания не удалось). Шаги этих команд тоже пишутся в журнал.

## Windows 7

Для Windows 7 SP1 есть отдельные архивы: `openncalayer-<версия>-win7-x64.zip` для 64-битной системы и `openncalayer-<версия>-win7-x86.zip` для 32-битной. На Windows 10 и 11 берите обычные `openncalayer-<версия>-x86_64-pc-windows-msvc.zip` и `openncalayer-<версия>-i686-pc-windows-msvc.zip` (x86). Все сборки для Windows собраны со статическим CRT, Visual C++ Redistributable не нужен. `cargo xtask package windows` не выпустит программу или установщик для Windows 10/11, которым он нужен.

В архиве для Windows 7 рядом с `openncalayer.exe` и `nmhost.exe` лежат две маленькие DLL. Распаковывайте архив целиком и держите их в одном каталоге с программой:
- `combase.dll` передаёт `CoTaskMemFree` и `CoCreateFreeThreadedMarshaler` в `ole32.dll`. Библиотеки `windows`, на которых построены окна (Slint и его зависимости), импортируют эти функции из `combase.dll`, а в Windows 7 её нет;
- `api-ms-win-core-winrt-error-l1-1-0.dll` содержит заглушки `RoOriginateErrorW` и `RoOriginateError`. В Windows 7 нет WinRT, сообщить об ошибке через него нельзя, поэтому заглушки ничего не делают и возвращают `FALSE`.

DLL экспортируют только эти функции и обращаются только к `kernel32.dll` и `ole32.dll`. Windows 8 и новее эти DLL не загружают: `combase.dll` там входит в KnownDLLs, а `api-ms-…` является набором API, и загрузчик берёт системные. Поэтому сборка для Windows 7 запускается и на новых Windows. Запуск проверен на Windows 11 и Windows Server 2025 (job `win7` в CI, x64 и x86), на Windows 10 не проверялся. Relay `nmhost.exe` этим DLL не пользуется, потому что `nm install` копирует его отдельно.

Для установки и обновления через Velopack релиз собирает из тех же файлов установщики `openncalayer-<версия>-win7-x64-setup.exe` и `openncalayer-<версия>-win7-x86-setup.exe` и пакеты вариантов `win7-x64` и `win7-x86`. Наши исполняемые файлы пакета, `Squirrel.exe` (Update.exe Velopack) с его заглушкой и сам `Setup.exe` проходят ту же проверку импортов в релизном workflow и в job `win7` CI (`cargo xtask package windows`).

Окна на Windows 7 берут размер шрифта по умолчанию из системных метрик (`SystemParametersInfoW`) с поправкой на DPI, потому что функции `SystemParametersInfoForDpi`, которой пользуется Slint, в Windows 7 нет (подробности в разделе [«Разработка»](../dev/development.md#разработка)).

Последние версии браузеров для Windows 7: Firefox ESR 115 и Chrome 109. Расширение ставится в Firefox ESR 115 так же, как в обычный Firefox (раздел [«Расширение браузера»](browser-extension.md)). Шим там работает через Xray, и у этого режима свои ограничения. Подкласс `WebSocket` страницы не получает свой класс ни для какого адреса (в остальных браузерах только для адресов NCALayer), а после отключения, удаления или обновления расширения открытые вкладки нужно перезагрузить (раздел [«Отличия и ограничения расширения»](browser-extension.md#отличия-и-ограничения-расширения)). Сквозная проверка расширения проходит в Firefox ESR 115 на Linux.

В лаборатории проекта на Windows 7 проверены архив и запуск программы, расширение в Chrome 109 и Firefox ESR 115, установщик с перезагрузкой и удаление. Автоматически проверяются импорт каждой функции (ни одной DLL и функции из списка Windows 8+) и запуск сборки на Windows 11 и Windows Server 2025 (CI). Сверки импортов с полным списком экспортов Windows 7 SP1 нет.

## Сайт проекта

[arynyklas.github.io/OpenNCALayer](https://arynyklas.github.io/OpenNCALayer/) на русском, казахском (`/kk/`) и английском (`/en/`):

- [«Плагины»](https://arynyklas.github.io/OpenNCALayer/plugins/): каталог портов плагинов оригинала. Для каждого порта указано, какой бандл он заменяет, состояние и сверка, версии в каналах `beta` и `stable` и изменился ли бандл у оригинала после переноса. У каждого порта своя страница с возможностями и отличиями от оригинала. Строка бандла имеет якорь `#<symname>`, на него ведёт подсказка `installBundle`.
- [«Загрузка»](https://arynyklas.github.io/OpenNCALayer/download/): последний релиз и предварительная версия, проверка файлов.
- [«История оригинала»](https://arynyklas.github.io/OpenNCALayer/upstream/): версии бандлов оригинального NCALayer и их изменения по данным наблюдателя.

Сайт строится из `plugins/*/plugin.toml` и `registry.toml`, индексов обновлений `updates/v1/`, списка релизов и ветки `upstream`. Он публикуется на GitHub Pages тем же workflow, что и индексы обновлений, и индексы при этом не меняются ни на байт ([`docs/dev/release.md`](../dev/release.md), раздел 9).

## Вопросы и ошибки

Вопросы по установке и работе задавайте в чате проекта в Telegram: [t.me/OpenNCALayer](https://t.me/OpenNCALayer). Ссылка на чат есть и в окне «О программе». Об ошибках сообщайте в [Issues](https://github.com/arynyklas/OpenNCALayer/issues): укажите версию программы (окно «О программе»), систему и приложите журнал. Ключи, пароли и документы не прикладывайте.
