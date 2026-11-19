# WinGet: манифест и подача

Здесь описано, как получить манифест опубликованного релиза и подать его в `microsoft/winget-pkgs`. Команда `winget install --id arynyklas.OpenNCALayer --exact` заработает только после того, как пакет примут (шаг 6 подачи).

## Установщик в манифесте

WinGet запускает не обычный `…-setup.exe`, а `openncalayer-<версия>-win-<x64|x86>-winget-setup.exe`. Он рассчитан только на Windows 10 1809 и новее, Windows 7 в WinGet не заявлена. Это небольшая обёртка `oncl-winget-setup`, внутри которой лежит неизменённый Velopack `Setup.exe` ([`winget-installer.md`](winget-installer.md)).

Обёртка нужна из-за двух особенностей `Setup.exe` закреплённой версии Velopack (1.3.39-g8d2844f, `src/bins/src/commands/install.rs`). При переустановке он безусловно завершает установленную программу (`force_stop_package`), даже посреди подписи. При невыполненных предварительных требованиях он возвращает `Ok(())` и выходит с кодом 0, ничего не установив. Оба действия происходят в самом `Setup.exe` раньше любых хуков приложения, и параметрами `vpk pack` их не отключить. Обёртка просит запущенную программу приостановиться через `oncl_ipc::maintenance`, проверяет, что установка действительно прошла, и возвращает правдивый код.

## Манифест

```sh
cargo xtask winget manifest --version 0.2.0
```

Версия указывается как в теге, без `v`. Команда скачивает `SHA256SUMS` релиза `v<версия>` (или берёт файл из `--sums <путь>`) и пишет в `target/winget` (`--out`) три файла схемы 1.12.0: `arynyklas.OpenNCALayer.yaml`, `….locale.en-US.yaml` и `….installer.yaml`. В `installer.yaml` два установщика, `x64` и `x86`. Их URL указывают на ассеты этого релиза `https://github.com/arynyklas/OpenNCALayer/releases/download/v<версия>/…`, SHA-256 берутся из `SHA256SUMS`. Установщик принимает только `--silent` (интерактивного режима нет), код 4 («занято: идёт подпись») описан как `packageInUse`, а не как успех, `Scope: user`, повышение прав запрещено. В репозитории ничего не сохраняется.

Схему проверяет `winget validate target/winget`; установку эта команда не проверяет.

## Что нужно до подачи

- Опубликованный релиз без суффикса (`0.x.y`, не `-alpha.N`): в WinGet подаются только стабильные версии.
- Оба `winget-setup.exe` подписаны Authenticode. Для этого настроен SignPath и в его артефакте разрешён `*-winget-setup.exe` ([`winget-installer.md`](winget-installer.md), «Шаг оператора»). Неподписанный манифест не подавать.
- Установка проверена в чистой виртуальной машине с Windows 10/11 или в Sandbox: `winget settings --enable LocalManifestFiles`, затем `winget install --manifest target/winget --silent`, обновление со старой версии и `winget uninstall`. Список сценариев есть в [`winget-installer.md`](winget-installer.md). Имя и издатель записи Apps & Features видны только после настоящей установки. Если WinGet не узнаёт установленную версию, добавьте в `installer.yaml` поле `AppsAndFeaturesEntries` по этой записи.
- Идентификатор `PackageIdentifier` `arynyklas.OpenNCALayer` свободен: в `microsoft/winget-pkgs` нет каталога `manifests/a/arynyklas/OpenNCALayer/` и открытых PR с ним.
- Владелец проекта согласовал первый fork и PR; дальше пакет должен одобрить Microsoft.

## Подача

1. Сделайте fork `microsoft/winget-pkgs` и ветку `arynyklas.OpenNCALayer-<версия>`.
2. Скопируйте три файла в `manifests/a/arynyklas/OpenNCALayer/<версия>/`.
3. Выполните `winget validate --manifest manifests/a/arynyklas/OpenNCALayer/<версия>`. Флаги `--force` и `--ignore-security-hash` не используйте.
4. Откройте PR с заголовком `New package: arynyklas.OpenNCALayer version <версия>` и честно отметьте пункты чек-листа шаблона.
5. Ответьте на замечания проверок Microsoft. Если ассет релиза заменить после подачи, SHA-256 в манифесте перестанет совпадать, поэтому в таком случае выпускайте новую версию.
6. Когда PR слит и индекс WinGet обновился (это занимает часы), проверьте в чистой машине `winget install --id arynyklas.OpenNCALayer --exact --source winget --silent`, обновление и удаление. После этого обновите упоминания WinGet в README и [`docs/user/install.md`](../user/install.md).
