# Документация

Установка и первые шаги описаны в [корневом README](../README.md).

## Для пользователей (`user/`)

- [`install.md`](user/install.md): установка и удаление.
- [`desktop.md`](user/desktop.md): программа на компьютере, значок, окна, настройки.
- [`browser-extension.md`](user/browser-extension.md): расширение браузера, через которое сайт видит программу.
- [`tls.md`](user/tls.md): сертификат для браузера, если расширения нет.
- [`plugins.md`](user/plugins.md): плагины сторонних сайтов, каталог, установка, удаление.
- [`manual-plugins.md`](user/manual-plugins.md): подпись плагинами вручную в окне «Инструменты».
- [`tokens.md`](user/tokens.md): токены (экспериментально).
- [`updates.md`](user/updates.md): как программа обновляется и что делать, если обновления не приходят.
- [`compatibility.md`](user/compatibility.md): отличия от оригинального NCALayer.
- [`cli.md`](user/cli.md): командная строка `oncl`.
- [`server.md`](user/server.md): HTTP-сервис `oncl-server`, запуск и настройка.
- [`http-api.md`](user/http-api.md): запросы к `oncl-server`.

## Для разработчиков (`dev/`)

- [`development.md`](dev/development.md): сборка, окружение для тестов, проверки перед отправкой, форки зависимостей.
- [`release.md`](dev/release.md): выпуск версии, подпись индекса, TUF, плагины, приватность.
- [`sdk-overview.md`](dev/sdk-overview.md): что умеет SDK и как это проверить.
- [`sdk.md`](dev/sdk.md): как встроить `oncl-core` в свою программу.
- [`audit.md`](dev/audit.md): журнал аудита `oncl-server`.
- [`plugin-version-check.md`](dev/plugin-version-check.md): проверка версий плагинов (`cargo xtask plugin-version-check`).
- [`plugins-manual-tests.md`](dev/plugins-manual-tests.md): сборка wasm портов и тесты окна ручных инструментов.
- [`interop-ncanode.md`](dev/interop-ncanode.md): проверка подписей в NCANode.
- [`platform-interop.md`](dev/platform-interop.md): независимая матрица совместимости платформы.
- [`platform-acceptance.md`](dev/platform-acceptance.md): приёмочная проверка на документах до 1 ГиБ.
- [`upstream-watch.md`](dev/upstream-watch.md): наблюдатель за оригиналом.
- [`winget.md`](dev/winget.md): манифест WinGet и его подача.
- [`winget-installer.md`](dev/winget-installer.md): установщик для WinGet.

## Устройство (`design/`)

- [`roadmap.md`](design/roadmap.md): общее устройство и состояние работ.
- [`platform.md`](design/platform.md): SDK, программа для рабочего стола, командная строка и HTTP-сервис как одна платформа.
- [`plugins.md`](design/plugins.md): пакет, манифест, ABI, возможности и порты плагинов.
- [`manual-plugins.md`](design/manual-plugins.md): как разрешается подпись плагинами в окне ручных инструментов.
- [`manual-plugins-inventory.md`](design/manual-plugins-inventory.md): какие плагины работают в этом окне.
- [`tokens.md`](design/tokens.md): аппаратные токены и удостоверение личности.
- [`update-index.md`](design/update-index.md): формат и правила индекса обновлений.
- [`tuf.md`](design/tuf.md): как защищены обновления (TUF).

## Оригинальный NCALayer (`original/`)

- [`architecture.md`](original/architecture.md): как устроен оригинальный NCALayer.
