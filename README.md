> **Test repository of the OpenNCALayer lab (publisher-catalog gate).** Synthetic keys, lab builds: do not install anything from here. The project is https://github.com/arynyklas/OpenNCALayer.

# OpenNCALayer

Открытая замена NCALayer для подписи документов ЭЦП на сайтах: egov.kz, госзакупки, банки, ЭДО. Сайты работают с ней так же, как с оригиналом, и менять на них ничего не нужно.

Проект независимый и не связан с НУЦ РК.

## Установка

1. Скачайте установщик для своей системы со страницы [«Загрузка»](https://arynyklas.github.io/OpenNCALayer/download/): Windows (в том числе Windows 7), macOS или Linux.
2. Установите [расширение браузера](docs/user/browser-extension.md). Так сайт проще всего увидит программу.
3. Откройте сайт и подпишите документ как обычно.

Можно обойтись и без расширения: выпустите сертификат в меню значка программы, пункт «Сертификат для браузера…» ([инструкция](docs/user/tls.md)).

Подробнее, в том числе как удалить программу: [`docs/user/install.md`](docs/user/install.md).

## Что работает

- Подпись и вход по ключам из файлов `.p12`, `.pfx`, `.jks`.
- Проверка сертификатов НУЦ.
- Плагины сторонних сайтов, перенесённые из оригинала.
- Автоматическое обновление.

Пока не работает или не проверено:
- шифрования и расшифрования нет;
- токены и удостоверение личности поддерживаются экспериментально и выключены по умолчанию;
- установщики не подписаны, поэтому Windows покажет предупреждение SmartScreen, а macOS предупреждение Gatekeeper.

Отличия от оригинала описаны в [`docs/user/compatibility.md`](docs/user/compatibility.md).

## Помощь

- Вопросы задавайте в Telegram-чате [t.me/OpenNCALayer](https://t.me/OpenNCALayer).
- Об ошибках сообщайте в [Issues](https://github.com/arynyklas/OpenNCALayer/issues).
- Об уязвимостях сообщайте только приватно, см. [`SECURITY.md`](SECURITY.md).

## Для разработчиков

Ту же подпись можно использовать без программы для рабочего стола:
- библиотека для Rust: [`docs/dev/sdk-overview.md`](docs/dev/sdk-overview.md);
- командная строка `oncl`: [`docs/user/cli.md`](docs/user/cli.md);
- HTTP-сервис `oncl-server`: [`docs/user/server.md`](docs/user/server.md).

Как собрать и проверить проект: [`docs/dev/development.md`](docs/dev/development.md). Как устроен оригинальный NCALayer: [`docs/original/architecture.md`](docs/original/architecture.md).

## Лицензия

© 2026 Aryn Yklas. [Apache-2.0](LICENSE), см. также [NOTICE](NOTICE).

`web/demo/vendor/ncalayer-client.js` распространяется по лицензии MIT, см. [`web/demo/vendor/LICENSE`](web/demo/vendor/LICENSE). Velopack (MIT), бэкенд winit из Slint (LicenseRef-Slint-Royalty-free-2.0) и `multer` (MIT) собираются из наших форков с небольшими изменениями. Streebog для секретного ввода в `oncl-gost` основан на коде `streebog` из RustCrypto (MIT или Apache-2.0). Подробности приведены в [NOTICE](NOTICE).
