# Windows и macOS 0.2.1 preview — актуальные установщики

Исходники: `19ad13ce50a40a4fda439a562a831ad4ded8946a`. Проверено **19 ноября 2026**: по сравнению с `main` (`b6d5b0122a64b978e703f247bc25c9533f9847aa`) изменены только документация и метаданные; код, зависимости и упаковщики совпадают. Повторно проверены SHA-256 и размеры всех пяти бинарников.

[Релиз v0.2.1-preview.20261118](https://github.com/jEUGENEdev/vpn/releases/tag/v0.2.1-preview.20261118).

| Платформа | Скачать | Размер |
|---|---|---|
| Windows x64 | [LineVPN-0.2.1-19ad13c-windows-x64.msi](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.1-preview.20261118/LineVPN-0.2.1-19ad13c-windows-x64.msi) | 174.9 MiB |
| macOS Apple Silicon | [LineVPN-0.2.1-19ad13c-macos-arm64.dmg](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.1-preview.20261118/LineVPN-0.2.1-19ad13c-macos-arm64.dmg) | 127.1 MiB |
| macOS Intel | [LineVPN-0.2.1-19ad13c-macos-x64.dmg](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.1-preview.20261118/LineVPN-0.2.1-19ad13c-macos-x64.dmg) | 134.0 MiB |
| Linux amd64 server | [linevpn-server-19ad13c-linux-amd64](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.1-preview.20261118/linevpn-server-19ad13c-linux-amd64) | 31.5 MiB |
| Linux amd64 keygen | [linevpn-keygen-19ad13c-linux-amd64](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.1-preview.20261118/linevpn-keygen-19ad13c-linux-amd64) | 30.8 MiB |

macOS: откройте DMG → **Install-LineVPN.pkg**. Он обновляет приложение и службу вместе. Windows: запустите MSI поверх предыдущей версии.

**Дополнение 19.11.2026:** [Android 0.2.1 с новым постоянным ключом опубликован в том же релизе](../android-preview-20261119/). Со старой подписью APK 0.2.0 он несовместим; сначала сохраните профиль и ключ входа. Исторический полный manifest в `installers/current` сохранён.

[Отчёт о сборке и проверке актуальности](../../docs/manual-build-2026-11-18.md), [manifest](manifest.json), [SHA256SUMS](SHA256SUMS). Скачайте `SHA256SUMS` и восемь перечисленных в нём файлов в один каталог и выполните `sha256sum -c SHA256SUMS`. Для добавленного Android используются отдельные `android-manifest.json` и `ANDROID-SHA256SUMS`; автоматически добавленные GitHub архивы исходников не нужны.

**Preview:** Windows без Authenticode, macOS ad-hoc без нотарификации, PKG не подписан. Нативная установка/обновление и работа VPN на устройствах не проверены. Последний запуск GitHub Actions не выполнил сборку. Публикация файлов не обновляет VPS.
