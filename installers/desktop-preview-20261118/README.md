# Подготовленные Windows и macOS 0.2.1 preview — 18 ноября 2026

Исходники: `19ad13ce50a40a4fda439a562a831ad4ded8946a`.

**Файлы собраны и проверены, но ещё не опубликованы в GitHub Releases.** Две попытки загрузки через браузер не завершились. Установщики переданы владельцу отдельными файлами; несуществующие ссылки на скачивание здесь не размещены. Планируемый тег: `v0.2.1-preview.20261118`.

| Платформа | Файл | Размер |
|---|---|---|
| Windows x64 | `LineVPN-0.2.1-19ad13c-windows-x64.msi` | 174.9 MiB |
| macOS Apple Silicon | `LineVPN-0.2.1-19ad13c-macos-arm64.dmg` | 127.1 MiB |
| macOS Intel | `LineVPN-0.2.1-19ad13c-macos-x64.dmg` | 134.0 MiB |
| Linux amd64 server | `linevpn-server-19ad13c-linux-amd64` | 31.5 MiB |
| Linux amd64 keygen | `linevpn-keygen-19ad13c-linux-amd64` | 30.8 MiB |

macOS: откройте DMG → **Install-LineVPN.pkg**. Он обновляет приложение и службу вместе. Windows: запустите MSI поверх предыдущей версии.

**Android 0.2.1 отсутствует:** нужен прежний keystore. Старый полный manifest в `installers/current` сохранён.

[Подробный отчёт](../../docs/manual-build-2026-11-18.md), [manifest](manifest.json) и [SHA256SUMS](SHA256SUMS). Проверка всех полученных файлов: `sha256sum -c SHA256SUMS`. Архив рецепта передан вместе с установщиками.

**Preview:** Windows без Authenticode, macOS ad-hoc без нотарификации. Нативная установка/обновление и работа VPN на устройствах не проверены. GitHub Actions заблокирован billing; VPS не обновлялся.
