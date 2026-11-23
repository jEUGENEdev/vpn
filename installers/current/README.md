# Актуальные установщики — Сеть 0.3.0

[Релиз v0.3.0-preview.20261123](https://github.com/jEUGENEdev/vpn/releases/tag/v0.3.0-preview.20261123). Полный комплект из `5f37180b5d19e531fe3ae3198859f58c94b46f5e` после объединения PR #39 и #40 и исправления упаковки macOS.

| Платформа | Скачать | Размер |
|---|---|---|
| Android 10+ · ARM64 / x86_64 | [Set-0.3.0-5f37180-android-preview.apk](https://github.com/jEUGENEdev/vpn/releases/download/v0.3.0-preview.20261123/Set-0.3.0-5f37180-android-preview.apk) | 82.0 MiB |
| Windows · x64 | [Set-0.3.0-5f37180-windows-x64.msi](https://github.com/jEUGENEdev/vpn/releases/download/v0.3.0-preview.20261123/Set-0.3.0-5f37180-windows-x64.msi) | 175.7 MiB |
| macOS · Apple Silicon | [Set-0.3.0-5f37180-macos-arm64.dmg](https://github.com/jEUGENEdev/vpn/releases/download/v0.3.0-preview.20261123/Set-0.3.0-5f37180-macos-arm64.dmg) | 128.6 MiB |
| macOS · Intel | [Set-0.3.0-5f37180-macos-x64.dmg](https://github.com/jEUGENEdev/vpn/releases/download/v0.3.0-preview.20261123/Set-0.3.0-5f37180-macos-x64.dmg) | 135.6 MiB |
| Сервер Linux · amd64 | [linevpn-server-5f37180-linux-amd64](https://github.com/jEUGENEdev/vpn/releases/download/v0.3.0-preview.20261123/linevpn-server-5f37180-linux-amd64) | 31.5 MiB |
| Генератор профиля Linux · amd64 | [linevpn-keygen-5f37180-linux-amd64](https://github.com/jEUGENEdev/vpn/releases/download/v0.3.0-preview.20261123/linevpn-keygen-5f37180-linux-amd64) | 30.8 MiB |

Android 10+: версия 0.3.0, versionCode 3000, постоянная подпись от 19.11.2026. Подпись совместима с APK 0.2.1 от этой даты; удалять его перед обновлением не нужно. Для старой 0.2.0 с прежним ключом требуется [миграция](../../docs/android-signing.md).

Windows: запустить MSI поверх установленной версии. macOS: открыть DMG, затем `Установить-Сеть.pkg`; приложение и служба обновляются вместе, профиль и правила сохраняются. Установленное приложение называется **Сеть**; имена вложений используют `Set-`, поскольку GitHub удаляет кириллицу из имён файлов.

[Отчёт о сборке и проверках](../../docs/manual-build-2026-11-23.md), [порядок обновления](../../docs/installer-upgrade.md), [обновление сервера](../../docs/deployment.md), [восстановление сети](../../docs/network-recovery.md). Для новых серверных функций требуется соответствующая версия сервера. **VPS этим выпуском не обновлён.**

`manifest.json` содержит SHA-256 и размеры бинарников; `SHA256SUMS` также включает отчёт, manifest и архив рецепта. Для полного комплекта скачайте все Assets релиза и выполните `sha256sum -c SHA256SUMS`. SHA-256 шести бинарников на GitHub сверены с локальной сборкой.

**Preview:** установка и сетевое поведение на физических устройствах не проверены. Windows без Authenticode; macOS ad-hoc без нотарификации, PKG не подписан Apple. GitHub Actions заблокирован оплатой/лимитом аккаунта; использована локальная сборка. Полный Go race/vet, проверки интерфейса и содержимого пакетов пройдены; ограничения Chromium/Ansible описаны в отчёте.

Предыдущие комплекты: [Android 0.2.1](../android-preview-20261119/), [Windows/macOS 0.2.1](../desktop-preview-20261118/), [релизы](https://github.com/jEUGENEdev/vpn/releases).
