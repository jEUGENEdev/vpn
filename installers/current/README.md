# Актуальные установщики — Сеть 0.3.1

[Релиз v0.3.1-preview.20261123](https://github.com/jEUGENEdev/vpn/releases/tag/v0.3.1-preview.20261123). Сборки из `613e19213aa3543e2dc8b7eaa35647e27b3992be`; исправления объединены в `main` через PR #41.

| Платформа | Скачать | Размер |
|---|---|---|
| macOS · Intel / Apple Silicon | [Set-0.3.1-macos-universal.dmg](https://github.com/jEUGENEdev/vpn/releases/download/v0.3.1-preview.20261123/Set-0.3.1-macos-universal.dmg) | 293.5 MiB |
| Windows · x64 | [Set-0.3.1-windows-x64.msi](https://github.com/jEUGENEdev/vpn/releases/download/v0.3.1-preview.20261123/Set-0.3.1-windows-x64.msi) | 175.7 MiB |
| Android 10+ · ARM64 / x86_64 | [Set-0.3.1-android-preview.apk](https://github.com/jEUGENEdev/vpn/releases/download/v0.3.1-preview.20261123/Set-0.3.1-android-preview.apk) | 82.0 MiB |

**macOS:** откройте DMG, затем **«Установщик Сеть.app»**. В одном окне доступны установка/обновление и удаление; Intel и Apple Silicon определяются автоматически. Новый установщик умеет удалять повреждённую старую установку. При обновлении профиль и правила сохраняются. [Подробная инструкция и журналы ошибок](../../docs/macos-installation.md).

**Windows:** запустите MSI поверх установленной версии. **Android:** установите APK поверх 0.3.0 или 0.2.1 от 19.11.2026; versionCode 3001, постоянный ключ подписи сохранён. Для старой 0.2.0 с другим сертификатом действует [порядок миграции](../../docs/android-signing.md).

Установленное приложение называется **Сеть**. ASCII-имена вложений `Set-` используются для совместимости с GitHub.

Серверные компоненты из тех же исходников: [Сервер Linux · amd64](https://github.com/jEUGENEdev/vpn/releases/download/v0.3.1-preview.20261123/linevpn-server-613e192-linux-amd64) · [Генератор профиля Linux · amd64](https://github.com/jEUGENEdev/vpn/releases/download/v0.3.1-preview.20261123/linevpn-keygen-613e192-linux-amd64). [Порядок обновления сервера](../../docs/deployment.md). **VPS этим выпуском не обновлялся.**

[Отчёт о найденных ошибках, сборке и проверках](../../docs/installer-fixes-2026-11-23.md) · [Обновление приложения](../../docs/installer-upgrade.md) · [Восстановление сети](../../docs/network-recovery.md).

`manifest.json` содержит SHA-256, размеры и ссылки на бинарники. `SHA256SUMS` также включает manifest, отчёт и архив рецептов/проверок. Все девять загруженных вложений сверены по SHA-256 и размеру с локальными файлами. Скачайте все Assets релиза и выполните `sha256sum -c SHA256SUMS`.

**Preview:** установка и VPN на физических устройствах не проверены. macOS ad-hoc без нотарификации Apple; Windows без Authenticode. Локально прошли Go race/vet, 25 installer fixtures, DOM/desktop и проверки безопасности; готовые пакеты извлечены и сверены с исходниками. Chromium и один Ansible fixture заблокированы ограничениями Unix-сокетов. GitHub Actions не запустил задания из-за оплаты/лимита аккаунта.

Предыдущие версии сохранены в [GitHub Releases](https://github.com/jEUGENEdev/vpn/releases). В репозитории поддерживается только этот актуальный каталог.
