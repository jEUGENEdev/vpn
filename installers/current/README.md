# Актуальные установщики — Сеть 0.3.2

[Релиз v0.3.2-preview.20261123](https://github.com/jEUGENEdev/vpn/releases/tag/v0.3.2-preview.20261123). Исходники объединены в `main` через PR #42: `b08c0ed9de69c149d9862d128008d303976667dd`. Desktop собран из `ff81de82cb6760e0fd6a911f0582a08f60d7fc57` с идентичным деревом исходников; Android и серверные компоненты — из того же дерева после слияния.

| Платформа | Скачать | Размер |
|---|---|---|
| macOS · Intel / Apple Silicon | [Set-0.3.2-macos-universal.dmg](https://github.com/jEUGENEdev/vpn/releases/download/v0.3.2-preview.20261123/Set-0.3.2-macos-universal.dmg) | 293.5 MiB |
| Windows · x64 | [Set-0.3.2-windows-x64.msi](https://github.com/jEUGENEdev/vpn/releases/download/v0.3.2-preview.20261123/Set-0.3.2-windows-x64.msi) | 175.7 MiB |
| Android 10+ · ARM64 / x86_64 | [Set-0.3.2-android-preview.apk](https://github.com/jEUGENEdev/vpn/releases/download/v0.3.2-preview.20261123/Set-0.3.2-android-preview.apk) | 82.0 MiB |

**macOS:** откройте DMG, затем **«Установщик Сеть.app»**. В одном окне доступны установка/обновление и удаление; Intel и Apple Silicon определяются автоматически. Исправлена ошибка `Cannot compare installed Сеть version`, в том числе после полного удаления. При обновлении профиль и правила сохраняются. [Подробная инструкция и журналы ошибок](../../docs/macos-installation.md).

**Windows:** запустите MSI поверх установленной версии. Исправлены замена устаревшего Electron EXE и создание ярлыка **«Сеть»** в общем меню «Пуск». Профиль и правила сохраняются. **Android:** установите APK поверх 0.3.1, 0.3.0 или 0.2.1 от 19.11.2026; versionCode 3002, постоянный ключ подписи сохранён. Для старой 0.2.0 с другим сертификатом действует [порядок миграции](../../docs/android-signing.md).

Установленное приложение называется **Сеть**. ASCII-имена вложений `Set-` используются для совместимости с GitHub.

Серверные компоненты из тех же исходников: [Сервер Linux · amd64](https://github.com/jEUGENEdev/vpn/releases/download/v0.3.2-preview.20261123/linevpn-server-b08c0ed-linux-amd64) · [Генератор профиля Linux · amd64](https://github.com/jEUGENEdev/vpn/releases/download/v0.3.2-preview.20261123/linevpn-keygen-b08c0ed-linux-amd64). Для исправлений установщиков 0.3.2 обновление сервера не требуется. **VPS этим выпуском не обновлялся.**

[Отчёт о найденных ошибках, сборке и проверках](../../docs/installer-hotfix-2026-11-23.md) · [Обновление приложения](../../docs/installer-upgrade.md) · [Восстановление сети](../../docs/network-recovery.md).

`manifest.json` содержит SHA-256, размеры и ссылки на бинарники. `SHA256SUMS` также включает manifest, отчёт и архив рецептов/проверок. Все девять загруженных вложений сверены по SHA-256 и размеру с локальными файлами. Скачайте все Assets релиза и выполните `sha256sum -c SHA256SUMS`.

**Preview:** установка и VPN на физических устройствах не проверены. macOS ad-hoc без нотарификации Apple; Windows без Authenticode. Локально прошли Go race/vet, 30 installer fixtures, DOM/desktop и проверки безопасности; готовые пакеты извлечены и сверены с исходниками. Тест с настоящим Apple PlistBuddy пропущен на Linux. Chromium и один Ansible fixture заблокированы ограничениями Unix-сокетов. GitHub Actions завершился до выполнения шагов; нативные задания пропущены.

Предыдущие версии сохранены в [GitHub Releases](https://github.com/jEUGENEdev/vpn/releases). В репозитории поддерживается только этот актуальный каталог.
