**Подготовлены Windows/macOS 0.2.1:** [статус и суммы от 18.11.2026](../desktop-preview-20261118/). Публикация новых файлов в Releases не завершена; они переданы отдельно. Android 0.2.1 ожидает прежний ключ подписи. Ниже сохранён предыдущий полный комплект; он не содержит последующих исправлений.

# Последний полный комплект LineVPN 0.2.0

Комплект после объединения PR #16/#17/#18 через #19. Все бинарники собраны из `d067d97f1fcd86aa00b74aa4c3f74ee1176a58bb`.

[Релиз v0.2.0-preview.20261117.4](https://github.com/jEUGENEdev/vpn/releases/tag/v0.2.0-preview.20261117.4).

| Платформа | Скачать | Размер |
|---|---|---|
| Android 10+ · ARM64 / x86_64 | [LineVPN-0.2.0-d067d97-android-preview.apk](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.0-preview.20261117.4/LineVPN-0.2.0-d067d97-android-preview.apk) | 82.3 MiB |
| Windows · x64 | [LineVPN-0.2.0-d067d97-windows-x64.msi](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.0-preview.20261117.4/LineVPN-0.2.0-d067d97-windows-x64.msi) | 174.9 MiB |
| macOS · Apple Silicon | [LineVPN-0.2.0-d067d97-macos-arm64.dmg](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.0-preview.20261117.4/LineVPN-0.2.0-d067d97-macos-arm64.dmg) | 142.9 MiB |
| macOS · Intel | [LineVPN-0.2.0-d067d97-macos-x64.dmg](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.0-preview.20261117.4/LineVPN-0.2.0-d067d97-macos-x64.dmg) | 149.9 MiB |
| Сервер Linux · amd64 | [linevpn-server-d067d97-linux-amd64](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.0-preview.20261117.4/linevpn-server-d067d97-linux-amd64) | 31.5 MiB |
| Генератор профиля Linux · amd64 | [linevpn-keygen-d067d97-linux-amd64](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.0-preview.20261117.4/linevpn-keygen-d067d97-linux-amd64) | 30.8 MiB |

Нужно обновить сервер и клиенты. Существующие база, профиль, сертификаты и ключи сохраняются; повторная генерация профиля не требуется.

[Отчёт о сборке и проверках](../../docs/manual-build-media-integration-2026-11-17.md), [сверка PR](../../docs/pr-16-17-integration.md), [обновление сервера](../../docs/deployment.md), [восстановление сети](../../docs/network-recovery.md).

manifest.json содержит SHA-256 и размеры бинарников. SHA256SUMS включает бинарники, manifest, отчёт и архив рецепта из Assets. Проверяйте суммы в каталоге со всеми скачанными файлами: `sha256sum -c SHA256SUMS`.

**Preview:** установка и работа на физических устройствах и VPS не проверены. Android подписан прежним debug-ключом; Windows без Authenticode; macOS ad-hoc без нотарификации, сервисный PKG не подписан. Версии приложения остаются 0.2.0 preview; комплекты различаются по SHA и тегу.

Автодеплой d067d97 остановлен до запуска из-за ошибки оплаты/лимита GitHub Actions. Публикация файлов сама по себе не обновляет VPS. Отзыв/сужение доступа может кратковременно прерывать остальные устройства.
