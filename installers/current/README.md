# Актуальные установщики

Ручная сборка **0.2.0 preview от 17 ноября 2026**: [открыть релиз](https://github.com/jEUGENEdev/vpn/releases/tag/v0.2.0-preview.20261117).

APK, MSI и оба DMG хранятся в **Assets релиза этого репозитория**. Скачивайте файлы по ссылкам ниже или из Assets. Клонирование Git и скачивание исходников ZIP не включают эти установщики. Старые LFS-файлы удалены из текущего каталога; они остаются в истории Git.

| Платформа | Скачать | Размер, байт | Исходники |
|---|---|---:|---|
| Android 10+ · ARM64 / x86_64 | [LineVPN-0.2.0-4499b31-android-preview.apk](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.0-preview.20261117/LineVPN-0.2.0-4499b31-android-preview.apk) | 86 227 790 | `4499b31` |
| Windows · x64 | [LineVPN-0.2.0-69b0ee2-windows-x64.msi](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.0-preview.20261117/LineVPN-0.2.0-69b0ee2-windows-x64.msi) | 183 352 832 | `69b0ee2` |
| macOS · Apple Silicon | [LineVPN-0.2.0-69b0ee2-macos-arm64.dmg](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.0-preview.20261117/LineVPN-0.2.0-69b0ee2-macos-arm64.dmg) | 149 787 687 | `69b0ee2` |
| macOS · Intel | [LineVPN-0.2.0-69b0ee2-macos-x64.dmg](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.0-preview.20261117/LineVPN-0.2.0-69b0ee2-macos-x64.dmg) | 157 170 186 | `69b0ee2` |

[manifest.json](manifest.json) содержит точные SHA-256, размеры, ссылки, исходные коммиты и сведения о подписях. [SHA256SUMS](SHA256SUMS) позволяет проверить скачанные файлы: `sha256sum -c SHA256SUMS` в Linux или `shasum -a 256 -c SHA256SUMS` в macOS. В Windows используйте `Get-FileHash <файл> -Algorithm SHA256` и сравните с manifest.

Desktop собран из `69b0ee2`. Android дополнительно содержит исправление компиляции из [PR #13](https://github.com/jEUGENEdev/vpn/pull/13), уже слитого в `main` коммитом `f72738a`. Последующие изменения документации и публикации не требуют пересборки приложения. Изменение исходников само по себе не обновляет эти файлы — сверяйте `source_commit` в manifest.

Это **preview**: Android подписан debug-ключом, macOS использует ad-hoc-подпись без нотарификации (PKG не подписан), Windows — без Authenticode. Установка и VPN на реальных устройствах не проверялись; обязательные испытания перечислены в [acceptance.md](../../docs/acceptance.md). При смене Android-подписи может понадобиться переустановка: предварительно сохраните ключ входа и профиль подключения.

[Отчёт о ручной сборке и проверках](../../docs/manual-build-2026-11-17.md). Адаптеры упаковки, проверки и журнал сборки находятся в `LineVPN-manual-build-recipe.zip` в Assets релиза; архив фиксирует состояние на момент сборки, до слияния PR. Инструкция для macOS: [macos-installation.md](../../docs/macos-installation.md).

Сборки выполнены вручную, без GitHub Actions. Штатный workflow `Test and build current installers` при следующем успешном запуске может заменить manifest и вернуть комплект файлов через Git LFS; для определения актуального способа скачивания всегда смотрите manifest.
