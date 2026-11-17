# Актуальные установщики

Комплект **0.2.0 preview с исправлением восстановления сети**, 17 ноября 2026: [открыть релиз](https://github.com/jEUGENEdev/vpn/releases/tag/v0.2.0-preview.20261117.2). Все четыре файла собраны из `main` на `66e60336a053a3f0f058cab6bc41eb31bbef0373` и содержат [PR #14](https://github.com/jEUGENEdev/vpn/pull/14).

| Платформа | Скачать | Размер, байт |
|---|---|---:|
| Android 10+ · ARM64 / x86_64 | [LineVPN-0.2.0-66e6033-android-preview.apk](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.0-preview.20261117.2/LineVPN-0.2.0-66e6033-android-preview.apk) | 86 267 830 |
| Windows · x64 | [LineVPN-0.2.0-66e6033-windows-x64.msi](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.0-preview.20261117.2/LineVPN-0.2.0-66e6033-windows-x64.msi) | 183 362 048 |
| macOS · Apple Silicon | [LineVPN-0.2.0-66e6033-macos-arm64.dmg](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.0-preview.20261117.2/LineVPN-0.2.0-66e6033-macos-arm64.dmg) | 149 813 874 |
| macOS · Intel | [LineVPN-0.2.0-66e6033-macos-x64.dmg](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.0-preview.20261117.2/LineVPN-0.2.0-66e6033-macos-x64.dmg) | 157 206 355 |

APK, MSI и оба DMG находятся в **Assets релиза этого приватного репозитория**. Для скачивания нужен доступ к репозиторию. Git clone и ZIP исходников не содержат установщики.

В этом комплекте: полное выключение VPN, восстановление старых DNS/WFP/PF, очистка при удалении и прямой резерв при недоступном VPN. Приоритет — доступность сети; при сбое соединения могут идти напрямую, без VPN-защиты. Правила и серверная авторизация сохраняются.

Ошибка **«500: очередь адресов заполнена»** у кнопки «Оставить напрямую» относится к бэкенду. Для неё подготовлен [PR #15](https://github.com/jEUGENEdev/vpn/pull/15); замена установщика сама по себе серверную ошибку не устраняет.

Android подписан тем же сертификатом, что предыдущий ручной APK: совместимость подписей проверена. MSI имеет новый ProductCode, прежний UpgradeCode и настройки обновления сборки 0.2.0. macOS DMG включают сервисный PKG, Install-Service.command и Uninstall-LineVPN.command. Инструкции: [macOS](../../docs/macos-installation.md), [восстановление сети](../../docs/network-recovery.md).

Это **preview**: Android использует debug-подпись, macOS — ad-hoc без нотарификации и с неподписанным PKG, Windows — без Authenticode. Проверены сборка, содержимое, контрольные суммы и структура пакетов; установка, служба и восстановление сети на целевых ОС ещё не проверены. См. [приёмку](../../docs/acceptance.md).

[manifest.json](manifest.json) фиксирует исходный коммит, точные размеры, SHA-256 и подписи. Проверка скачанных файлов: `sha256sum -c SHA256SUMS` или `shasum -a 256 -c SHA256SUMS`; в Windows — `Get-FileHash <файл> -Algorithm SHA256`.

[Отчёт сборки](../../docs/manual-build-network-fix-2026-11-17.md); рецепт и журналы — `LineVPN-manual-build-66e6033-recipe.zip` в Assets релиза. Предыдущий релиз сохранён для истории. Изменение исходников не обновляет установщики автоматически: сверяйте `source_commit` в manifest. Штатный CI при успешном запуске может опубликовать новый комплект через Git LFS; актуальный способ скачивания указан в manifest.
