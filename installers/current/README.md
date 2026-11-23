# Актуальные установщики — Сеть 0.3.3

**Сборки готовы и переданы владельцу; загрузка в GitHub Releases не завершена.** Ссылки ниже доступны владельцу файлов, доступ к репозиторию сам по себе не предоставляет доступ к ним. Исходники слиты в `main` через [PR #43](https://github.com/jEUGENEdev/vpn/pull/43): `9be48a1257ef4337fc3fad1a774715a9e3a32771`. Все установщики собраны после слияния.

| Платформа | Скачать | Размер |
|---|---|---|
| Windows · x64 | [Set-0.3.3-windows-x64.msi](https://chatgpt.com/library?file_id=libfile_fde3_f-f0bb5743e1508191aee40006604c7345_fc3cc296b86481919e16d10029f6df30&account_id=personal) | 175.7 MiB |
| macOS · Intel / Apple Silicon | [Set-0.3.3-macos-universal.dmg](https://chatgpt.com/library?file_id=libfile_fde3_f-783a4afba9588191ab51d02209f5d5f1_fc3cc296b86481919e16d10029f6df30&account_id=personal) | 293.5 MiB |
| Android 10+ · ARM64 / x86_64 | [Set-0.3.3-android-preview.apk](https://chatgpt.com/library?file_id=libfile_fde3_f-e9fc7ad899188191936e66426e5bb028_fc3cc296b86481919e16d10029f6df30&account_id=personal) | 82.0 MiB |

**Windows:** запустите MSI поверх установленной версии. Повторный запуск того же MSI выполняет восстановление автоматически — отдельный пункт выбирать не нужно. Исправлены обязательность установки службы, проверка её готовности, имя `Сеть.exe` и ярлык «Сеть». Профиль и правила сохраняются. Если MSI завершится ошибкой, запустите его с журналом: `msiexec /i Set-0.3.3-windows-x64.msi /L*V set-install.log`.

**macOS:** откройте DMG и **«Установщик Сеть.app»**. В одном окне доступны установка/обновление и удаление; Intel и Apple Silicon выбираются автоматически. Установщик теперь проверяет готовность фоновой службы. [Инструкция и журналы](../../docs/macos-installation.md).

**Android:** установите APK поверх 0.3.2, 0.3.1, 0.3.0 или 0.2.1 от 19.11.2026; versionCode 3003, постоянный ключ сохранён. Для старой 0.2.0 с другим сертификатом действует [порядок миграции](../../docs/android-signing.md).

Установленное приложение называется **Сеть**. ASCII-имена вложений `Set-` нужны для совместимости с GitHub. Обновление сервера не требуется; VPS этим выпуском не обновлялся.

[Отчёт о причинах, исправлениях и проверках](../../docs/installer-service-hotfix-2026-11-23.md) · [Обновление приложения](../../docs/installer-upgrade.md) · [Восстановление сети](../../docs/network-recovery.md).

`manifest.json` содержит SHA-256, размеры и ссылки на установщики. Скачайте файлы по ссылкам и выполните `sha256sum -c SHA256SUMS`.

[Архив проверок](https://chatgpt.com/library?file_id=libfile_fde3_f-fde2f23bd9dc81919ef341122bfd2777_fc3cc296b86481919e16d10029f6df30&account_id=personal) · [Контрольные суммы](https://chatgpt.com/library?file_id=libfile_fde3_f-0dd6cf5ee2f48191a181590828c9d311_fc3cc296b86481919e16d10029f6df30&account_id=personal) · [Manifest](https://chatgpt.com/library?file_id=libfile_fde3_f-7cf6b02ee2d88191978f791a974deb85_fc3cc296b86481919e16d10029f6df30&account_id=personal).

**Preview:** реальные установка и VPN на Windows/macOS/Android не проверены. macOS ad-hoc без нотарификации Apple; Windows без Authenticode. Прошли Go race/vet, desktop/DOM, 31 installer fixture и проверки безопасности; все готовые пакеты извлечены и проверены. Apple PlistBuddy пропущен на Linux. Chromium не установлен; Ansible RPC и SSH fixture не прошли. GitHub Actions завершился до выполнения шагов, нативные задания пропущены.

Предыдущие версии сохранены в [GitHub Releases](https://github.com/jEUGENEdev/vpn/releases). В репозитории поддерживается один актуальный каталог.
