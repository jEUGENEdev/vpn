# Android 0.2.1 preview — сборка 19.11.2026

[Скачать LineVPN-0.2.1-2dc8d55-android-preview.apk](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.1-preview.20261118/LineVPN-0.2.1-2dc8d55-android-preview.apk) — 85 808 763 байта (81.8 MiB).
Исходный commit: `2dc8d555085a423117ccf7f01a0410086529338e`.
Android 10+, ARM64 и x86_64; versionCode 2001; release-вариант.

**APK опубликован 19.11.2026** в [релизе v0.2.1-preview.20261118](https://github.com/jEUGENEdev/vpn/releases/tag/v0.2.1-preview.20261118).
После загрузки сверены размер и SHA-256 файла в GitHub:
`58e73b228cb68ba0635ebcf625227d2b2b839f6d21f6ffcbbb62710f3857e720`.
Локальные [manifest.json](manifest.json) и [SHA256SUMS](SHA256SUMS) описывают этот APK.
В Assets релиза скачайте APK, `android-manifest.json`, `android-apk-verification.json`,
`manual-build-android-2026-11-19.md` и `LineVPN-Android-build-evidence-20261119.zip`
в один каталог с `ANDROID-SHA256SUMS`, затем выполните `sha256sum -c ANDROID-SHA256SUMS`.
Файлы `manifest.json` и `SHA256SUMS` в самом релизе относятся к Windows/macOS и серверу.

**Подпись новая.** Прежний ключ недоступен; владелец разрешил создать постоянный.
APK не установится поверх старой 0.2.0. Сначала сохраните профиль и личный ключ
входа; удаление старой версии очищает локальные данные и несинхронизированные
правила. [Порядок перехода и хранение ключа](../../docs/android-signing.md).

Проверены подпись APK, identity/version, обе архитектуры, 16 KiB alignment,
побайтовое происхождение native-библиотек из свежего AAR и отказ обновления
старого APK с другой подписью. [Отчёт и ограничения проверок](../../docs/manual-build-android-2026-11-19.md).
На устройстве установка и работа VPN ещё не проверены.

[Опубликованные Windows/macOS 0.2.1](../desktop-preview-20261118/).
