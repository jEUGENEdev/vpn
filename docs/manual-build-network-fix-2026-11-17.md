# Обновлённые установщики после PR #14 — 17 ноября 2026

Все четыре установщика собраны вручную из `66e60336a053a3f0f058cab6bc41eb31bbef0373` (`main` после слияния PR #14), дерево `03295783587e2ac714048f2943af9351a65ab527`. По Git blob SHA сверены 157 файлов исходников и конфигурации; неизменённые скриншоты документации не нужны для сборки. Релиз: [v0.2.0-preview.20261117.2](https://github.com/jEUGENEdev/vpn/releases/tag/v0.2.0-preview.20261117.2).

Комплект содержит полное выключение VPN, восстановление сети после остановки/удаления, миграцию старых DNS и firewall-настроек и прямой резерв при недоступном VPN. Версия приложения остаётся 0.2.0 preview; новые файлы отличаются исходным SHA и тегом комплекта.

| Платформа | Скачать | Размер, байт |
|---|---|---:|
| Android 10+ · ARM64 / x86_64 | [LineVPN-0.2.0-66e6033-android-preview.apk](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.0-preview.20261117.2/LineVPN-0.2.0-66e6033-android-preview.apk) | 86 267 830 |
| Windows · x64 | [LineVPN-0.2.0-66e6033-windows-x64.msi](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.0-preview.20261117.2/LineVPN-0.2.0-66e6033-windows-x64.msi) | 183 362 048 |
| macOS · Apple Silicon | [LineVPN-0.2.0-66e6033-macos-arm64.dmg](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.0-preview.20261117.2/LineVPN-0.2.0-66e6033-macos-arm64.dmg) | 149 813 874 |
| macOS · Intel | [LineVPN-0.2.0-66e6033-macos-x64.dmg](https://github.com/jEUGENEdev/vpn/releases/download/v0.2.0-preview.20261117.2/LineVPN-0.2.0-66e6033-macos-x64.dmg) | 157 206 355 |

## Проверки

- Android: заново собран Go AAR для arm64/amd64, `assembleDebug` успешен. APK ZIP цел, APK v2-подпись и `zipalign -c -P 16 -v 4` проверены. Обе ELF-архитектуры и библиотеки из Gradle сверены с APK. Сертификат совпадает с предыдущим ручным релизом; SHA-256 сертификата: `b13dfe366940dc70d27e244c8bf17ed18ff3dfdad93713bdbc1b91cbfa85f0b1`. `versionCode=2`, `minSdk=29`, `targetSdk=35`.
- Windows: извлечены и побайтово сверены все 75 файлов MSI, включая новый `recover-network.ps1`. Проверены таблицы службы, обновления и удаления. `RecoverNetwork` имеет Type 3090: deferred EXE с системными правами и проверкой результата. Действие выполняется после StopServices, перед DeleteServices и RemoveFiles, при `REMOVE~="ALL"`. Новый ProductCode: `{216CE0EC-02E5-519A-AA91-BF7B727FE77D}`; UpgradeCode сохранён, обновление той же версии разрешено.
- macOS: оба DMG проходят проверку и извлечение 7-Zip. Для каждого сверены 272 обычных файла приложения, 14 ссылок, исполняемые права и содержимое внешних установочных команд. Проверены 14 Mach-O, 9 bundle и 481 ресурсный хеш. Извлечены PKG/Payload/Scripts; агент, plist, `service-wrapper.sh`, `recover-network.sh`, `uninstall.sh` и postinstall совпадают с подготовленным пакетом. Ссылка Applications внутри образа указывает на `/Applications`.
- Windows и оба macOS-приложения: `main.cjs` и `preload.cjs` внутри ASAR совпадают с исходниками.
- После сборки исходники повторно сверены с GitHub snapshot. Размеры и SHA-256 итоговых файлов записаны в manifest и SHA256SUMS.

Go race/vet, DOM и packaging-проверки кода выполнены при проверке PR #14; результаты в [отчёте проверки](network-availability-verification.md). В этой сборке код приложения не менялся.

## Ограничения

Это preview. Нативная установка, служба, TUN, DNS, off/on, crash и uninstall на Windows/macOS/Android не проверялись в Linux-среде. Android emulator, Apple codesign/hdiutil/spctl/Gatekeeper и полный Chromium-прогон не выполнялись. Проверка бинарных пакетов не заменяет [приёмку на целевых ОС](acceptance.md).

Windows не подписан Authenticode. macOS приложение и агент имеют ad-hoc-подписи, PKG не подписан, Apple-нотарификации нет. Android подписан прежним debug-ключом окружения; новая смена подписи для этого комплекта не требуется. Ключ подписи в артефакты и рецепт не включён.

## Сборка

Go 1.27.4, Electron 45.3.3, electron-builder 26.18.0, Android SDK/build-tools 35, NDK 28.0.13004108, Gradle 8.11.1, AGP 8.9.2, Kotlin 2.1.20 и JDK 21. Использованы зависимости с неизменённым package-lock.json. `GOFLAGS=-buildvcs=false` применяется к snapshot checkout.

Windows: штатный WiX 4 генератор адаптирован для wixl 0.106. Сохранены payload, GUID компонентов, UpgradeCode, служба и новая recovery CustomAction; FileRef преобразован в FileKey, Condition в текст WiX 3. Два названия MSI переведены в ASCII из-за ограничения wixl. Редактирование ресурсов EXE отключено при Linux-кросс-сборке.

macOS: вместо pkgbuild/codesign/hdiutil использованы bomutils, libarchive, rcodesign 0.29.0 и leaanthony/dmg. Адаптер обновлён для включения supervisor и деинсталлятора из PR #14. Windows упакован до подготовки macOS assets, чтобы платформенные ресурсы не смешивались.

Рецепт `LineVPN-manual-build-66e6033-recipe.zip` содержит адаптеры, проверки, source-proof и журналы. Исходники приложения берутся из указанного коммита. Сборочные SDK и закрытые ключи в архив не входят.
