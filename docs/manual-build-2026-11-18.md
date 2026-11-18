# Ручные сборки 0.2.1 — 18 ноября 2026

Исходный commit: `19ad13ce50a40a4fda439a562a831ad4ded8946a`.
Tree: `5ae322873bf8ef4142d49a9d082660bd3867e8af`.
Локальное дерево исходников побайтово соответствует tree GitHub; последующие
изменения каталога загрузок содержат только документацию и метаданные.

В `main` слиты #25 и #26–34 через интеграционный #37. Два новых PR #35–36
отклонены: Ansible 2.22 требует Python >=3.13, проект использует 3.12.
[Security review](security-quality-review-2026-11-18.md) и
[Dependabot review](dependabot-review-2026-11-18.md) содержат результаты и причины.

## Подготовленные файлы

Windows x64 MSI, macOS Apple Silicon DMG, macOS Intel DMG, Linux amd64 server/keygen.
Все бинарники имеют `19ad13c` в имени и используют Go-зависимости итогового commit,
включая sing 0.9.6, x/crypto 0.59.0, compress 1.20.2. Desktop version — 0.2.1,
Electron — 45.3.3, electron-builder — 26.18.0, Go — 1.27.4, Node — 24.22.3.
Go-артефакты собраны с `-trimpath -ldflags='-s -w'`, `CGO_ENABLED=0`,
`-buildvcs=false`; source provenance задаётся проверенным tree и manifest.

**Android 0.2.1 не выпущен.** Нет прежнего keystore; штатный preflight останавливает
сборку. Требуется исходный сертификат SHA-256
`b13dfe366940dc70d27e244c8bf17ed18ff3dfdad93713bdbc1b91cbfa85f0b1`.
Новый ключ не создавался. Старый APK 0.2.0 не содержит последующих исправлений
и не выдаётся за обновлённую сборку. Поэтому старый полный `installers/current/manifest.json`
не заменён неполным комплектом. Новые desktop-метаданные расположены отдельно.

## Проверки полученных пакетов

- MSI извлечён через msiextract: все 75 файлов совпадают с исходным payload.
  EXE и агент — PE x64. Проверены ProductVersion 0.2.1, стабильные ProductCode и
  UpgradeCode, таблицы ServiceInstall/ServiceControl, CustomAction и Upgrade.
- При новой версии RemoveExistingProducts идёт после InstallInitialize, внутри
  транзакции. Та же версия задаёт REINSTALL=ALL/REINSTALLMODE=amus. RecoverNetwork
  выполняется с повышенными правами и проверкой ошибки после StopServices, до
  DeleteServices/RemoveFiles, только при явном удалении, не при обновлении.
- Оба DMG проходят проверку контейнера 7-Zip. Из каждого извлечён единый
  `Install-LineVPN.pkg`, затем Payload и Scripts. Все 289 файлов и symlinks
  совпадают с подготовленным деревом. CPIO-записи имеют uid/gid 0; проверены
  безопасные относительные пути, версия и identifier пакета, preinstall/postinstall,
  приложение, агент, LaunchDaemon и сценарии восстановления/удаления.
- Каждый PKG обновляет `/Applications/LineVPN.app` и службу вместе, с
  `dev.linevpn.service` 0.2.1, фиксированным install-location `/` и upgrade-bundle.
- На каждой macOS-архитектуре проверены 14 Mach-O, 9 bundle seals и 477 ресурсных
  хешей, отдельно страницы ad-hoc подписи агента. Это проверка структуры и хешей
  на Linux, не результат Apple `codesign --verify` или Gatekeeper.
- Все три извлечённых ASAR содержат только точные main.cjs, preload.cjs и package.json
  версии 0.2.1; node_modules отсутствуют. У извлечённых агентов проверены Go module
  versions. SHA-256 и размеры записаны в manifest и SHA256SUMS.

## Сборка и подписи

Кросс-сборка на Linux использует WiX v3/wixl 0.106 (адаптер штатного WiX v4 XML),
libarchive/cpio, bomutils `c247002e2f49878bab32dd0fcf805810ae0992cb`,
rcodesign 0.29.0, mkdmg `3d3581c3dfa304a59b0a91915229285805b43ff6`.
Адаптер сохраняет identity, repair, upgrade ordering и uninstall conditions;
для совместимости wixl видимое имя службы/ярлыка — LineVPN.
В отдельном архиве переданы рецепт, проверки и логи без keystore и секретов.

Preview: Windows без Authenticode, приложение и агент macOS подписаны ad-hoc,
PKG не подписан Developer ID, нотарификации нет. Нативная установка, повторное
обновление, удаление, WFP/PF и поведение сети на устройствах не проверены.

## Проверки исходников и ограничения

PASS: полный Go race/vet после sing update; DOM + Chromium (90 сочетаний,
масштаб текста, диалоги/фокус); desktop glob regression; actionlint; Gitleaks;
OSV с одним ранее обоснованным picomatch-исключением до 25.11.2026.
Picomatch — известная build-only находка; исправленного upstream-релиза пока нет.
Установочные fixtures — 12 PASS; manual deployment — 7 PASS; SSH fixture — PASS.
Один Ansible fixture блокируется запретом локальных Unix sockets хоста, не исключён
из тестов. Новый Playwright проверен с уже установленным Chromium 141; загрузка
штатного 159 заблокирована сетью. GitHub Actions не начинает jobs из-за billing.

Ни один реальный VPS не обновлялся. Публикация бинарников не выполняет деплой.
Для установки macOS откройте DMG, затем **Install-LineVPN.pkg**. На Windows
запустите MSI поверх установленной версии; предварительное удаление не требуется.

## Публикация

Публикация GitHub Releases не завершена: две попытки загрузки файлов через браузер зависли. Нового релиза или успешной загрузки не подтверждено. Проверенные установщики, server/keygen, рецепт, manifest и суммы сохранены и переданы владельцу отдельными файлами. Запланированный тег — `v0.2.1-preview.20261118`. Исходники и результаты проверки находятся в main.
