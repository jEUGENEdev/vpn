# Android APK 0.2.1 — 19 ноября 2026

Исходники: commit `2dc8d555085a423117ccf7f01a0410086529338e`,
tree `b9c34084732fb85cef4a4b950d373f29cb0f9889`.
Локальное дерево перед сборкой сверено с GitHub побайтово.
База — main `2d2ea1b9b66125ad922c77d85e3f4958162ca6a7`.
Изменения этого выпуска касаются подписи и её проверок; VPN-код и зависимости
берутся из актуальной main. Старое Go-ядро из APK 0.2.0 не переиспользуется.

## Подпись и миграция

Владелец разрешил новый ключ при отсутствии прежнего. Старый keystore не найден
среди доступных файлов и резервных копий; Android-секреты Actions отсутствовали.
Проверены SHA-256 и сертификат прежнего опубликованного APK d067d97.
Новый постоянный RSA-3072 ключ не совместим с обновлением поверх старой подписи.
Приватная резервная копия передана отдельно и не входит в Git/Release.
Отпечатки и безопасный порядок перехода: [android-signing.md](android-signing.md).
GitHub Actions secrets этой ручной сборкой не настроены.

## Воспроизведение

- Go 1.27.4; Java Temurin 17.0.21.1+2; Gradle 8.11.1.
- Android SDK 35 / Build Tools 35.0.0 / NDK 28.0.13004108.
- Версии библиотек из неизменённых go.mod/go.sum и Gradle-файлов.
- `GOFLAGS='-p=2 -buildvcs=false -trimpath'`, `GOMAXPROCS=2`.
- `scripts/package-android.sh`: свежий gomobile AAR с `with_gvisor`,
  `-ldflags='-checklinkname=0 -s -w'`, Android API 29, ARM64 + x86_64.
- После исправления локального адреса прокси выполнен Gradle
  `-p apps/android --no-daemon --max-workers=2 assembleRelease` с тем же AAR.
  Локальный JVM использует системное хранилище доверенных CA; TLS-проверка
  не отключалась. Исправления прокси не входят в исходники приложения.
- `ANDROID_KEYSTORE` и пароли читаются из приватной копии через окружение;
  значения не передаются в командной строке и не входят в рецепт.

## Проверки исходников

PASS: полный `scripts/check.sh go` (целостность модулей, race-тесты всех пакетов,
vet); 13 installer regression tests; DOM-тесты; desktop glob/file filters;
actionlint; Gitleaks с редактированием значений; OSV offline для Go/npm/PyPI.
Новый regression test сначала воспроизвёл отсутствие отдельной закреплённой
подписи, затем прошёл; повреждённый отпечаток, другой ключ и старый сертификат
не получают обхода проверки совместимости.

Полный локальный прогон **не полностью зелёный**: Chromium не запускается из-за
запрета Unix-сокетов; один Ansible fixture не может запустить локальный RPC по той
же причине. SSH fixture заканчивается `Connection reset by peer`; его успех
не заявляется. Остальные portable fixtures, в том числе установщики и deployment
command generation, пройдены. Эти ограничения не скрывались изменением тестов.

Нативные установка/обновление, VPN, lockdown, трафик IPv4/IPv6 и поведение на
физическом Android-устройстве в этом выпуске не проверены. APK остаётся preview.
VPS и системная сеть пользовательских устройств не изменялись.

## Проверка готового APK

PASS: release-вариант без debuggable/testOnly; `dev.linevpn.app`, versionName 0.2.1,
versionCode 2001, minSdk 29, targetSdk 35. `apksigner verify --verbose --print-certs`
подтвердил APK Signature Scheme v2 и единственный постоянный RSA-3072 сертификат.
`zipalign -c -P 16 4` пройден; ELF LOAD-сегменты обеих архитектур имеют alignment
16384. Обе native-библиотеки побайтово совпали с результатом независимого
`llvm-strip --strip-unneeded` свежих библиотек AAR. DEX и notices присутствуют.

`verify_android_update.py --previous` принимает новый APK с тем же сертификатом
и отклоняет реальный старый APK d067d97 с ожидаемой ошибкой несовместимой подписи.
Это статическая проверка, не установка на устройство.

Файл: `LineVPN-0.2.1-2dc8d55-android-preview.apk`.
Размер: 85808763 байт.
SHA-256: `58e73b228cb68ba0635ebcf625227d2b2b839f6d21f6ffcbbb62710f3857e720`.
