# Завершение PR #25 — 18 ноября 2026

Проверены единственный открытый PR #25 (`912d007db4ec201835ddc28f76246bc914de140b`)
и его база `main` (`cdda72dee008a8fe7d9860237da3ca88febe878f`). Конфликтов и
открытых review threads нет. Полное дерево исходников получено из GitHub,
включая бинарные файлы документации; blob SHA, tree SHA и исходный commit SHA
проверены локально. Ревью выполнено одним исполнителем, без независимого ревьюера.

## Исправленные зависимости

- В исходном PR `klauspost/compress` уже обновлён до 1.20.2.
- `minimatch` 9.0.9 и 10.2.6 заменены через ограниченные overrides на 11.0.9.
  Не затронуты API старых major 3 и 5. Node 24 поддерживается новой версией.
  Воспроизведение `a/**/../b`, повторённого 18 раз при optimizationLevel=2,
  на старой версии превысило лимит 3 секунды и было завершено. После обновления
  библиотека быстро отклоняет шаблон с ожидаемым RangeError. Тот же тест
  проверяет включение/исключение файлов настоящим FileMatcher electron-builder.
- Свежая публичная база OSV также обнаружила GO-2026-5932 в `x/crypto` 0.58.0.
  Обновлено до 0.59.0, где устаревший OpenPGP вынесен из модуля. Необходимые
  транзитивные версии: x/sys 0.50.0, x/sync 0.25.0, x/text 0.44.0.
  `go mod tidy` удалил старые суммы и уточнил прямую зависимость protobuf.

Источники: [minimatch advisory](https://github.com/advisories/GHSA-g3hv-75wg-m249),
[изменение базы Go](https://go.googlesource.com/vulndb/+/a2082f757c2551694285855180b2d17666d7bcd6),
[picomatch advisory](https://osv.dev/vulnerability/GHSA-fc5q-39xc-vjpf).

## Ограниченное исключение picomatch

GHSA-fc5q-39xc-vjpf остаётся известной уязвимостью, а не считается исправленной.
18 ноября registry возвращает 4.0.7 как последнюю версию; исправленного выпуска нет.
Исключение в `apps/desktop/osv-scanner.toml` действует только для этого lockfile,
только для данного advisory и его aliases, до **25 ноября 2026**. Нет исключения
всего пакета, npm или devDependencies. Ответственный за повторную оценку —
сопровождающий репозитория `jEUGENEdev`. После срока OSV снова блокирует проверку,
если находка не устранена. При изменении цепочки зависимостей нужна новая оценка.

Проверенная цепочка: electron-builder 26.18.0 → app-builder-lib →
@electron/rebuild 4.2.1 → node-gyp 12.4.0 → tinyglobby 0.2.17 → picomatch 4.0.7.
fdir 6.5.0 использует ту же копию picomatch. У node-gyp в `lib/build.js` только
литеральные glob `build/*.sln` и `build/*.mk`. Данные VPN, адреса, профили и
сообщения API не становятся шаблонами сборки. Недоверенные PR уже могут исполнять
произвольный код в PR runner; секреты production туда не передаются.

В `apps/desktop/package.json` нет production npm dependencies, все пакеты lockfile
помечены dev. Реальная Windows-упаковка electron-builder успешно выполнена:
ASAR содержит только `main.cjs`, `preload.cjs`, `package.json`, без node_modules.
Таким образом, предпосылка этой ReDoS-находки отсутствует в проверенном пути
исполнения приложения. Это обоснование неприменимо к другому приложению или
сборочному сценарию с пользовательскими glob.

## Фактическая проверка

| Проверка | Результат |
| --- | --- |
| `bash scripts/check.sh go` после обновления x/crypto | PASS: gofmt, module verify, все race tests с with_gvisor, vet |
| `bash scripts/check.sh ui` | PASS: DOM, полный Chromium, 90 экран/тема/размер сочетаний, масштаб текста и возврат фокуса |
| `bash scripts/check.sh desktop` | PASS: отказ опасного glob за ограниченное время и совместимость FileMatcher |
| `bash scripts/check-security.sh` | PASS с одним раскрытым выше временным исключением; actionlint, Gitleaks, 3 теста правил, OSV Go/npm/Python |
| `bash scripts/check.sh portable` | Не завершён успешно: 1 Ansible-тест заблокирован средой |
| Installer fixtures | PASS: 12 тестов, recovery ordering и проверка версии 0.2.1 |
| Deployment Actions fixtures | 6 PASS; `test_generated_admin_password_survives_redeploy` не выполнен из-за запрета AF_UNIX |
| Ручной деплой и SSH fixtures отдельными командами | PASS: 7 manual и 1 SSH тест |
| Windows Electron payload | Собран; проверен состав ASAR |
| Нативные Windows/macOS/Android acceptance | Не запускались в этой Linux-среде |

Ansible 2.21.6 требует локальный Unix socket для RPC; `socket(AF_UNIX)` возвращает
EPERM, далее `Local RPC server did not start`. Утверждения теста не ослаблены,
тест не исключён из общего прогона. Это ограничение окружения, а не PASS.

[GitHub Actions #60](https://github.com/jEUGENEdev/vpn/actions/runs/44130219288)
не запустил security job из-за ошибки оплаты аккаунта или лимита расходов.
Причина прочитана в annotations через интерфейс GitHub. Удалённый CI не считается
успешным; добавленные проверки по-прежнему обязательны для зависимых jobs.

## Установщики и границы результата

Версия исходников — 0.2.1; прежний опубликованный комплект — 0.2.0 из d067d97.
Подготовка новых desktop preview ведётся отдельно с проверкой содержимого
MSI/DMG/PKG. Linux-кросс-сборка не подтверждает работу WFP/PF, Apple Gatekeeper,
установку/обновление на реальных ОС или отсутствие сетевых утечек.

В текущем окружении нет прежнего Android keystore. Штатный preflight отклоняет
выпуск без `ANDROID_KEYSTORE`; новый ключ не создаётся. Нужен исходный ключ с
сертификатом из текущего manifest, иначе Android отклонит обновление поверх
существующего приложения. Результат с другой подписью нельзя выдавать за обновление.
