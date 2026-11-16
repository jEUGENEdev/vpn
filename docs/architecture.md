# Архитектура

- `internal/policy`: нормализация адресов, наследование доменов, решение direct/VPN/block.
- `internal/client`: устойчивая DNS-таблица, TUN TCP/UDP, политика и синхронизация, локальный API.
- `internal/transport`: закреплённая версия Xray, VLESS/XHTTP/REALITY, запрет private egress и обязательный socket protect/bind.
- `internal/server`, `internal/store`: аккаунты, регистрационные заявки, устройства, одноразовая привязка, разрешения, BoltDB.
- `internal/events`: ограничение частоты уведомлений и группировка доменов.
- `internal/platform`: persistent WFP / PF, TUN и привязка исходящих сокетов к физическому интерфейсу.
- `internal/ui`: встроенный интерфейс клиента и админки без внешних CDN/шрифтов/аналитики.
- `apps/desktop`: Electron UI; фоновая служба существует независимо от окна.
- `apps/android`, `mobile`: Android VpnService, уведомления и JNI/gomobile.
- `deploy/ansible`: воспроизводимый деплой Linux-сервера без домена.
- `scripts`, `packaging`, `.github/workflows`: платформенные сборки и комплект установщиков.

## Разработка

Go 1.27.4, Node 24, Java 17, Android SDK 35 / NDK 28.0.13004108 / Gradle 8.11.1. Мобильный клиент использует Android 10+.

```bash
go test -race -tags with_gvisor ./...
go vet -tags with_gvisor ./...
scripts/build-server.sh
```

Интеграционный тест транспортного слоя поднимает настоящий Xray-клиент и сервер с XHTTP/REALITY и проверяет TCP round trip, затем удаляет разрешение и проверяет отсутствие соединений к целевому listener. Интернет и реальный VPS для этого теста не нужны.

Нативные команды сборки: `scripts/package-android.sh`, `scripts/package-macos.sh arm64` / `amd64`, `scripts/package-windows.ps1`. macOS-пакет собирается на macOS, MSI — на Windows. Секреты подписи не заложены в репозиторий. Полный комплект публикуется в `installers/current` только после прохождения всех сборок, через Git LFS.

UI не содержит логотипов/герба Роскомнадзора или Ростелекома и не заявляет официальную связь. Визуальные ориентиры: строгая сине-белая основа, фиолетовые и оранжевые акценты, крупная типографика, русский язык, светлая/тёмная тема и адаптация к телефону.
