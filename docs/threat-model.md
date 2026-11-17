# Рабочая модель угроз LineVPN

Основа: `main` `cdda72dee008a8fe7d9860237da3ca88febe878f`, 17 ноября 2026.
Это модель для разработки и ревью, а не полный аудит. При изменении границы
доверия обновите таблицу и соответствующие проверки.

Активы: правила маршрутизации, намерение off/on, токены устройств и аккаунтов,
ключ профиля, admin session, TLS/REALITY private keys, ключи подписи установщиков,
конфиденциальность трафика и доступность сети. Публичный SPKI pin и имя устройства
не являются секретами или доказательством полномочий.

| Граница / основной код | Недоверенный ввод и опасность | Обязательный контроль / проверка |
| --- | --- | --- |
| Интернет → API (`internal/server`) | Тела запросов, старые/чужие токены, регистрация, pair/rotate | Лимиты тела/частоты, auth + account/device ownership, проверки внутри транзакции; `server/*_test.go` |
| Клиент → TLS API (`internal/secure`) | Чужой/просроченный сертификат, redirect | TLS 1.3, обязательный SPKI и validity check, запрет redirect; `secure_test.go` |
| Приложение → TUN/DNS (`internal/client`, `internal/owner`) | Домен/IP, процесс, UDP tuple, неподтверждённая атрибуция | Нормализация, Fake-IP mapping, OS ownership, отдельное правило назначения, fail-closed; client/policy/owner tests |
| Политика → сетевой runtime (`client`, `transport`, `platform`) | Сбой API/worker, stale dial, отмена, смена сети | Сохранённые правила, `routeEpoch`, закрытие старых потоков, firewall и явный off; race/power/fail_closed tests + native packet capture |
| VLESS → публичный egress (`internal/transport`) | Внутренний адрес, metadata, обход через app credential | Deny-by-default, одинаковый запрет служебных сетей у обоих credentials, отзыв принятых сессий; transport integration tests |
| Аккаунт → устройства (`server/devices.go`, `access_keys.go`) | Совпавшее имя, украденный старый токен, cross-account action | Имя не identity, независимые device credentials, атомарный отзыв/ротация; devices/access_keys tests |
| Web UI → local API (`client/localapi.go`, `apps/desktop`) | Чужой HTTP origin, HTML в домене/имени, недоверенный IPC | Loopback, bearer token, CSP/экранирование, узкий preload; DOM/browser tests и ревью Electron настроек |
| Запись → диск (`secure.Save`, `internal/store`) | Неполная запись, некорректный state, crash | Сохранение до публикации, ограниченные права, транзакции, отсутствие неявного recovery; upgrade/network_intent tests |
| Installer → привилегированная ОС (`packaging`, `scripts`) | Повторная установка, старая версия, другой signer, ошибка stop/cleanup | Стабильная identity, проверка подписи/версии, сохранение state, fail-closed при upgrade; portable fixtures + native acceptance |
| PR/зависимость → CI → deploy | Подменённый Action/package, install script, секрет в diff | SHA/lockfile, read-only checks, secret scan, security prerequisite, main-only publish/deploy |

Особенности модели:

- Локальные пользователи desktop preview разделяют доступ к политике машины;
  приложение пока не обещает изоляцию VPN-аккаунта между пользователями ОС.
- Управление сетью требует привилегий. Администратор ОС, скомпрометированный VPS
  и оператор гипервизора находятся за пределами обещаний этой защиты.
- При падении TUN desktop firewall может блокировать всю сеть. Автоматически
  открывать её ради доступности нельзя; административный recovery явный.
- Android без системного lockdown не гарантирует защиту после смерти процесса.
  DoH/DoT и неизвестный владелец потока ограничивают доменную/приложенческую
  классификацию; это нельзя скрывать формулировкой «утечек нет».
- Запись отзыва в БД сама по себе не доказывает отзыв активного транспорта:
  для изменений `Apply` проверяйте отказ, сужение правил и уже принятые потоки.

Не подтверждаются одним Linux-прогоном: фактическая конфигурация VPS/SSH/firewall,
работа PF/WFP на пользовательской ОС, Android lockdown, сон/смена сети,
доверие к сертификату подписи и поведение старого установленного клиента.
Список оставшихся проверок поддерживается в `docs/acceptance.md` и `docs/status.md`.
