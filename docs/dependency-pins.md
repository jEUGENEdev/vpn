# Зависимости: причины закрепления

Проверено 24 ноября 2026 года. Псевдоверсия Go сама по себе не означает,
что код взят вне релиза. Обновлять транспорт нужно совместимым комплектом,
с проверкой активных сессий, отзыва и egress.

| Зависимость | Решение и проверяемая причина |
| --- | --- |
| Xray `676eaf66f8f0` | Это commit официального [релиза v26.11.9](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9). Тег v26 несовместим с объявленным module path без `/v26`; Go использует совместимую псевдоверсию того же commit. Другая версия кода ради оформления тега не устанавливается. |
| uTLS `a13c59ffe98b` | Закреплён в [go.mod этого релиза Xray](https://github.com/XTLS/Xray-core/blob/v26.11.9/go.mod). Нужна совместимость REALITY/Chrome fingerprint. Последний [тег uTLS v1.8.2](https://github.com/refraction-networking/utls/releases/tag/v1.8.2) старше этого кода; переход рассматривается при выпуске совместимого тега и обновлении Xray. |
| REALITY `4bb46b2afd8b` | Закреплён тем же релизом Xray. Upstream [REALITY](https://github.com/XTLS/REALITY) не публикует подходящих module release tags; проверка `git ls-remote --tags` не возвращает теги. |
| gorilla/websocket `d67f41855da4` | [Исправление маски WebSocket через crypto/rand](https://github.com/gorilla/websocket/commit/d67f41855da42d7bccd9ef050c49f7e54e783b95) закрывает [GO-2026-6278](https://pkg.go.dev/vuln/GO-2026-6278). Возврат на v1.5.3 вернёт уязвимость. История проверки: [Android review](android-app-isolation-2026-11-24.md). Перейти на тег после релиза с этим исправлением. |
| tailscale/wf `6fbb0a674ee6` | Совпадает с текущим upstream HEAD на дату проверки. Удаление WFP ради возраста версии лишит Windows kill switch. Замена требует отдельной нативной проверки WFP. |
| honnef.co/go/tools | Транзитивный tools-import самого `tailscale/wf`, установленный `go mod why -m`; не является runtime-импортом VPN. Директива `tool` в нашем модуле не удалит upstream import. Проверочные CLI устанавливаются отдельно через `tools/checks/install.sh`. |
| golang.org/x/tools | Приходит через существующий `tools` → `golang.org/x/mobile/bind` → `internal/importers` → `go/packages`. Требуется для Android bindings. |
| ghodss/yaml, yaml.v2 | Приходят через Xray `main/distro/all` → `infra/conf/serial`. Простая замена версии на другую библиотеку невозможна; удаление требует согласованного изменения импортов/форматов upstream. |

Python для деплоя закреплён полным набором транзитивных зависимостей и SHA-256
допустимых wheels в `deploy/remote-requirements.txt`; установка требует хеши и
запрещает сборку sdist. Это защищает от получения других байтов с тем же
номером версии, но не доказывает безопасность первоначально проверенного пакета.
Обновление lockfile требует проверки источника, новых wheels и двух поддержанных
веток Python/Ansible. Ansible Galaxy collection остаётся точно закреплённой
`community.general 10.7.0`; её версия не означает криптографическую подпись.

CI сохраняет OSV и добавляет `govulncheck v1.10.0 -tags with_gvisor ./...`.
Версия инструмента закреплена в `tools/checks/install.sh`, обновление не использует
`@latest` внутри production workflow. Go/npm/Python проверяются без новых
исключений сканера.
