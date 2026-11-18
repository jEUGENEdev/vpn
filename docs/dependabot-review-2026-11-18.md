# Проверка автоматических PR — 18 ноября 2026

После слияния #25 Dependabot создал #26–36. В интеграцию входят #26–34;
#35 и #36 отклонены с конкретной причиной совместимости.

| PR | Решение и проверка |
| --- | --- |
| #26–29, #31 | Обновить закреплённые SHA setup/cache Actions. Проверены action.yml, сохранены используемые inputs и permissions. Node 24 поддерживается выбранными GitHub-hosted runners; actionlint PASS. Удалённый запуск блокируется billing. |
| #30 | Обновить setup-gradle 6.4.1, явно выбрать `cache-provider: basic`: прежнее хранение в GitHub Actions cache, без нового коммерческого сервиса, который стал default. |
| #32 | Playwright 1.65.1: полный UI-прогон PASS с установленным Chromium 141 (revision 1194), выбранным через существующий CHROMIUM_PATH. Загрузка штатного Chromium 159 блокируется политикой сети хоста (HTML вместо ZIP); с ним тесты не выполнены. CI по-прежнему устанавливает штатный браузер. |
| #33 | sing 0.9.6: module verify, полный race-прогон с with_gvisor и vet PASS. Дальнейшие desktop-сборки используют эту версию. |
| #34 | jsdom 31.0.1: исходный DOM-тест пытался фокусировать поле скрытой вкладки. Сценарий теперь открывает нужные вкладки и дополнительно требует успешного фокуса при каждом вводе. Проверки сохранения фокуса и политики сохранены. DOM и Chromium PASS. |
| #35–36 | Не сливать ansible-core 2.22.0: requires_python `>=3.13`, а CI и контроллер используют Python 3.12. `pip install ansible-core==2.22.0` на 3.12 воспроизводимо не находит совместимый выпуск. Остаётся 2.21.6; Python 3.11 remote использует 2.19.15. |

`scrollIntoView` в DOM-окружении заменён пустой функцией, поскольку jsdom не
реализует раскладку. Реальная прокрутка и геометрия остаются в Chromium suite.
Полный браузерный прогон: 90 сочетаний экрана/темы/размера, 200% текста,
диалоги, сохранение фокуса, вход и управление разрешениями.

Повторный security-прогон PASS: actionlint, Gitleaks и OSV с тем же одним
временным picomatch-исключением, раскрытым в
[отчёте #25](security-quality-review-2026-11-18.md). Новых исключений нет.
Ограничение AF_UNIX для Ansible fixtures и отсутствие нативной приёмки остаются.

Источники требований: [Ansible PyPI](https://pypi.org/pypi/ansible-core/2.22.0/json),
[Gradle action.yml](https://github.com/gradle/actions/blob/8da46b539cd8fe6ab27ca75128919a18d757604c/setup-gradle/action.yml),
[setup-go](https://github.com/actions/setup-go/blob/b7ad1dad31e06c5925ef5d2fc7ad053ef454303e/action.yml).
