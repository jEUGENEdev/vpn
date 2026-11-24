#!/bin/bash
set -euo pipefail
/usr/bin/osascript -e 'display dialog "Полностью удалить «Сеть», фоновую службу, локальный профиль, вход и настройки? Несохранённые на сервере правила будут потеряны. Для новой установки нужны профиль сервера и ключ доступа." with title "Удаление «Сеть»" buttons {"Отмена", "Удалить"} default button "Отмена" cancel button "Отмена" with icon caution' >/dev/null
sudo '/Library/Application Support/LineVPN/uninstall.sh'
