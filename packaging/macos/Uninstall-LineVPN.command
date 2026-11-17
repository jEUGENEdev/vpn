#!/bin/bash
set -euo pipefail
echo 'Удаление Линии VPN и восстановление сети. Потребуется пароль администратора.'
sudo '/Library/Application Support/LineVPN/uninstall.sh'
