# Развёртывание сервера

Требуется чистый VPS Debian 12/13 или Ubuntu 24.04, Linux amd64, публичный IPv4/IPv6 и SSH. Домен и покупной сертификат не нужны. Порты: TCP 443 для REALITY, TCP 8443 для TLS API и админки, ваш SSH-порт. На хосте не должны работать другие сервисы на 443/8443.

## Установка

На управляющей машине установите Go 1.27.4 и Ansible, клонируйте репозиторий и выполните:

```bash
scripts/build-server.sh
cd deploy/ansible
cp inventory.example.ini inventory.ini
cp group_vars/vpn.example.yml group_vars/vpn.yml
ansible-galaxy collection install -r requirements.yml
ansible-vault create group_vars/vault.yml
```

В `inventory.ini` укажите VPS. В зашифрованном `group_vars/vault.yml` сохраните:

```yaml
vault_admin_password: "ВАШ_УНИКАЛЬНЫЙ_ПАРОЛЬ_16_72_БАЙТА"
```

Передайте vault-файл явно, потому что он не является группой inventory:

```bash
ansible-playbook deploy.yml --extra-vars @group_vars/vault.yml --ask-vault-pass
```

Playbook создаёт пользователя `linevpn`, ключи REALITY, сертификат TLS с IP в SAN, systemd-службу, месячное обновление сертификата и firewall. Ключи создаются только один раз. Повторный запуск не меняет закреплённый публичный ключ API. Секреты и сгенерированные профили исключены из Git.

После установки в `deploy/ansible/generated/` появятся профиль `linevpn://IP:8443?pin=…` и сертификат API. Они получены по проверенному SSH-соединению. Профиль содержит публичный отпечаток, а не пароль аккаунта.

## Админка

Адрес: `https://IP:8443/`. Пароль — `vault_admin_password`, на VPS он находится в `/etc/linevpn/admin-password` с режимом 0600. Внесите полученный по SSH сертификат в доверенные сертификаты своего браузера/ОС. Не подтверждайте неизвестный сертификат без проверки. Клиент проверяет SPKI-отпечаток автоматически и отклоняет подмену, просроченный сертификат и HTTP-переадресацию.

Регистрация создаёт `pending`. До одобрения не выдаются рабочие данные устройства. Администратор может одобрить/отклонить заявку, заблокировать аккаунт и отозвать отдельное устройство. Блокировка/отзыв перестраивает Xray и завершает существующие сессии.

## Обслуживание

```bash
sudo systemctl status linevpn
sudo journalctl -u linevpn -n 50
sudo systemctl status linevpn-renew.timer
```

Резервируйте `/etc/linevpn` и `/var/lib/linevpn` в зашифрованном виде. Для согласованной копии BoltDB остановите службу или используйте snapshot-транзакцию. Потеря ключа API требует нового профиля на устройствах. При смене IP требуется обновить конфигурацию и сертификат; playbook не заменяет их молча.

Сборки сервера также сохраняются как артефакт workflow `server-binaries`. Проверка `-check` проверяет поля конфигурации; полный запуск проверяет совместимость Xray и доступность слушателей.
