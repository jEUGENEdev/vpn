package desktopcontrol

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// Description comes from the service's actual immutable request, not from the
// untrusted Electron process. Secrets are not put into dialogs or process argv.
func Description(action string, raw json.RawMessage, server string, application func(string) string) (string, error) {
	title, err := ActionTitle(action)
	if err != nil {
		return "", err
	}
	var data map[string]any
	if json.Unmarshal(raw, &data) != nil {
		return "", errors.New("invalid data")
	}
	clean := func(s string) string {
		return strings.Map(func(r rune) rune {
			if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
				return '�'
			}
			return r
		}, s)
	}
	var lines []string
	lines = append(lines, title, "Сервер: "+clean(server))
	switch action {
	case "settings-session":
		lines = append(lines, "Разрешить включать и выключать VPN, менять режим трафика и правила адресов и приложений без повторного ввода пароля. Доступ действует до выхода из приложения «Сеть», максимум 12 часов.")
	case "bootstrap":
		uri, _ := data["uri"].(string)
		u, e := url.Parse(uri)
		if e != nil {
			return "", e
		}
		lines = append(lines, "Новый сервер: "+clean(u.Host))
	case "login", "pair/claim":
		lines = append(lines, "Разрешить вход/привязку этого компьютера с введённым секретом.")
	case "register":
		lines = append(lines, "Имя аккаунта: "+clean(fmt.Sprint(data["login"])))
	case "applications":
		id, _ := data["id"].(string)
		name := id
		if application != nil {
			name = application(id)
		}
		decision, _ := data["decision"].(string)
		labels := map[string]string{"trusted": "ВЕСЬ трафик приложения через VPN", "addresses": "VPN только для разрешённых адресов", "denied": "Запретить VPN приложению"}
		if labels[decision] == "" {
			return "", errors.New("invalid decision")
		}
		lines = append(lines, "Приложение: "+clean(name), labels[decision])
	case "traffic-mode":
		mode, _ := data["mode"].(string)
		switch mode {
		case "all":
			lines = append(lines, "Разрешить VPN ВСЕМ приложениям и направить весь интернет-трафик через VPN.")
		case "selective":
			lines = append(lines, "Вернуть выборочные разрешения. Остальной трафик сможет идти напрямую.")
		default:
			return "", errors.New("invalid mode")
		}
	case "vpn":
		enabled, ok := data["enabled"].(bool)
		if !ok {
			return "", errors.New("invalid power")
		}
		if enabled {
			lines = append(lines, "Включить VPN и сохранённую защиту.")
		} else {
			lines = append(lines, "ВЫКЛЮЧИТЬ VPN. Весь трафик сможет идти напрямую.")
		}
	default:
		for _, key := range []string{"action", "target", "id"} {
			if value, ok := data[key]; ok {
				lines = append(lines, key+": "+clean(fmt.Sprint(value)))
			}
		}
		if action == "pair" {
			lines = append(lines, "Создать одноразовый код доступа для нового устройства.")
		}
		if action == "access-key/rotate" {
			lines = append(lines, "Отозвать текущие подключения и заменить ключ доступа аккаунта.")
		}
	}
	lines = append(lines, "Разрешайте только изменение, которое вы сами запросили в приложении «Сеть».")
	result := strings.Join(lines, "\n\n")
	if len(result) > 3000 {
		return "", errors.New("description too long")
	}
	return result, nil
}
