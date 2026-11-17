package events

import (
	"fmt"
	"sync"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
)

type Event struct {
	ID      string                 `json:"id"`
	Kind    string                 `json:"kind"`
	Title   string                 `json:"title"`
	Message string                 `json:"message"`
	Target  string                 `json:"target,omitempty"`
	At      time.Time              `json:"at"`
	Source  *model.ApplicationInfo `json:"source,omitempty"`
}
type Center struct {
	mu               sync.Mutex
	last             map[string]time.Time
	items            []Event
	outage           bool
	next             uint64
	globalSuggestion time.Time
	failures         map[string][]time.Time
}

func New() *Center { return &Center{last: map[string]time.Time{}, failures: map[string][]time.Time{}} }
func (c *Center) add(now time.Time, kind, key, title, msg, target string, source model.ApplicationInfo, cooldown time.Duration) bool {
	if at, ok := c.last[key]; ok && now.Sub(at) < cooldown {
		return false
	}
	c.last[key] = now
	c.next++
	event := Event{ID: fmt.Sprint(c.next), Kind: kind, Title: title, Target: target, At: now}
	if target != "" {
		// Capture the actual triggering connection, never infer its owner from
		// other requests to the same address. Message also reaches native clients.
		origin := "Приложение-источник не определено"
		if source.ID != "" && source.Name != "" && source.Path != "" {
			event.Source = &source
			origin = source.Name
		}
		msg += "\nАдрес: " + target + "\nИсточник: " + origin
	}
	event.Message = msg
	c.items = append(c.items, event)
	if len(c.items) > 100 {
		c.items = c.items[len(c.items)-100:]
	}
	if len(c.last) > 4096 {
		for k, v := range c.last {
			if now.Sub(v) > 24*time.Hour {
				delete(c.last, k)
			}
		}
	}
	return true
}
func (c *Center) Outage(now time.Time, message string) {
	c.ConnectionOutage(now, message, "", model.ApplicationInfo{})
}
func (c *Center) ConnectionOutage(now time.Time, message, target string, source model.ApplicationInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.outage = true
	title := "VPN недоступен"
	if target != "" {
		title = "Ошибка VPN-соединения"
	}
	c.add(now, "outage", "outage", title, message, target, source, 15*time.Minute)
}
func (c *Center) Recovered(now time.Time) {
	c.ConnectionRecovered(now, "", model.ApplicationInfo{})
}
func (c *Center) ConnectionRecovered(now time.Time, target string, source model.ApplicationInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.outage {
		c.outage = false
		c.add(now, "recovered", "recovered", "Защита восстановлена", "Одобренные адреса снова доступны через VPN.", target, source, time.Minute)
	}
}
func (c *Center) FailedDirect(now time.Time, target string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := policy.Group(target)
	times := c.failures[key][:0]
	for _, at := range c.failures[key] {
		if now.Sub(at) < time.Minute {
			times = append(times, at)
		}
	}
	times = append(times, now)
	c.failures[key] = times
	if len(c.failures) > 4096 {
		for k, v := range c.failures {
			if len(v) == 0 || now.Sub(v[len(v)-1]) > time.Minute {
				delete(c.failures, k)
			}
		}
	}
	if len(times) < 2 || now.Sub(c.globalSuggestion) < 5*time.Minute {
		return
	}
	if c.add(now, "suggestion", "suggest:"+key, "Не удаётся подключиться", "Можно попробовать разрешить VPN. Причиной также может быть сбой самого сайта.", target, model.ApplicationInfo{}, time.Hour) {
		c.globalSuggestion = now
	}
}
func (c *Center) List() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	items := append([]Event{}, c.items...)
	for i := range items {
		if items[i].Source != nil {
			source := *items[i].Source
			items[i].Source = &source
		}
	}
	return items
}

func (c *Center) NewApplication(now time.Time, source model.ApplicationInfo, target string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.globalSuggestion) < 5*time.Minute {
		return
	}
	if c.add(now, "application", "app:"+source.ID, "Новое приложение", "Нет ответа напрямую. Откройте Линию, чтобы выбрать VPN для приложения или только отдельных адресов.", target, source, 24*time.Hour) {
		c.globalSuggestion = now
	}
}

func (c *Center) DirectUnavailable(now time.Time, target string, source model.ApplicationInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.globalSuggestion) < 5*time.Minute {
		return
	}
	if c.add(now, "suggestion", "suggest:"+policy.Group(target), "Нет ответа напрямую", "Прямое подключение несколько раз завершилось ошибкой. Можно разрешить VPN; причиной также может быть сбой самого сервиса.", target, source, time.Hour) {
		c.globalSuggestion = now
	}
}
