package events

import (
	"fmt"
	"github.com/jEUGENEdev/vpn/internal/policy"
	"sync"
	"time"
)

type Event struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`
	Title   string    `json:"title"`
	Message string    `json:"message"`
	Target  string    `json:"target,omitempty"`
	At      time.Time `json:"at"`
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
func (c *Center) add(now time.Time, kind, key, title, msg, target string, cooldown time.Duration) bool {
	if at, ok := c.last[key]; ok && now.Sub(at) < cooldown {
		return false
	}
	c.last[key] = now
	c.next++
	c.items = append(c.items, Event{fmt.Sprint(c.next), kind, title, msg, target, now})
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
	c.mu.Lock()
	defer c.mu.Unlock()
	c.outage = true
	c.add(now, "outage", "outage", "VPN недоступен", message, "", 15*time.Minute)
}
func (c *Center) Recovered(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.outage {
		c.outage = false
		c.add(now, "recovered", "recovered", "Защита восстановлена", "Одобренные адреса снова доступны через VPN.", "", time.Minute)
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
	if c.add(now, "suggestion", "suggest:"+key, "Не удаётся подключиться", target+": можно попробовать разрешить VPN. Причиной также может быть сбой самого сайта.", target, time.Hour) {
		c.globalSuggestion = now
	}
}
func (c *Center) List() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Event{}, c.items...)
}

func (c *Center) NewApplication(now time.Time, id, name, target string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.globalSuggestion) < 5*time.Minute {
		return
	}
	if c.add(now, "application", "app:"+id, "Новое приложение", name+" обращается к "+policy.Group(target)+". Откройте Линию, чтобы выбрать VPN для приложения или только отдельных адресов.", id, 24*time.Hour) {
		c.globalSuggestion = now
	}
}

func (c *Center) DirectUnavailable(now time.Time, target string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.globalSuggestion) < 5*time.Minute {
		return
	}
	if c.add(now, "suggestion", "suggest:"+policy.Group(target), "Нет ответа напрямую", target+": прямое подключение несколько раз завершилось ошибкой. Можно разрешить VPN; причиной также может быть сбой самого сервиса.", target, time.Hour) {
		c.globalSuggestion = now
	}
}
