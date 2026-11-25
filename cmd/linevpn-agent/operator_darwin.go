package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const operatorDir = "/Library/Application Support/LineVPN"

func openDesktopOperator(_ string) (*desktopOperator, error) {
	raw, err := os.ReadFile(filepath.Join(operatorDir, "desktop-operator.uid"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	uid := strings.TrimSpace(string(raw))
	n, err := strconv.ParseUint(uid, 10, 32)
	if err != nil || n < 500 || strconv.FormatUint(n, 10) != uid {
		return nil, errors.New("invalid desktop operator UID")
	}
	account, err := user.LookupId(uid)
	if err != nil || account.Username == "" || strings.ContainsAny(account.Username, ":, \t\n\r") {
		return nil, errors.New("desktop operator account unavailable")
	}
	path := filepath.Join(operatorDir, "desktop-operator.json")
	token, err := writeOperatorToken(path)
	if err != nil {
		return nil, err
	}
	if err = exec.Command("/bin/chmod", "+a", "user:"+account.Username+" allow read,readattr", path).Run(); err != nil {
		return nil, err
	}
	// launchctl must enter the active GUI bootstrap before running osascript
	// as the operator. Keep only this fixed dialog operation across UID drop.
	cmd := exec.Command(filepath.Join(operatorDir, "linevpn-agent"), "--operator-dialog", uid)
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, childOutput, err := os.Pipe()
	if err != nil {
		input.Close()
		return nil, err
	}
	cmd.Stdout = childOutput
	err = cmd.Start()
	childOutput.Close()
	if err != nil {
		input.Close()
		output.Close()
		return nil, err
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			input.Close()
			output.Close()
			cmd.Process.Kill()
			cmd.Wait()
		})
	}
	encoder, reader := json.NewEncoder(input), bufio.NewReader(output)
	confirm := func(ctx context.Context, summary string) (bool, error) {
		deadline, _ := ctx.Deadline()
		if err := output.SetReadDeadline(deadline); err != nil {
			stop()
			return false, err
		}
		if err := encoder.Encode(summary); err != nil {
			stop()
			return false, err
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			stop() // An abandoned reply must never approve a subsequent ticket.
			return false, err
		}
		return line == "true\n" && ctx.Err() == nil, nil
	}
	return &desktopOperator{token: token, confirm: confirm, close: stop}, nil
}

func consoleOperator(uid string) bool {
	var stat syscall.Stat_t
	return syscall.Stat("/dev/console", &stat) == nil && stat.Uid >= 500 && strconv.FormatUint(uint64(stat.Uid), 10) == uid
}

func serveOperatorDialog(uid string) error {
	if os.Geteuid() != 0 {
		return errors.New("operator dialog broker requires the service")
	}
	for _, file := range []*os.File{os.Stdin, os.Stdout} {
		info, err := file.Stat()
		if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			return errors.New("operator dialog requires inherited pipes")
		}
	}
	const script = `on run argv
set choice to display dialog (item 1 of argv) with title "Сеть — подтверждение" buttons {"Отмена", "Разрешить"} default button "Отмена" cancel button "Отмена" with icon caution giving up after 75
if not (gave up of choice) and (button returned of choice is "Разрешить") then return "allow"
return "deny"
end run`
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 16384)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	summaries := make(chan string)
	go func() {
		defer close(summaries)
		defer stop() // Parent exit also dismisses a dialog already in progress.
		for scanner.Scan() {
			var summary string
			if json.Unmarshal(scanner.Bytes(), &summary) != nil || len(summary) > 3000 {
				return
			}
			select {
			case summaries <- summary:
			case <-ctx.Done():
				return
			}
		}
	}()
	for summary := range summaries {
		allowed := false
		if consoleOperator(uid) {
			dialogCtx, cancel := context.WithTimeout(ctx, 80*time.Second)
			cmd := exec.CommandContext(dialogCtx, "/bin/launchctl", "asuser", uid, "/usr/bin/sudo", "-n", "-H", "-u", "#"+uid, "--", "/usr/bin/osascript", "-e", script, summary)
			cmd.WaitDelay = time.Second
			output, err := cmd.Output()
			cancel()
			allowed = err == nil && ctx.Err() == nil && strings.TrimSpace(string(output)) == "allow" && consoleOperator(uid)
		}
		if _, err := fmt.Fprintln(os.Stdout, allowed); err != nil {
			return err
		}
	}
	return scanner.Err()
}
