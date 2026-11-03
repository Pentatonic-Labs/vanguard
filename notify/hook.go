package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

const (
	// CommandTimeout bounds a notify command. A transport that hangs must not
	// stall the watch loop behind it.
	CommandTimeout = 60 * time.Second
	// WebhookTimeout bounds the webhook request. Retries belong to the
	// receiver, not to a poll loop that only fires when something changed.
	WebhookTimeout = 10 * time.Second
)

// RunCommand runs path once with the payload as JSON on stdin. Output from the
// command is only surfaced when it fails.
func RunCommand(path string, payload Payload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), CommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path)
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return fmt.Errorf("%s: %w: %s", path, err, msg)
		}
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// PostWebhook posts the payload to url once, with no retries.
func PostWebhook(url string, payload Payload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), WebhookTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s: HTTP %s", url, resp.Status)
	}
	return nil
}
