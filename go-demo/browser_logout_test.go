package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Opt in with GODEMO_WEBDRIVER_URL=http://127.0.0.1:<chromedriver-port>.
// Only synthetic in-memory sessions and a loopback fake forum are used.
func TestBrowserLogoutForm(t *testing.T) {
	driverURL := os.Getenv("GODEMO_WEBDRIVER_URL")
	if driverURL == "" {
		t.Skip("set GODEMO_WEBDRIVER_URL to a local ChromeDriver")
	}
	u, err := url.Parse(driverURL)
	if err != nil || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") {
		t.Fatal("WebDriver must use a loopback HTTP URL")
	}
	f := makeForum(t)
	a, store := makeApp(t, f)
	cookie, session := seedSession(t, a, time.Now().Add(time.Hour))
	srv := httptest.NewUnstartedServer(nil)
	a.config.PublicBaseURL = "http://" + srv.Listener.Addr().String()
	app := a.handler()
	headers := make(chan [2]string, 1)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app.ServeHTTP(w, r)
		if r.Method == http.MethodPost && r.URL.Path == "/logout" {
			headers <- [2]string{r.Header.Get("Origin"), r.Header.Get("Referer")}
		}
	})
	srv.Start()
	t.Cleanup(srv.Close)
	client := &http.Client{Timeout: 30 * time.Second}
	command := func(method, path string, payload any) any {
		t.Helper()
		var body io.Reader
		if payload != nil {
			encoded, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			body = bytes.NewReader(encoded)
		}
		r, err := http.NewRequest(method, strings.TrimRight(driverURL, "/")+path, body)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var reply struct{ Value any }
		if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("WebDriver %s %s returned HTTP %d", method, path, resp.StatusCode)
		}
		return reply.Value
	}
	caps := map[string]any{"capabilities": map[string]any{"alwaysMatch": map[string]any{
		"browserName": "chrome", "goog:chromeOptions": map[string]any{
			"args": []string{"--headless=new", "--no-sandbox", "--disable-dev-shm-usage", "--no-proxy-server", "--disable-background-networking", "--disable-component-update", "--no-first-run"},
		},
	}}}
	created := command("POST", "/session", caps).(map[string]any)
	path := "/session/" + created["sessionId"].(string)
	t.Cleanup(func() { command("DELETE", path, nil) })
	command("POST", path+"/url", map[string]any{"url": srv.URL + "/"})
	command("POST", path+"/cookie", map[string]any{"cookie": map[string]any{
		"name": cookie.Name, "value": cookie.Value, "path": "/", "httpOnly": true, "sameSite": "Lax",
	}})
	command("POST", path+"/url", map[string]any{"url": srv.URL + "/?browser_test=logout"})
	button := command("POST", path+"/element", map[string]any{"using": "css selector", "value": "form[action='/logout'] button"}).(map[string]any)
	id := button["element-6066-11e4-a52e-4f735466cecf"].(string)
	command("POST", path+"/element/"+id+"/click", map[string]any{})
	select {
	case got := <-headers:
		if got[0] != srv.URL || got[1] != srv.URL+"/" {
			t.Fatalf("form did not send canonical Origin and origin-only Referer: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("browser did not submit the logout form")
	}
	if _, err := store.GetSession(context.Background(), session.Hash, time.Now().Unix()); err != errMissing {
		t.Fatal("browser logout did not delete its synthetic session")
	}
	if current := command("GET", path+"/url", nil); current != srv.URL+"/?logged_out=1" {
		t.Fatal("browser did not finish on the signed-out page")
	}
	for _, item := range command("GET", path+"/cookie", nil).([]any) {
		if item.(map[string]any)["name"] == cookie.Name {
			t.Fatal("browser retained the demo session cookie")
		}
	}
	if f.tokenCalls.Load() != 0 {
		t.Fatal("local logout made an OAuth token call")
	}
}
