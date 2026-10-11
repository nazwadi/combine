package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

type memoryStore struct {
	mu       sync.Mutex
	attempts map[string]Attempt
	sessions map[string]Session
}

func freshStore() *memoryStore {
	return &memoryStore{attempts: map[string]Attempt{}, sessions: map[string]Session{}}
}
func (s *memoryStore) Ping(context.Context) error { return nil }
func (s *memoryStore) CreateAttempt(_ context.Context, a Attempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts[a.StateHash] = a
	return nil
}
func (s *memoryStore) ConsumeAttempt(_ context.Context, state, browser string, now int64) (Attempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.attempts[state]
	if !ok || a.BrowserHash != browser || a.ExpiresAt <= now {
		return Attempt{}, errMissing
	}
	delete(s.attempts, state)
	return a, nil
}
func (s *memoryStore) CreateSession(_ context.Context, old string, v Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, old)
	s.sessions[v.Hash] = v
	return nil
}
func (s *memoryStore) GetSession(_ context.Context, hash string, now int64) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.sessions[hash]
	if !ok || v.ExpiresAt <= now {
		return Session{}, errMissing
	}
	return v, nil
}
func (s *memoryStore) UpdateToken(_ context.Context, hash string, token []byte, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.sessions[hash]
	if !ok || v.ExpiresAt <= now {
		return errMissing
	}
	v.Token = token
	s.sessions[hash] = v
	return nil
}
func (s *memoryStore) DeleteSession(_ context.Context, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, hash)
	return nil
}
func (s *memoryStore) Prune(_ context.Context, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.sessions {
		if v.ExpiresAt <= now {
			delete(s.sessions, k)
		}
	}
	for k, v := range s.attempts {
		if v.ExpiresAt <= now {
			delete(s.attempts, k)
		}
	}
	return nil
}

type fakeForum struct {
	server        *httptest.Server
	mu            sync.Mutex
	verifier      string
	refreshes     atomic.Int32
	tokenCalls    atomic.Int32
	meStatus      atomic.Int32
	refreshStatus atomic.Int32
	userID        atomic.Int64
}

func makeForum(t *testing.T) *fakeForum {
	t.Helper()
	f := &fakeForum{}
	f.meStatus.Store(200)
	f.userID.Store(42)
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/oauth2/token":
			f.tokenCalls.Add(1)
			if r.Method != "POST" {
				t.Error("token exchange must POST")
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.PostForm.Get("client_id") != "client" || r.PostForm.Get("client_secret") != "secret" {
				t.Error("credentials must use POST body")
			}
			if r.Header.Get("Authorization") != "" {
				t.Error("must not send HTTP Basic client credentials")
			}
			if r.PostForm.Get("grant_type") == "refresh_token" {
				f.refreshes.Add(1)
				if f.refreshStatus.Load() != 0 {
					w.WriteHeader(int(f.refreshStatus.Load()))
					_, _ = io.WriteString(w, `{"errors":[{"code":"invalid_grant","message":"Expired"}]}`)
					return
				}
				time.Sleep(20 * time.Millisecond)
				_, _ = io.WriteString(w, `{"access_token":"new-access","refresh_token":"new-refresh","token_type":"bearer","expires_in":7200}`)
			} else {
				f.mu.Lock()
				f.verifier = r.PostForm.Get("code_verifier")
				f.mu.Unlock()
				if r.PostForm.Get("redirect_uri") != "http://localhost:18080/auth/callback" {
					t.Error("unexpected callback URI")
				}
				_, _ = io.WriteString(w, `{"access_token":"access","refresh_token":"refresh","token_type":"bearer","expires_in":7200}`)
			}
		case "/api/me/":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				t.Error("missing bearer token")
			}
			w.WriteHeader(int(f.meStatus.Load()))
			_, _ = fmt.Fprintf(w, `{"me":{"user_id":%d,"username":"Test Player"}}`, f.userID.Load())
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func makeApp(t *testing.T, forum *fakeForum) (*App, *memoryStore) {
	t.Helper()
	store := freshStore()
	c := Config{ListenAddr: "127.0.0.1:18080", PublicBaseURL: "http://localhost:18080", ForumBaseURL: forum.server.URL, SessionHours: 24}
	s := Secrets{OAuthClientID: "client", OAuthClientSecret: "secret", TokenEncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32))}
	a, err := newApp(c, s, store)
	if err != nil {
		t.Fatal(err)
	}
	return a, store
}

func request(a *App, method, path string, cookies []*http.Cookie, body url.Values) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != nil {
		reader = strings.NewReader(body.Encode())
	}
	r := httptest.NewRequest(method, "http://localhost:18080"+path, reader)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, r)
	return w
}

func startLogin(t *testing.T, a *App) (string, []*http.Cookie, url.Values) {
	t.Helper()
	w := request(a, "GET", "/login?continue=https://evil.invalid", nil, nil)
	if w.Code != 303 {
		t.Fatalf("login status %d", w.Code)
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("scope") != "user:read" {
		t.Fatal("PKCE/scope missing")
	}
	return q.Get("state"), w.Result().Cookies(), q
}

func seedSession(t *testing.T, a *App, expiry time.Time) (*http.Cookie, Session) {
	t.Helper()
	raw := randomValue()
	s := Session{Hash: hashValue(raw), CSRF: randomValue(), UserID: 42, Username: "Test Player", CreatedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix()}
	token := &oauth2.Token{AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "bearer", Expiry: expiry}
	var err error
	s.Token, err = a.encodeToken(token, s.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.store.CreateSession(context.Background(), "", s); err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: sessionCookie, Value: raw}, s
}

func TestLoginCallbackStatePKCEAndReplay(t *testing.T) {
	f := makeForum(t)
	a, store := makeApp(t, f)
	oldCookie, old := seedSession(t, a, time.Now().Add(time.Hour))
	state, cookies, q := startLogin(t, a)
	if w := request(a, "GET", "/auth/callback?code=x&state="+randomValue(), cookies, nil); w.Code != 400 {
		t.Fatal("mismatched state accepted")
	}
	if w := request(a, "GET", "/auth/callback?code=x&state="+state, nil, nil); w.Code != 400 {
		t.Fatal("missing browser binding accepted")
	}
	cookies = append(cookies, oldCookie)
	w := request(a, "GET", "/auth/callback?code=x&state="+state, cookies, nil)
	if w.Code != 303 || w.Header().Get("Location") != "/account" {
		t.Fatalf("callback %d %s", w.Code, w.Header().Get("Location"))
	}
	if _, err := store.GetSession(context.Background(), old.Hash, time.Now().Unix()); err != errMissing {
		t.Fatal("old session was not rotated")
	}
	f.mu.Lock()
	verifier := f.verifier
	f.mu.Unlock()
	if q.Get("code_challenge") != oauth2.S256ChallengeFromVerifier(verifier) {
		t.Fatal("PKCE verifier mismatch")
	}
	newCookies := w.Result().Cookies()
	if len(newCookies) != 1 || newCookies[0].Value == oldCookie.Value || !newCookies[0].HttpOnly || newCookies[0].SameSite != http.SameSiteLaxMode || newCookies[0].Domain != "" {
		t.Fatal("invalid opaque cookie")
	}
	if w := request(a, "GET", "/auth/callback?code=x&state="+state, cookies, nil); w.Code != 400 {
		t.Fatal("callback replay accepted")
	}
	if f.tokenCalls.Load() != 1 {
		t.Fatal("replay reached token endpoint")
	}
	if w := request(a, "GET", "/account", newCookies, nil); w.Code != 200 || !strings.Contains(w.Body.String(), "Test Player") {
		t.Fatal("protected page failed")
	}
}

func TestExpiredAttemptAndDeniedAuthorization(t *testing.T) {
	f := makeForum(t)
	a, store := makeApp(t, f)
	state, cookies, _ := startLogin(t, a)
	w := request(a, "GET", "/auth/callback?error=access_denied&state="+state, cookies, nil)
	if w.Code != 200 || f.tokenCalls.Load() != 0 {
		t.Fatal("denied authorization exchanged token")
	}
	if w := request(a, "GET", "/auth/callback?code=x&state="+state, cookies, nil); w.Code != 400 {
		t.Fatal("denied state not consumed")
	}
	state, cookies, _ = startLogin(t, a)
	store.mu.Lock()
	v := store.attempts[hashValue(state)]
	v.ExpiresAt = time.Now().Unix() - 1
	store.attempts[v.StateHash] = v
	store.mu.Unlock()
	if w := request(a, "GET", "/auth/callback?code=x&state="+state, cookies, nil); w.Code != 400 {
		t.Fatal("expired state accepted")
	}
}

func TestLogoutRequiresPOSTAndCSRF(t *testing.T) {
	f := makeForum(t)
	a, store := makeApp(t, f)
	cookie, s := seedSession(t, a, time.Now().Add(time.Hour))
	cookies := []*http.Cookie{cookie}
	if w := request(a, "GET", "/logout", cookies, nil); w.Code != 405 {
		t.Fatal("GET logout accepted")
	}
	if w := request(a, "POST", "/logout", cookies, url.Values{"csrf": {"wrong"}}); w.Code != 403 {
		t.Fatal("CSRF accepted")
	}
	if _, err := store.GetSession(context.Background(), s.Hash, time.Now().Unix()); err != nil {
		t.Fatal("failed logout deleted session")
	}
	w := request(a, "POST", "/logout", cookies, url.Values{"csrf": {s.CSRF}})
	if w.Code != 303 {
		t.Fatalf("logout status %d", w.Code)
	}
	if _, err := store.GetSession(context.Background(), s.Hash, time.Now().Unix()); err != errMissing {
		t.Fatal("session survived logout")
	}
	if w := request(a, "GET", "/account", cookies, nil); w.Code != 401 {
		t.Fatal("old cookie survived logout")
	}
	if f.tokenCalls.Load() != 0 {
		t.Fatal("local logout made an OAuth request")
	}
}

func TestLogoutOriginAndCSRF(t *testing.T) {
	for _, tc := range []struct {
		name, origin string
		validCSRF    bool
		status       int
	}{
		{"same origin", "http://localhost:18080", true, 303},
		{"null origin", "null", true, 403},
		{"foreign origin", "https://elsewhere.invalid", true, 403},
		{"wrong local port", "http://localhost:18079", true, 403},
		{"same origin bad CSRF", "http://localhost:18080", false, 403},
		{"missing origin bad CSRF", "", false, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := makeForum(t)
			a, store := makeApp(t, f)
			cookie, session := seedSession(t, a, time.Now().Add(time.Hour))
			csrf := "invalid"
			if tc.validCSRF {
				csrf = session.CSRF
			}
			r := httptest.NewRequest("POST", a.config.PublicBaseURL+"/logout", strings.NewReader(url.Values{"csrf": {csrf}}.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			a.handler().ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("logout status %d; want %d", w.Code, tc.status)
			}
			_, err := store.GetSession(context.Background(), session.Hash, time.Now().Unix())
			if tc.status == 303 && err != errMissing {
				t.Fatal("successful logout retained session")
			}
			if tc.status == 403 && err != nil {
				t.Fatal("rejected logout changed session")
			}
			if f.tokenCalls.Load() != 0 {
				t.Fatal("local logout contacted the OAuth provider")
			}
		})
	}
}

func TestConcurrentRefreshPersistsRotatedPair(t *testing.T) {
	f := makeForum(t)
	a, store := makeApp(t, f)
	cookie, s := seedSession(t, a, time.Now().Add(-time.Minute))
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil)
			if w.Code != 200 {
				t.Errorf("account status %d", w.Code)
			}
		}()
	}
	wg.Wait()
	if f.refreshes.Load() != 1 {
		t.Fatalf("refresh count %d", f.refreshes.Load())
	}
	stored, err := store.GetSession(context.Background(), s.Hash, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	token, err := a.decodeToken(stored)
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "new-access" || token.RefreshToken != "new-refresh" {
		t.Fatal("new pair not persisted")
	}
	if strings.Contains(string(stored.Token), "new-access") {
		t.Fatal("token stored unencrypted")
	}
	// A fresh app process uses the persisted pair without another refresh.
	b, _ := makeApp(t, f)
	b.store = store
	if w := request(b, "GET", "/account", []*http.Cookie{cookie}, nil); w.Code != 200 {
		t.Fatal("restart continuity failed")
	}
	if f.refreshes.Load() != 1 {
		t.Fatal("restart refreshed unnecessarily")
	}
}

func TestUpstreamOutageKeepsSessionButRevocationEndsIt(t *testing.T) {
	f := makeForum(t)
	a, store := makeApp(t, f)
	cookie, s := seedSession(t, a, time.Now().Add(time.Hour))
	f.meStatus.Store(503)
	if w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil); w.Code != 503 {
		t.Fatal("outage allowed access")
	}
	if _, err := store.GetSession(context.Background(), s.Hash, time.Now().Unix()); err != nil {
		t.Fatal("outage erased session")
	}
	f.meStatus.Store(403)
	if w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil); w.Code != 403 {
		t.Fatal("forbidden status ignored")
	}
	f.meStatus.Store(401)
	if w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil); w.Code != 401 {
		t.Fatal("revocation allowed access")
	}
	if _, err := store.GetSession(context.Background(), s.Hash, time.Now().Unix()); err != errMissing {
		t.Fatal("revoked session retained")
	}
}

func TestRefreshFailureClassification(t *testing.T) {
	for _, status := range []int{400, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f := makeForum(t)
			a, store := makeApp(t, f)
			cookie, s := seedSession(t, a, time.Now().Add(-time.Minute))
			f.refreshStatus.Store(int32(status))
			w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil)
			_, err := store.GetSession(context.Background(), s.Hash, time.Now().Unix())
			if status == 400 {
				if w.Code != 401 || err != errMissing {
					t.Fatal("invalid refresh grant not cleared")
				}
			}
			// 5xx with an invalid_grant-shaped body remains an outage, not a logout.
			if status == 503 {
				if w.Code != 503 || err != nil {
					t.Fatal("refresh outage cleared session")
				}
			}
		})
	}
}

func TestIdentityMismatchEndsSession(t *testing.T) {
	f := makeForum(t)
	a, _ := makeApp(t, f)
	cookie, _ := seedSession(t, a, time.Now().Add(time.Hour))
	f.userID.Store(99)
	if w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil); w.Code != 401 {
		t.Fatal("identity mismatch accepted")
	}
}

func TestLogoutDuringRefreshCannotResurrectSession(t *testing.T) {
	f := makeForum(t)
	a, store := makeApp(t, f)
	cookie, session := seedSession(t, a, time.Now().Add(-time.Minute))
	done := make(chan struct{})
	go func() {
		defer close(done)
		request(a, "GET", "/account", []*http.Cookie{cookie}, nil)
	}()
	deadline := time.Now().Add(time.Second)
	for f.refreshes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.refreshes.Load() == 0 {
		t.Fatal("refresh never started")
	}
	w := request(a, "POST", "/logout", []*http.Cookie{cookie}, url.Values{"csrf": {session.CSRF}})
	<-done
	if w.Code != 303 {
		t.Fatalf("logout status %d", w.Code)
	}
	if _, err := store.GetSession(context.Background(), session.Hash, time.Now().Unix()); err != errMissing {
		t.Fatal("refresh resurrected a logged-out session")
	}
}

func TestEncryptionBindingAndConfiguration(t *testing.T) {
	f := makeForum(t)
	a, _ := makeApp(t, f)
	_, s := seedSession(t, a, time.Now().Add(time.Hour))
	s.Hash = hashValue("different session")
	if _, err := a.decodeToken(s); err == nil {
		t.Fatal("ciphertext transplanted between sessions")
	}
	a.configured = false
	if w := request(a, "GET", "/login", nil, nil); w.Code != 503 || f.tokenCalls.Load() != 0 {
		t.Fatal("unconfigured login enabled")
	}
	r := httptest.NewRequest("GET", "http://evil.invalid/", nil)
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, r)
	if w.Code != 421 {
		t.Fatal("untrusted Host accepted")
	}
	w = request(a, "GET", "/", nil, nil)
	if !strings.Contains(w.Body.String(), "Sign-in not configured") || w.Header().Get("Referrer-Policy") != "strict-origin" {
		t.Fatal("guest preview or privacy headers missing")
	}
}

func TestNoSecretsRendered(t *testing.T) {
	f := makeForum(t)
	a, _ := makeApp(t, f)
	cookie, _ := seedSession(t, a, time.Now().Add(time.Hour))
	w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil)
	for _, secret := range []string{"old-access", "old-refresh", "client_secret", cookie.Value} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("secret rendered")
		}
	}
	if json.Valid(w.Body.Bytes()) {
		t.Fatal("expected rendered HTML")
	}
}

// Exercise the actual disk store with a fake provider. A workstation restart
// must preserve a pending login, the rotated token pair and a completed logout.
func TestOAuthJSONStoreRestart(t *testing.T) {
	f := makeForum(t)
	dir := t.TempDir()
	var disk *JSONStore
	open := func() *App {
		t.Helper()
		if disk != nil {
			if err := disk.Close(); err != nil {
				t.Fatal(err)
			}
		}
		var err error
		disk, err = openStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := makeApp(t, f)
		a.store = disk
		return a
	}
	t.Cleanup(func() {
		if disk != nil {
			_ = disk.Close()
		}
	})
	a := open()
	state, cookies, _ := startLogin(t, a)
	a = open()
	w := request(a, "GET", "/auth/callback?code=x&state="+state, cookies, nil)
	if w.Code != 303 {
		t.Fatalf("callback after restart: %d", w.Code)
	}
	cookies = w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookie {
		t.Fatal("missing session cookie")
	}
	hash := hashValue(cookies[0].Value)
	s, err := disk.GetSession(context.Background(), hash, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	token, err := a.decodeToken(s)
	if err != nil {
		t.Fatal(err)
	}
	token.Expiry = time.Now().Add(-time.Minute)
	encoded, err := a.encodeToken(token, hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := disk.UpdateToken(context.Background(), hash, encoded, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	a = open()
	if w := request(a, "GET", "/account", cookies, nil); w.Code != 200 {
		t.Fatalf("identity after restart/refresh: %d", w.Code)
	}
	a = open()
	if w := request(a, "GET", "/account", cookies, nil); w.Code != 200 || f.refreshes.Load() != 1 {
		t.Fatal("rotated token pair did not persist")
	}
	contents, err := os.ReadFile(filepath.Join(dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{cookies[0].Value, "new-access", "new-refresh"} {
		if strings.Contains(string(contents), secret) {
			t.Fatal("raw credential written to disk")
		}
	}
	if w := request(a, "POST", "/logout", cookies, url.Values{"csrf": {s.CSRF}}); w.Code != 303 {
		t.Fatalf("logout: %d", w.Code)
	}
	a = open()
	if w := request(a, "GET", "/account", cookies, nil); w.Code != 401 {
		t.Fatal("logout did not survive restart")
	}
}
