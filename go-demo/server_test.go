package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	accessStatus  atomic.Int32
	accessCalls   atomic.Int32
	accessBody    atomic.Value
	rejectOld     atomic.Bool
	refreshStatus atomic.Int32
	userID        atomic.Int64
}

func makeForum(t *testing.T) *fakeForum {
	t.Helper()
	f := &fakeForum{}
	f.accessStatus.Store(200)
	f.accessBody.Store("")
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
		case "/api/shadowrest/access/":
			f.accessCalls.Add(1)
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				t.Error("missing bearer token")
			}
			if r.Method != http.MethodGet {
				t.Error("access check must GET")
			}
			if r.Header.Get("XF-Api-Key") != "" || r.Header.Get("XF-Api-User") != "" || r.URL.RawQuery != "" {
				t.Error("OAuth access check must not send a machine key, identity override or permission bypass")
			}
			if f.rejectOld.Load() && r.Header.Get("Authorization") == "Bearer old-access" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(int(f.accessStatus.Load()))
			if body := f.accessBody.Load().(string); body != "" {
				_, _ = io.WriteString(w, body)
				return
			}
			_, _ = fmt.Fprintf(w, `{"allowed":true,"user_id":%d,"username":"Test Player"}`, f.userID.Load())
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
	if q.Get("code_challenge_method") != "S256" || q.Get("scope") != "shadowrest_access:read" {
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
	f.accessStatus.Store(503)
	if w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil); w.Code != 503 {
		t.Fatal("outage allowed access")
	}
	if _, err := store.GetSession(context.Background(), s.Hash, time.Now().Unix()); err != nil {
		t.Fatal("outage erased session")
	}
	f.accessStatus.Store(403)
	if w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil); w.Code != 403 {
		t.Fatal("forbidden status ignored")
	}
	f.accessStatus.Store(401)
	if w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil); w.Code != 401 {
		t.Fatal("revocation allowed access")
	}
	if _, err := store.GetSession(context.Background(), s.Hash, time.Now().Unix()); err != errMissing {
		t.Fatal("revoked session retained")
	}
}

func TestAccessDenialsPreserveSessionAndExplainCallback(t *testing.T) {
	for _, code := range []string{
		"shadowrest_account_not_valid", "shadowrest_sms_not_enrolled",
		"shadowrest_oauth_client_inactive", "shadowrest_api_bypass_not_allowed",
		"you_have_been_banned", "your_account_has_been_rejected", "your_account_has_been_disabled",
		"your_account_is_currently_security_locked", "do_not_have_permission", "missing_scope",
		"shadowrest_authentication_type_not_allowed", "login_required", "user_id_not_valid",
		"user_id_not_allowed", "api_key_inactive", "unknown_future_denial",
	} {
		t.Run(code, func(t *testing.T) {
			f := makeForum(t)
			a, store := makeApp(t, f)
			cookie, session := seedSession(t, a, time.Now().Add(time.Hour))
			f.accessStatus.Store(403)
			params := any([]string{}) // Native XenForo may encode empty params as [].
			if code == "shadowrest_account_not_valid" {
				params = map[string]string{"user_state": "email_confirm"}
			}
			body, _ := json.Marshal(map[string]any{"errors": []any{map[string]any{
				"code": code, "message": "Complete the forum account requirement.", "params": params,
			}}})
			f.accessBody.Store(string(body))
			_, err := a.fetchAccess(context.Background(), &oauth2.Token{AccessToken: "fixture"})
			var denial *AccessDenial
			if !errors.As(err, &denial) || denial.Code != code {
				t.Fatalf("structured denial lost: %v", err)
			}
			if code == "shadowrest_account_not_valid" && denial.UserState != "email_confirm" {
				t.Fatal("account-state detail lost")
			}
			wantMessage := "Complete the forum account requirement."
			if code == "missing_scope" {
				wantMessage = "log out of the demo and sign in again"
			}
			w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil)
			if w.Code != 403 || !strings.Contains(w.Body.String(), wantMessage) || w.Header().Get("Location") != "" {
				t.Fatal("policy denial was hidden or redirected to login")
			}
			if _, err := store.GetSession(context.Background(), session.Hash, time.Now().Unix()); err != nil {
				t.Fatal("policy denial deleted the local session")
			}
			if f.refreshes.Load() != 0 {
				t.Fatal("policy denial triggered a refresh")
			}
			state, cookies, _ := startLogin(t, a)
			w = request(a, "GET", "/auth/callback?code=x&state="+state, cookies, nil)
			if w.Code != 403 || !strings.Contains(w.Body.String(), wantMessage) || len(w.Result().Cookies()) != 0 {
				t.Fatal("callback denial created a session or became an upstream failure")
			}
			if len(store.sessions) != 1 {
				t.Fatal("denied callback changed the existing session set")
			}
			// The same local session becomes usable after the forum policy allows it.
			f.accessStatus.Store(200)
			f.accessBody.Store("")
			if w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil); w.Code != 200 {
				t.Fatal("policy recovery required an unnecessary new login")
			}
		})
	}
}

func TestAccessDenialTextIsEscapedAndBounded(t *testing.T) {
	f := makeForum(t)
	a, _ := makeApp(t, f)
	cookie, _ := seedSession(t, a, time.Now().Add(time.Hour))
	f.accessStatus.Store(403)
	message := "<script>alert('no')</script>\n" + strings.Repeat("x", 600)
	body, _ := json.Marshal(map[string]any{"errors": []any{map[string]any{"code": "no_permission", "message": message, "params": []string{}}}})
	f.accessBody.Store(string(body))
	w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil)
	if w.Code != 403 || strings.Contains(w.Body.String(), "<script>") || !strings.Contains(w.Body.String(), "&lt;script&gt;") || strings.Contains(w.Body.String(), strings.Repeat("x", 501)) {
		t.Fatal("upstream denial text was not safely rendered")
	}
	f.accessBody.Store("not JSON")
	w = request(a, "GET", "/account", []*http.Cookie{cookie}, nil)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "currently denying access") {
		t.Fatal("malformed 403 lost the generic access-denied fallback")
	}
}

func TestAccessRequiresExplicitValidAllowance(t *testing.T) {
	for name, body := range map[string]string{
		"missing allowance": `{"user_id":42,"username":"Player"}`,
		"false allowance":   `{"allowed":false,"user_id":42,"username":"Player"}`,
		"null allowance":    `{"allowed":null,"user_id":42,"username":"Player"}`,
		"string allowance":  `{"allowed":"true","user_id":42,"username":"Player"}`,
		"missing ID":        `{"allowed":true,"username":"Player"}`,
		"invalid ID":        `{"allowed":true,"user_id":0,"username":"Player"}`,
		"blank username":    `{"allowed":true,"user_id":42,"username":" "}`,
		"trailing data":     `{"allowed":true,"user_id":42,"username":"Player"} {}`,
		"oversized":         `{"allowed":true,"user_id":42,"username":"Player","extra":"` + strings.Repeat("x", 1<<20) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := makeForum(t)
			a, store := makeApp(t, f)
			cookie, session := seedSession(t, a, time.Now().Add(time.Hour))
			f.accessBody.Store(body)
			if w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil); w.Code != 503 {
				t.Fatalf("malformed allowance returned %d", w.Code)
			}
			if _, err := store.GetSession(context.Background(), session.Hash, time.Now().Unix()); err != nil {
				t.Fatal("bad upstream payload erased the local session")
			}
			state, cookies, _ := startLogin(t, a)
			if w := request(a, "GET", "/auth/callback?code=x&state="+state, cookies, nil); w.Code != 502 || len(w.Result().Cookies()) != 0 {
				t.Fatal("malformed callback allowance created a session")
			}
		})
	}
}

func TestAccess401RefreshesOnceAndPersistsRotatedPair(t *testing.T) {
	f := makeForum(t)
	a, store := makeApp(t, f)
	cookie, session := seedSession(t, a, time.Now().Add(time.Hour))
	f.rejectOld.Store(true)
	if w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil); w.Code != 200 {
		t.Fatalf("401 recovery returned %d", w.Code)
	}
	if f.refreshes.Load() != 1 || f.accessCalls.Load() != 2 {
		t.Fatal("401 recovery did not refresh and retry exactly once")
	}
	stored, err := store.GetSession(context.Background(), session.Hash, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	token, err := a.decodeToken(stored)
	if err != nil || token.AccessToken != "new-access" || token.RefreshToken != "new-refresh" {
		t.Fatal("401 recovery did not persist the rotated pair")
	}
	if w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil); w.Code != 200 || f.refreshes.Load() != 1 {
		t.Fatal("later request did not reuse the persisted token")
	}
}

func TestPersistentAccess401EndsSessionWithoutRefreshLoop(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprint(expired), func(t *testing.T) {
			f := makeForum(t)
			a, store := makeApp(t, f)
			expiry := time.Now().Add(time.Hour)
			wantAccessCalls := int32(2)
			if expired {
				expiry = time.Now().Add(-time.Minute)
				wantAccessCalls = 1
			}
			cookie, session := seedSession(t, a, expiry)
			f.accessStatus.Store(401)
			if w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil); w.Code != 401 {
				t.Fatal("persistent 401 allowed access")
			}
			if f.refreshes.Load() != 1 || f.accessCalls.Load() != wantAccessCalls {
				t.Fatal("request exceeded one refresh or retried unexpectedly")
			}
			if _, err := store.GetSession(context.Background(), session.Hash, time.Now().Unix()); err != errMissing {
				t.Fatal("invalid authorization retained the session")
			}
		})
	}
}

func TestAccess401RefreshFailureClassification(t *testing.T) {
	for _, status := range []int{400, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f := makeForum(t)
			a, store := makeApp(t, f)
			cookie, session := seedSession(t, a, time.Now().Add(time.Hour))
			f.accessStatus.Store(401)
			f.refreshStatus.Store(int32(status))
			w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil)
			_, err := store.GetSession(context.Background(), session.Hash, time.Now().Unix())
			if status == 400 && (w.Code != 401 || err != errMissing) {
				t.Fatal("invalid refresh after 401 did not end the session")
			}
			if status == 503 && (w.Code != 503 || err != nil) {
				t.Fatal("temporary refresh failure after 401 did not preserve the session")
			}
			if f.refreshes.Load() != 1 || f.accessCalls.Load() != 1 {
				t.Fatal("failed refresh retried the access endpoint")
			}
		})
	}
}

func TestAccessNetworkFailureKeepsSession(t *testing.T) {
	f := makeForum(t)
	a, store := makeApp(t, f)
	cookie, session := seedSession(t, a, time.Now().Add(time.Hour))
	f.server.Close()
	if w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil); w.Code != 503 {
		t.Fatal("network failure allowed access")
	}
	if _, err := store.GetSession(context.Background(), session.Hash, time.Now().Unix()); err != nil {
		t.Fatal("network failure erased the session")
	}
}

func TestAccessUnavailableKeepsSession(t *testing.T) {
	f := makeForum(t)
	a, store := makeApp(t, f)
	cookie, session := seedSession(t, a, time.Now().Add(time.Hour))
	f.accessStatus.Store(http.StatusServiceUnavailable)
	f.accessBody.Store(`{"errors":[{"code":"shadowrest_access_unavailable","message":"The access service is temporarily unavailable.","params":[]}]}`)
	w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil)
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "allowed Shadowrest access") {
		t.Fatal("unavailable add-on allowed access")
	}
	if w.Header().Get("Location") != "" || len(w.Result().Cookies()) != 0 {
		t.Fatal("unavailable add-on restarted login or changed its cookie")
	}
	if _, err := store.GetSession(context.Background(), session.Hash, time.Now().Unix()); err != nil {
		t.Fatal("unavailable add-on erased the local session")
	}
	if f.accessCalls.Load() != 1 || f.tokenCalls.Load() != 0 {
		t.Fatal("unavailable add-on triggered a retry or token refresh")
	}
	f.accessStatus.Store(http.StatusOK)
	f.accessBody.Store("")
	if w := request(a, "GET", "/account", []*http.Cookie{cookie}, nil); w.Code != http.StatusOK {
		t.Fatal("restored access service did not accept the retained session")
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
