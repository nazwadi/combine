package main

import (
	"context"
	"crypto/cipher"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

//go:embed templates/*.html assets/*
var webFiles embed.FS

const sessionCookie = "go_demo_session"
const loginCookie = "go_demo_login"

var errLoginRequired = errors.New("login required")
var errAccessDenied = errors.New("access denied")
var errUpstream = errors.New("forum temporarily unavailable")

type App struct {
	config Config
	store  Store
	aead   cipher.AEAD
	oauth  oauth2.Config
	client *http.Client
	views  *template.Template
	// One application process is supported. A bounded set of striped mutexes
	// serializes refresh, logout and session replacement without unbounded keys.
	sessionLocks [128]sync.Mutex
	configured   bool
}

type View struct {
	Title, Message, ForumURL, CSRF, Username string
	UserID                                   int64
	Configured, SignedIn, Account            bool
}

func newApp(c Config, s Secrets, store Store) (*App, error) {
	aead, err := newCipher(s.TokenEncryptionKey)
	if err != nil {
		return nil, err
	}
	views, err := template.ParseFS(webFiles, "templates/page.html")
	if err != nil {
		return nil, err
	}
	return &App{
		config: c, store: store, aead: aead, views: views,
		configured: s.OAuthClientID != "" && s.OAuthClientSecret != "",
		client:     &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		oauth:      oauth2.Config{ClientID: s.OAuthClientID, ClientSecret: s.OAuthClientSecret, RedirectURL: c.PublicBaseURL + "/auth/callback", Scopes: []string{"user:read"}, Endpoint: oauth2.Endpoint{AuthURL: c.ForumBaseURL + "/oauth2/authorize", TokenURL: c.ForumBaseURL + "/api/oauth2/token", AuthStyle: oauth2.AuthStyleInParams}},
	}, nil
}

func (a *App) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.home)
	mux.HandleFunc("GET /login", a.login)
	mux.HandleFunc("GET /auth/callback", a.callback)
	mux.HandleFunc("GET /account", a.account)
	mux.HandleFunc("POST /logout", a.logout)
	assets, _ := fs.Sub(webFiles, "assets")
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assets))))
	public, _ := url.Parse(a.config.PublicBaseURL)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		// Suppress callback paths/query strings without making form POST origins
		// opaque (no-referrer sends Origin: null and breaks the logout check).
		w.Header().Set("Referrer-Policy", "strict-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		// Proxy headers are deliberately unused. Public URLs are fixed config;
		// restricting Host also prevents DNS rebinding of the loopback prototype.
		if !strings.EqualFold(r.Host, public.Host) {
			http.Error(w, "Unexpected host", http.StatusMisdirectedRequest)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (a *App) render(w http.ResponseWriter, status int, v View) {
	v.Configured, v.ForumURL = a.configured, a.config.ForumBaseURL
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	// Templates are embedded and pre-parsed; clients may disconnect mid-render.
	_ = a.views.ExecuteTemplate(w, "page.html", v)
}

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil || len(c.Value) != 43 {
		return ""
	}
	return c.Value
}

func (a *App) setCookie(w http.ResponseWriter, name, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Expires: expires, MaxAge: int(time.Until(expires).Seconds()), Secure: a.config.CookieSecure, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}
func (a *App) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Path: "/", Expires: time.Unix(1, 0), MaxAge: -1, Secure: a.config.CookieSecure, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}
func (a *App) sessionHash(r *http.Request) string {
	if value := cookieValue(r, sessionCookie); value != "" {
		return hashValue(value)
	}
	return ""
}
func (a *App) lockSession(hash string) func() {
	var index byte
	for i := 0; i < len(hash); i++ {
		index ^= hash[i]
	}
	m := &a.sessionLocks[int(index)%len(a.sessionLocks)]
	m.Lock()
	return m.Unlock
}

func (a *App) home(w http.ResponseWriter, r *http.Request) {
	v := View{Title: "Go OAuth demo"}
	if r.URL.Query().Get("logged_out") == "1" {
		v.Message = "You’re logged out of this demo. Your forum login is unchanged."
	}
	if hash := a.sessionHash(r); hash != "" {
		s, err := a.store.GetSession(r.Context(), hash, time.Now().Unix())
		if err == nil {
			v.SignedIn, v.Username, v.UserID, v.CSRF = true, s.Username, s.UserID, s.CSRF
		} else if errors.Is(err, errMissing) {
			a.clearCookie(w, sessionCookie)
		} else {
			a.render(w, 503, View{Title: "The demo is temporarily unavailable", Message: "Please try again shortly."})
			return
		}
	}
	a.render(w, 200, v)
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if !a.configured {
		a.render(w, 503, View{Title: "Sign-in isn’t configured yet", Message: "Set client_id and client_secret in config.json, then restart the demo."})
		return
	}
	state, browser, verifier := randomValue(), cookieValue(r, loginCookie), oauth2.GenerateVerifier()
	if browser == "" {
		browser = randomValue()
	}
	expires := time.Now().Add(10 * time.Minute)
	attempt := Attempt{StateHash: hashValue(state), BrowserHash: hashValue(browser), ReturnPath: safeReturn(r.URL.Query().Get("continue")), ExpiresAt: expires.Unix()}
	attempt.Verifier = seal(a.aead, []byte(verifier), "attempt:"+attempt.StateHash)
	if err := a.store.CreateAttempt(r.Context(), attempt); err != nil {
		a.render(w, 503, View{Title: "Unable to start sign-in", Message: "Please try again shortly."})
		return
	}
	a.setCookie(w, loginCookie, browser, expires)
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusSeeOther)
}

func (a *App) oauthContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, a.client)
}

func (a *App) callback(w http.ResponseWriter, r *http.Request) {
	if !a.configured {
		a.render(w, 503, View{Title: "Sign-in isn’t configured yet"})
		return
	}
	state, browser := r.URL.Query().Get("state"), cookieValue(r, loginCookie)
	if len(state) != 43 || browser == "" {
		a.badAttempt(w)
		return
	}
	attempt, err := a.store.ConsumeAttempt(r.Context(), hashValue(state), hashValue(browser), time.Now().Unix())
	if errors.Is(err, errMissing) {
		a.badAttempt(w)
		return
	}
	if err != nil {
		a.render(w, 503, View{Title: "Unable to complete sign-in", Message: "Please try again shortly."})
		return
	}
	// Every valid callback consumes its state, including denial and failure.
	if r.URL.Query().Get("error") != "" {
		a.render(w, 200, View{Title: "Sign-in wasn’t completed", Message: "You can return home or try signing in again."})
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" || len(code) > 4096 {
		a.badAttempt(w)
		return
	}
	verifier, err := unseal(a.aead, attempt.Verifier, "attempt:"+attempt.StateHash)
	if err != nil {
		a.badAttempt(w)
		return
	}
	token, err := a.oauth.Exchange(a.oauthContext(r.Context()), code, oauth2.VerifierOption(string(verifier)))
	if err != nil || token == nil || token.AccessToken == "" || token.RefreshToken == "" || !strings.EqualFold(token.TokenType, "bearer") || token.Expiry.IsZero() {
		a.render(w, 502, View{Title: "Unable to complete sign-in", Message: "The forum could not complete this sign-in. Please start again."})
		return
	}
	identity, err := a.fetchIdentity(r.Context(), token)
	if err != nil {
		a.render(w, 502, View{Title: "Unable to verify your account", Message: "The forum did not confirm your identity. Please try signing in again."})
		return
	}
	// Future policy API: require eligibility here before creating a session,
	// and in authenticated before returning success for each protected request.
	cookie := randomValue()
	now := time.Now()
	s := Session{Hash: hashValue(cookie), CSRF: randomValue(), UserID: identity.UserID, Username: identity.Username, CreatedAt: now.Unix(), ExpiresAt: now.Add(time.Duration(a.config.SessionHours) * time.Hour).Unix()}
	s.Token, err = a.encodeToken(token, s.Hash)
	if err != nil {
		a.render(w, 500, View{Title: "Unable to complete sign-in"})
		return
	}
	oldHash := a.sessionHash(r)
	unlock := a.lockSession(oldHash)
	defer unlock()
	if err := a.store.CreateSession(r.Context(), oldHash, s); err != nil {
		a.render(w, 503, View{Title: "Unable to save your login", Message: "Please try signing in again."})
		return
	}
	a.setCookie(w, sessionCookie, cookie, time.Unix(s.ExpiresAt, 0))
	http.Redirect(w, r, safeReturn(attempt.ReturnPath), http.StatusSeeOther)
}

func (a *App) badAttempt(w http.ResponseWriter) {
	a.render(w, 400, View{Title: "That sign-in has expired", Message: "Please start a new sign-in from the demo. Login links can only be used once, in the browser that started them."})
}

func (a *App) encodeToken(token *oauth2.Token, hash string) ([]byte, error) {
	value, err := json.Marshal(token)
	if err != nil {
		return nil, err
	}
	return seal(a.aead, value, "session:"+hash), nil
}
func (a *App) decodeToken(s Session) (*oauth2.Token, error) {
	value, err := unseal(a.aead, s.Token, "session:"+s.Hash)
	if err != nil {
		return nil, err
	}
	var token oauth2.Token
	if err := json.Unmarshal(value, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func permanentTokenError(err error) bool {
	var re *oauth2.RetrieveError
	if !errors.As(err, &re) {
		return false
	}
	if re.Response == nil || re.Response.StatusCode < 400 || re.Response.StatusCode >= 500 {
		return false
	}
	if re.ErrorCode == "invalid_grant" {
		return true
	}
	// XenForo returns its native errors array, not OAuth's top-level error.
	var payload struct {
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if json.Unmarshal(re.Body, &payload) == nil {
		for _, e := range payload.Errors {
			if e.Code == "invalid_grant" {
				return true
			}
		}
	}
	return false
}

func (a *App) authenticated(ctx context.Context, hash string) (Session, *oauth2.Token, error) {
	if hash == "" {
		return Session{}, nil, errLoginRequired
	}
	unlock := a.lockSession(hash)
	defer unlock()
	s, err := a.store.GetSession(ctx, hash, time.Now().Unix())
	if errors.Is(err, errMissing) {
		return s, nil, errLoginRequired
	}
	if err != nil {
		return s, nil, errUpstream
	}
	token, err := a.decodeToken(s)
	if err != nil {
		return s, nil, errUpstream
	}
	if !token.Valid() {
		// Refresh rotates both tokens at XenForo. Keep this operation alive long
		// enough to persist the replacement even if its browser request cancels.
		refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
		defer cancel()
		fresh, err := a.oauth.TokenSource(a.oauthContext(refreshCtx), token).Token()
		if err != nil {
			if permanentTokenError(err) {
				_ = a.store.DeleteSession(refreshCtx, hash)
				return s, nil, errLoginRequired
			}
			return s, nil, errUpstream
		}
		if fresh.AccessToken == "" || fresh.RefreshToken == "" || !strings.EqualFold(fresh.TokenType, "bearer") || fresh.Expiry.IsZero() {
			return s, nil, errUpstream
		}
		encoded, err := a.encodeToken(fresh, hash)
		if err != nil {
			return s, nil, errUpstream
		}
		if err := a.store.UpdateToken(refreshCtx, hash, encoded, time.Now().Unix()); err != nil {
			return s, nil, errUpstream
		}
		s.Token, token = encoded, fresh
	}
	identity, err := a.fetchIdentity(ctx, token)
	if errors.Is(err, errLoginRequired) {
		_ = a.store.DeleteSession(context.WithoutCancel(ctx), hash)
		return s, nil, errLoginRequired
	}
	if err != nil {
		return s, token, err
	}
	if identity.UserID != s.UserID {
		_ = a.store.DeleteSession(context.WithoutCancel(ctx), hash)
		return s, nil, errLoginRequired
	}
	// Add the future Shadowrest access-policy call here, before returning success.
	// /api/me/ confirms identity only; it is not an SMS enrollment/access check.
	s.Username = identity.Username
	return s, token, nil
}

func (a *App) account(w http.ResponseWriter, r *http.Request) {
	s, _, err := a.authenticated(r.Context(), a.sessionHash(r))
	if errors.Is(err, errLoginRequired) {
		a.clearCookie(w, sessionCookie)
		a.render(w, 401, View{Title: "Sign in to the demo", Message: "Your demo session has ended or forum authorization was revoked. Sign in again to continue."})
		return
	}
	if errors.Is(err, errAccessDenied) {
		a.render(w, 403, View{Title: "Forum access is unavailable", Message: "The forum is currently denying access to this account.", SignedIn: true, CSRF: s.CSRF})
		return
	}
	if err != nil {
		a.render(w, 503, View{Title: "Unable to check your account", Message: "The forum is temporarily unavailable. Your demo login has been kept; try this page again shortly.", SignedIn: s.Hash != "", CSRF: s.CSRF})
		return
	}
	a.render(w, 200, View{Title: "Signed in", Account: true, SignedIn: true, CSRF: s.CSRF, UserID: s.UserID, Username: s.Username})
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && origin != a.config.PublicBaseURL {
		http.Error(w, "Invalid request origin", 403)
		return
	}
	hash := a.sessionHash(r)
	if hash == "" {
		http.Error(w, "No active demo session", 403)
		return
	}
	unlock := a.lockSession(hash)
	defer unlock()
	s, err := a.store.GetSession(r.Context(), hash, time.Now().Unix())
	if errors.Is(err, errMissing) {
		a.clearCookie(w, sessionCookie)
		http.Redirect(w, r, "/?logged_out=1", 303)
		return
	}
	if err != nil {
		a.render(w, 503, View{Title: "Unable to log out", Message: "Please try again shortly."})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(s.CSRF)) != 1 {
		http.Error(w, "Invalid form token", 403)
		return
	}
	if err := a.store.DeleteSession(r.Context(), hash); err != nil {
		a.render(w, 503, View{Title: "Unable to log out", Message: "Please try again shortly."})
		return
	}
	a.clearCookie(w, sessionCookie)
	a.clearCookie(w, loginCookie)
	// Local logout intentionally leaves the forum cookie and OAuth grant alone.
	// No network call is required to reliably end this demo session.
	http.Redirect(w, r, "/?logged_out=1", http.StatusSeeOther)
}
