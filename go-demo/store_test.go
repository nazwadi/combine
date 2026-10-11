package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testJSONStore(t *testing.T) (*JSONStore, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	s, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

func TestJSONStorePersistsAndProtectsFiles(t *testing.T) {
	s, dir := testJSONStore(t)
	ctx, now := context.Background(), time.Now().Unix()
	if _, err := os.Stat(filepath.Join(dir, "store.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("empty store should not create a snapshot")
	}
	a := Attempt{StateHash: "state", BrowserHash: "browser", Verifier: []byte("encrypted-verifier"), ExpiresAt: now + 100}
	v := Session{Hash: "session", CSRF: "csrf", UserID: 42, Username: "Example", Token: []byte("encrypted-token"), CreatedAt: now, ExpiresAt: now + 100}
	if err := s.CreateAttempt(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, "", v); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{dir: 0700, filepath.Join(dir, "store.lock"): 0600, filepath.Join(dir, "store.json"): 0600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("%s mode %o, want %o", filepath.Base(path), got, want)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.GetSession(ctx, v.Hash, now)
	if err != nil || got.UserID != 42 || string(got.Token) != "encrypted-token" {
		t.Fatalf("session did not survive reopen: %v", err)
	}
	if _, err := s.ConsumeAttempt(ctx, a.StateHash, "wrong-browser", now); !errors.Is(err, errMissing) {
		t.Fatal("wrong browser accepted")
	}
	if _, err := s.ConsumeAttempt(ctx, a.StateHash, a.BrowserHash, now); err != nil {
		t.Fatalf("valid browser could not consume preserved attempt: %v", err)
	}
	if err := s.UpdateToken(ctx, v.Hash, []byte("refreshed-token"), now); err != nil {
		t.Fatal(err)
	}
	newSession := v
	newSession.Hash = "replacement"
	if err := s.CreateSession(ctx, v.Hash, newSession); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, v.Hash, now); !errors.Is(err, errMissing) {
		t.Fatal("session rotation kept old session")
	}
	if err := s.DeleteSession(ctx, newSession.Hash); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.GetSession(ctx, newSession.Hash, now); !errors.Is(err, errMissing) {
		t.Fatal("logout was not persisted")
	}
	if _, err := s.ConsumeAttempt(ctx, a.StateHash, a.BrowserHash, now); !errors.Is(err, errMissing) {
		t.Fatal("consumed attempt reappeared after reopen")
	}
}

func TestJSONStoreConcurrentSingleUseAttempt(t *testing.T) {
	s, _ := testJSONStore(t)
	ctx, now := context.Background(), time.Now().Unix()
	if err := s.CreateAttempt(ctx, Attempt{StateHash: "state", BrowserHash: "browser", ExpiresAt: now + 100}); err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			_, err := s.ConsumeAttempt(ctx, "state", "browser", now)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, errMissing) {
				t.Errorf("unexpected consume error: %v", err)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("%d concurrent requests consumed one attempt", successes.Load())
	}
}

func TestJSONStoreLockAndCorruption(t *testing.T) {
	s, dir := testJSONStore(t)
	if second, err := openStore(dir); err == nil {
		second.Close()
		t.Fatal("second process/store accepted the same directory")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, broken := range []string{
		"not json", "{}", `{"version":2,"attempts":{},"sessions":{}}`,
		`{"version":1,"attempts":{},"sessions":{"wrong":{"Hash":"other"}}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, "store.json"), []byte(broken), 0600); err != nil {
			t.Fatal(err)
		}
		if opened, err := openStore(dir); err == nil {
			opened.Close()
			t.Fatal("invalid store accepted")
		}
		contents, err := os.ReadFile(filepath.Join(dir, "store.json"))
		if err != nil || string(contents) != broken {
			t.Fatal("invalid store was replaced")
		}
	}
}

func TestJSONStoreFailedSaveDoesNotConsumeAttempt(t *testing.T) {
	s, dir := testJSONStore(t)
	ctx, now := context.Background(), time.Now().Unix()
	if err := s.CreateAttempt(ctx, Attempt{StateHash: "state", BrowserHash: "browser", ExpiresAt: now + 100}); err != nil {
		t.Fatal(err)
	}
	// Force a rename failure even when tests run as root; permissions would not.
	path, saved := filepath.Join(dir, "store.json"), filepath.Join(dir, "saved.json")
	if err := os.Rename(path, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeAttempt(ctx, "state", "browser", now); err == nil {
		t.Fatal("consume succeeded despite failed persistence")
	}
	temps, err := filepath.Glob(filepath.Join(dir, ".store-*.tmp"))
	if err != nil || len(temps) != 0 {
		t.Fatal("failed write left temporary files")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeAttempt(ctx, "state", "browser", now); err != nil {
		t.Fatalf("failed write consumed in-memory attempt: %v", err)
	}
}

func TestJSONStoreCopiesTokensAndHonorsExpiry(t *testing.T) {
	s, dir := testJSONStore(t)
	ctx, now := context.Background(), time.Now().Unix()
	token := []byte("original")
	if err := s.CreateSession(ctx, "", Session{Hash: "session", Token: token, ExpiresAt: now + 100}); err != nil {
		t.Fatal(err)
	}
	token[0] = 'X'
	v, err := s.GetSession(ctx, "session", now)
	if err != nil || string(v.Token) != "original" {
		t.Fatal("caller's token buffer mutated the store")
	}
	v.Token[0] = 'X'
	v, err = s.GetSession(ctx, "session", now)
	if err != nil || string(v.Token) != "original" {
		t.Fatal("returned token buffer mutated the store")
	}
	if _, err := s.GetSession(ctx, "session", now+100); !errors.Is(err, errMissing) {
		t.Fatal("expired session accepted")
	}
	if err := s.UpdateToken(ctx, "session", []byte("refreshed"), now+100); !errors.Is(err, errMissing) {
		t.Fatal("expired session refreshed")
	}
	if err := s.Prune(ctx, now+100); err != nil {
		t.Fatal(err)
	}
	if len(s.data.Sessions) != 0 {
		t.Fatal("prune kept expired session")
	}
	// An expired record from a former process is removed on startup too.
	if err := s.CreateAttempt(ctx, Attempt{StateHash: "expired", ExpiresAt: now - 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(s.data.Attempts) != 0 {
		t.Fatal("startup kept expired attempt")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.DeleteSession(cancelled, "missing"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled operation accepted")
	}
}
