package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

var errMissing = errors.New("record missing or expired")

type Attempt struct {
	StateHash, BrowserHash, ReturnPath string
	Verifier                           []byte
	ExpiresAt                          int64
}

type Session struct {
	Hash, CSRF, Username string
	UserID               int64
	Token                []byte
	CreatedAt, ExpiresAt int64
}

type Store interface {
	Ping(context.Context) error
	CreateAttempt(context.Context, Attempt) error
	ConsumeAttempt(context.Context, string, string, int64) (Attempt, error)
	CreateSession(context.Context, string, Session) error
	GetSession(context.Context, string, int64) (Session, error)
	UpdateToken(context.Context, string, []byte, int64) error
	DeleteSession(context.Context, string) error
	Prune(context.Context, int64) error
}

type storeData struct {
	Version  int                `json:"version"`
	Attempts map[string]Attempt `json:"attempts"`
	Sessions map[string]Session `json:"sessions"`
}

// JSONStore is deliberately small: one process, one private JSON file. The app
// encrypts OAuth tokens and PKCE verifiers before handing them to this store.
type JSONStore struct {
	mu       sync.Mutex
	dir      string
	lockFile *os.File
	data     storeData
}

func openStore(directory string) (*JSONStore, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(directory, "store.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := lock.Chmod(0600); err != nil {
		lock.Close()
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("lock local store (another demo may be running): %w", err)
	}
	s := &JSONStore{dir: directory, lockFile: lock, data: storeData{
		Version: 1, Attempts: make(map[string]Attempt), Sessions: make(map[string]Session),
	}}
	if err := s.load(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *JSONStore) load() error {
	path := filepath.Join(s.dir, "store.json")
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // Do not create a snapshot until the first change.
	}
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	var data storeData
	if err := json.Unmarshal(contents, &data); err != nil {
		return fmt.Errorf("read local store (file preserved): %w", err)
	}
	if data.Version != 1 || data.Attempts == nil || data.Sessions == nil {
		return errors.New("unsupported or invalid local store (file preserved)")
	}
	for key, a := range data.Attempts {
		if key == "" || a.StateHash != key {
			return errors.New("invalid login attempt in local store (file preserved)")
		}
	}
	for key, v := range data.Sessions {
		if key == "" || v.Hash != key {
			return errors.New("invalid session in local store (file preserved)")
		}
	}
	if pruneData(&data, time.Now().Unix()) {
		if err := s.save(data); err != nil {
			return err
		}
	} else {
		s.data = data
	}
	return nil
}

func (s *JSONStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lockFile == nil {
		return nil
	}
	err := s.lockFile.Close() // Closing releases the process lock; leave the file.
	s.lockFile = nil
	return err
}

func (s *JSONStore) ready(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.lockFile == nil {
		return errors.New("local store is closed")
	}
	return nil
}

func (s *JSONStore) Ping(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready(ctx)
}

// Each mutation works on a copy. Failed writes leave the live in-memory state
// unchanged, so a callback is never consumed before that change reaches disk.
func copyData(data storeData) storeData {
	copy := storeData{Version: data.Version, Attempts: make(map[string]Attempt), Sessions: make(map[string]Session)}
	for key, a := range data.Attempts {
		a.Verifier = append([]byte(nil), a.Verifier...)
		copy.Attempts[key] = a
	}
	for key, v := range data.Sessions {
		v.Token = append([]byte(nil), v.Token...)
		copy.Sessions[key] = v
	}
	return copy
}

func pruneData(data *storeData, now int64) bool {
	changed := false
	for key, a := range data.Attempts {
		if a.ExpiresAt <= now {
			delete(data.Attempts, key)
			changed = true
		}
	}
	for key, v := range data.Sessions {
		if v.ExpiresAt <= now {
			delete(data.Sessions, key)
			changed = true
		}
	}
	return changed
}

func (s *JSONStore) save(data storeData) error {
	contents, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, ".store-*.tmp") // Created with mode 0600.
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(append(contents, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filepath.Join(s.dir, "store.json")); err != nil {
		return err
	}
	// This demo does not fsync the directory or promise power-loss durability.
	s.data = data // Rename is the commit point.
	return nil
}

func (s *JSONStore) CreateAttempt(ctx context.Context, a Attempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return err
	}
	data := copyData(s.data)
	pruneData(&data, time.Now().Unix())
	if a.StateHash == "" {
		return errors.New("empty login attempt key")
	}
	if _, exists := data.Attempts[a.StateHash]; exists {
		return errors.New("login attempt already exists")
	}
	a.Verifier = append([]byte(nil), a.Verifier...)
	data.Attempts[a.StateHash] = a
	return s.save(data)
}

func (s *JSONStore) ConsumeAttempt(ctx context.Context, state, browser string, now int64) (Attempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return Attempt{}, err
	}
	a, exists := s.data.Attempts[state]
	if !exists || a.BrowserHash != browser || a.ExpiresAt <= now {
		return Attempt{}, errMissing
	}
	data := copyData(s.data)
	pruneData(&data, now)
	delete(data.Attempts, state)
	if err := s.save(data); err != nil {
		return Attempt{}, err
	}
	a.Verifier = append([]byte(nil), a.Verifier...)
	return a, nil
}

func (s *JSONStore) CreateSession(ctx context.Context, oldHash string, v Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return err
	}
	data := copyData(s.data)
	pruneData(&data, time.Now().Unix())
	delete(data.Sessions, oldHash)
	if v.Hash == "" {
		return errors.New("empty session key")
	}
	if _, exists := data.Sessions[v.Hash]; exists {
		return errors.New("session already exists")
	}
	v.Token = append([]byte(nil), v.Token...)
	data.Sessions[v.Hash] = v
	return s.save(data)
}

func (s *JSONStore) GetSession(ctx context.Context, hash string, now int64) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return Session{}, err
	}
	v, exists := s.data.Sessions[hash]
	if !exists || v.ExpiresAt <= now {
		return Session{}, errMissing
	}
	v.Token = append([]byte(nil), v.Token...)
	return v, nil
}

func (s *JSONStore) UpdateToken(ctx context.Context, hash string, token []byte, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return err
	}
	data := copyData(s.data)
	pruneData(&data, now)
	v, exists := data.Sessions[hash]
	if !exists {
		return errMissing
	}
	v.Token = append([]byte(nil), token...)
	data.Sessions[hash] = v
	return s.save(data)
}

func (s *JSONStore) DeleteSession(ctx context.Context, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return err
	}
	data := copyData(s.data)
	changed := pruneData(&data, time.Now().Unix())
	if _, exists := data.Sessions[hash]; !exists && !changed {
		return nil
	}
	delete(data.Sessions, hash)
	return s.save(data)
}

func (s *JSONStore) Prune(ctx context.Context, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return err
	}
	data := copyData(s.data)
	if !pruneData(&data, now) {
		return nil
	}
	return s.save(data)
}
