package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	ListenAddr        string `json:"listen_addr"`
	PublicBaseURL     string `json:"public_base_url"`
	ForumBaseURL      string `json:"forum_base_url"`
	OAuthClientID     string `json:"client_id"`
	OAuthClientSecret string `json:"client_secret"`
	DataDir           string `json:"data_dir"`
	// Fixed defaults keep this a loopback development demo.
	CookieSecure bool `json:"-"`
	SessionHours int  `json:"-"`
}

type Secrets struct {
	OAuthClientID, OAuthClientSecret, TokenEncryptionKey string
}

func readJSON(path string, dest any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if err := d.Decode(dest); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("configuration must contain one JSON object")
	}
	return nil
}

func loadConfig(path string) (Config, error) {
	c := Config{ListenAddr: "127.0.0.1:18080", PublicBaseURL: "http://localhost:18080", ForumBaseURL: "https://forums.shadowrest.org", DataDir: "data", SessionHours: 24}
	if err := readJSON(path, &c); err != nil {
		return c, errors.New("cannot read config; copy config.example.json to config.json and check its JSON syntax")
	}
	if err := c.validate(); err != nil {
		return c, err
	}
	if !filepath.IsAbs(c.DataDir) {
		c.DataDir = filepath.Join(filepath.Dir(path), c.DataDir)
	}
	return c, nil
}

func (c *Config) validate() error {
	for _, raw := range []string{c.PublicBaseURL, c.ForumBaseURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return errors.New("base URLs must be origins without credentials, paths, queries or fragments")
		}
		ip := net.ParseIP(u.Hostname())
		loopback := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
		if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
			return errors.New("the forum URL requires HTTPS except for loopback test servers")
		}
	}
	c.PublicBaseURL = strings.TrimRight(c.PublicBaseURL, "/")
	c.ForumBaseURL = strings.TrimRight(c.ForumBaseURL, "/")
	public, _ := url.Parse(c.PublicBaseURL)
	if public.Scheme != "http" || (public.Hostname() != "localhost" && !net.ParseIP(public.Hostname()).IsLoopback()) {
		return errors.New("this demo's public_base_url must be HTTP on localhost or a loopback IP")
	}
	host, port, err := net.SplitHostPort(c.ListenAddr)
	if err != nil || !net.ParseIP(host).IsLoopback() || port == "" {
		return errors.New("listen_addr must use a loopback IP and port")
	}
	if (c.OAuthClientID == "") != (c.OAuthClientSecret == "") {
		return errors.New("set both client_id and client_secret, or leave both empty for the guest preview")
	}
	if c.DataDir == "" {
		return errors.New("data_dir must not be empty")
	}
	return nil
}

// The store lock must be held before calling this. Never replace a missing key
// underneath saved sessions: they were encrypted with the original key.
func loadSecrets(c Config) (Secrets, error) {
	s := Secrets{OAuthClientID: c.OAuthClientID, OAuthClientSecret: c.OAuthClientSecret}
	path := filepath.Join(c.DataDir, "key")
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if _, err := os.Stat(filepath.Join(c.DataDir, "store.json")); !errors.Is(err, os.ErrNotExist) {
			return s, errors.New("local key is missing but stored sessions exist; restore the matching key or move the entire data directory aside for a fresh start")
		}
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return s, errors.New("cannot create local encryption key")
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return s, errors.New("cannot create local key file")
		}
		_, writeErr := f.Write(key)
		syncErr := f.Sync()
		closeErr := f.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return s, errors.New("cannot save local key file")
		}
	} else if err != nil {
		return s, errors.New("cannot read local key file")
	}
	if len(key) != 32 {
		return s, errors.New("invalid local key file; expected 32 bytes")
	}
	if err := os.Chmod(path, 0600); err != nil {
		return s, errors.New("cannot restrict local key file permissions")
	}
	s.TokenEncryptionKey = base64.StdEncoding.EncodeToString(key)
	return s, nil
}

func newCipher(encoded string) (cipher.AEAD, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid token encryption key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func seal(aead cipher.AEAD, value []byte, purpose string) []byte {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic("cryptographic random source unavailable")
	}
	return aead.Seal(nonce, nonce, value, []byte(purpose))
}

func unseal(aead cipher.AEAD, value []byte, purpose string) ([]byte, error) {
	if len(value) < aead.NonceSize() {
		return nil, errors.New("invalid encrypted record")
	}
	return aead.Open(nil, value[:aead.NonceSize()], value[aead.NonceSize():], []byte(purpose))
}

func randomValue() string {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		panic("cryptographic random source unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func hashValue(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func safeReturn(string) string { return "/account" }
