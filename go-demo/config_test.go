package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigDefaultsAndLocalPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"client_id":"","client_secret":""}`), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != "127.0.0.1:18080" || c.PublicBaseURL != "http://localhost:18080" || c.DataDir != filepath.Join(dir, "data") || c.SessionHours != 24 {
		t.Fatal("incorrect defaults or config-relative data directory")
	}
	for _, input := range []string{
		`{"listen_addr":"0.0.0.0:18080"}`,
		`{"public_base_url":"http://elsewhere.invalid:18080"}`,
		`{"forum_base_url":"http://forums.shadowrest.org"}`,
		`{"public_base_url":"http://localhost:18080/?secret=bad"}`,
		`{"client_id":"incomplete"}`,
		`{"unknown_setting":true}`,
		`{} {}`,
		`{} invalid`,
	} {
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(path); err == nil {
			t.Fatal("invalid development configuration accepted")
		}
	}
}

func TestAutomaticKeyAndMissingKeyProtection(t *testing.T) {
	c := Config{DataDir: t.TempDir()}
	first, err := loadSecrets(c)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadSecrets(c)
	if err != nil || first.TokenEncryptionKey != second.TokenEncryptionKey {
		t.Fatal("key changed across restart")
	}
	if _, err := newCipher(first.TokenEncryptionKey); err != nil {
		t.Fatal("generated key is invalid")
	}
	info, err := os.Stat(filepath.Join(c.DataDir, "key"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("key permissions are not private")
	}
	if err := os.WriteFile(filepath.Join(c.DataDir, "store.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(c.DataDir, "key")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSecrets(c); err == nil {
		t.Fatal("missing key was silently replaced under existing sessions")
	}
	if _, err := os.Stat(filepath.Join(c.DataDir, "key")); !os.IsNotExist(err) {
		t.Fatal("replacement key was written")
	}
}

func TestExampleConfiguration(t *testing.T) {
	data, err := os.ReadFile("config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if c.OAuthClientID != "" || c.OAuthClientSecret != "" {
		t.Fatal("example contains credentials")
	}
	if _, err := loadConfig("config.example.json"); err != nil {
		t.Fatal(err)
	}
}
