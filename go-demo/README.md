# Go OAuth demo

A standalone, local Go application demonstrating XenForo OAuth login, a persistent
local session, an authenticated API request and logout. It needs only Go. It uses
a private JSON file rather than MariaDB or SQLite, and runs without Docker,
nginx, Anubis, PHP, Node or a frontend build system.

This is a small development example for Debian/Linux, not the Players application.
Its page shows your forum name and ID. There is no game or account-management
functionality. No forum source, credentials or user data are included.

## First run on Debian sid

Install Go and certificates. The C compiler is for the optional race detector:

```sh
sudo apt update
sudo apt install golang-go ca-certificates build-essential
```

Use Go 1.26 or newer (`go version`); sid currently supplies a suitable toolchain.
The Go commands below run as your normal user, from this directory beside go.mod:

```sh
cp config.example.json config.json
chmod 600 config.json
go test ./...
go run .
```

Go downloads the one external library declared in go.mod automatically. Do not
run go mod init; this is already a module. The first compile can take longer while
Go populates its build cache. No database installation or schema setup is needed.

Open **http://localhost:18080/**. Stop any SSH forward already using local port
18080 first. The demo initially works as a guest page with sign-in disabled.
Press Ctrl+C to stop. It automatically creates the private data/ directory and
encryption key on first startup.

## Enable forum login

In the XenForo ACP, use Setup > Service providers > OAuth2 clients. Use a
confidential, active development client with the **user:read** scope and this
exact redirect URI:

```text
http://localhost:18080/auth/callback
```

You can enter the existing development client's credentials if its registered
callback matches; a separate workstation client lets you revoke it independently.
The demo does not create a client or alter forum settings for you.

Edit **config.json**, setting client_id and client_secret, then restart go run.
Keep this file private; it is ignored by Git. Do not put credentials in the HTML.
The example has no credentials and should remain safe to copy.

Use localhost consistently in the browser: 127.0.0.1 is a different origin.
If changing the port, update listen_addr, public_base_url and the registered
OAuth callback together. The forum URL stays https://forums.shadowrest.org.
data_dir is relative to config.json's directory. An alternate config is supported:

```sh
go run . -config /path/to/another/config.json
```

Real login uses the live forum's normal consent/login/SMS or trusted-device flow.
Only the automated tests use a fake forum. The local app never sees your forum
password or sends SMS itself.

## Manual development workflow

Edit a file, stop the old server with Ctrl+C, then:

```sh
go fmt ./...       # Standard Go source formatting
go vet ./...       # Static checks for suspicious code
go test ./...      # Tests with fake forum and temporary local files
go run .          # Compile and run the current source
```

Use the dot, not go run main.go: the application spans several source files.
Go run compiles a temporary executable; it does not interpret source. For an
explicit executable you can run repeatedly:

```sh
mkdir -p bin
go build -o bin/go-demo .
./bin/go-demo
```

Run that binary from this directory so its default config.json is found, or pass
-config. Compiling alone does not update an already-running process. There is no
automatic reload. Templates and CSS are embedded into the executable, so their
edits require another go run or rebuild as well. Configuration changes need only
a restart. Sessions survive either kind of restart when data/ is retained.

For concurrency changes, run the race detector; -count=1 bypasses test caching:

```sh
go test -race -count=1 ./...
```

The ordinary suite includes real JSON file persistence and a fake-provider OAuth
flow across reopening the store. It needs no live forum, client credentials,
database service or browser. The optional Chromium regression skips unless
GODEMO_WEBDRIVER_URL points to a dedicated local ChromeDriver, for example:

```sh
GODEMO_WEBDRIVER_URL=http://127.0.0.1:9515 go test -race -run TestBrowserLogoutForm -count=1
```

## Where to edit

| File | Purpose |
| --- | --- |
| main.go | Read config, open local state, start/stop HTTP server |
| config.go | Configuration, automatic key and encryption helpers |
| server.go | Routes, OAuth flow, refresh and local logout |
| forum.go | Authenticated forum identity API call; future policy integration |
| store.go | Small persistent JSON store and one-process lock |
| templates/page.html | Page markup and text |
| assets/demo.css | Small stylesheet |
| *_test.go | Tests using temporary files and a fake forum |

The flow is /login -> forum authorization -> /auth/callback -> /account.
The callback checks browser-bound, single-use state, exchanges the code with
PKCE, and requests /api/me/ for the forum ID. The browser gets a random local
session cookie; OAuth tokens remain server-side. /account refreshes an expired
token if needed and calls /api/me/ again. The home page's greeting is only cached
session information; /account is the authenticated request demonstration.

The future access-policy API belongs next to fetchIdentity in forum.go, called
from the sign-in and authenticated-request paths. At present /api/me/ confirms
identity only. This demo does **not** enforce the proposed Shadowrest SMS
enrollment, confirmed-account or game eligibility policy.

## Local state and logout

- data/store.json contains pending login attempts and sessions. Tokens and PKCE
  verifiers are encrypted; forum IDs/names and session metadata are not.
- data/key is generated automatically. Keep it with store.json across restarts.
- data/store.lock prevents two processes from using the same store. Stop the old
  app before starting a replacement. Linux releases the lock when a process exits.
- The directory is private (0700); state/key files are private (0600). Git ignores
  config.json, data/ and bin/. This does not protect against someone who can read
  both the key and store as your operating-system user.
- Local sessions last 24 hours; pending sign-ins last ten minutes. Expired state
  is pruned on startup and writes. JSON saves replace the file atomically after
  syncing a temporary file; this is not a power-loss durability guarantee.
- Log out uses POST with a form token and origin checks. It removes the local
  session, not the forum session or the forum's OAuth grant. Signing in again can
  reuse the existing forum login. Each application owns its own logout.

For a fresh start, stop the demo and rename the entire data/ directory. It will
create a new one on startup. A corrupt store or a missing key alongside an existing
store causes an error rather than silently discarding sessions.

Only loopback HTTP is supported. The file store rewrites its small state file on
mutations and supports one process, which is intentional for this demo. A process
crash between remote refresh-token rotation and saving its replacement can require
signing in again. Keep the existing deployed Players stack separate.
