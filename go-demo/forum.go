package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"golang.org/x/oauth2"
)

// This is the only forum API call in the demo. To add a future access-policy
// endpoint, put its request/response handling beside fetchIdentity and call it
// from callback before creating a session and authenticated after matching its ID.
// Use the same authenticated token, timeout, response limit and fail-closed error
// handling. No SMS enrollment, ban or game-eligibility policy is implemented here.
type Identity struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
}

func (a *App) fetchIdentity(ctx context.Context, token *oauth2.Token) (Identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.config.ForumBaseURL+"/api/me/", nil)
	if err != nil {
		return Identity{}, errUpstream
	}
	token.SetAuthHeader(req)
	req.Header.Set("Accept", "application/json")
	res, err := a.client.Do(req)
	if err != nil {
		return Identity{}, errUpstream
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusUnauthorized {
		return Identity{}, errLoginRequired
	}
	if res.StatusCode == http.StatusForbidden {
		return Identity{}, errAccessDenied
	}
	if res.StatusCode != http.StatusOK {
		return Identity{}, errUpstream
	}
	var payload struct {
		Me Identity `json:"me"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&payload); err != nil {
		return Identity{}, errUpstream
	}
	if payload.Me.UserID <= 0 || payload.Me.Username == "" {
		return Identity{}, errLoginRequired
	}
	return payload.Me, nil
}
