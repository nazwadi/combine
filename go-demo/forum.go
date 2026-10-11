package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode"

	"golang.org/x/oauth2"
)

// XenForo owns the access policy. This client requires an explicit allowance and
// identity at login and on every protected request; it does not copy that policy.
type Identity struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
}

type AccessDenial struct {
	Code, Message, UserState string
}

func (e *AccessDenial) Error() string { return errAccessDenied.Error() }
func (e *AccessDenial) Unwrap() error { return errAccessDenied }

func accessDenialMessage(err error) string {
	var denial *AccessDenial
	if errors.As(err, &denial) && denial.Message != "" {
		return denial.Message
	}
	return "The forum is currently denying access to this account. Check your account on the forum before trying again."
}

// Native XenForo errors are user-facing text. Bound their size, omit control
// characters, and leave HTML escaping to html/template (never template.HTML).
func safeErrorText(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	runes := []rune(strings.TrimSpace(value))
	if len(runes) > 500 {
		runes = runes[:500]
	}
	return string(runes)
}

func (a *App) fetchAccess(ctx context.Context, token *oauth2.Token) (Identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.config.ForumBaseURL+"/api/shadowrest/access/", nil)
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
		var payload struct {
			Errors []struct {
				Code    string          `json:"code"`
				Message string          `json:"message"`
				Params  json.RawMessage `json:"params"`
			} `json:"errors"`
		}
		body, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
		if err == nil && len(body) <= 1<<20 && json.Unmarshal(body, &payload) == nil && len(payload.Errors) > 0 {
			problem := payload.Errors[0]
			var params struct {
				UserState string `json:"user_state"`
			}
			// Native empty params may be [] instead of an object.
			_ = json.Unmarshal(problem.Params, &params)
			denial := &AccessDenial{Code: safeErrorText(problem.Code), Message: safeErrorText(problem.Message), UserState: safeErrorText(params.UserState)}
			if denial.Code == "missing_scope" {
				denial.Message = "This demo needs the Shadowrest access permission. After it is enabled for the forum OAuth client, log out of the demo and sign in again."
			}
			return Identity{}, denial
		}
		return Identity{}, errAccessDenied
	}
	if res.StatusCode != http.StatusOK {
		return Identity{}, errUpstream
	}
	var payload struct {
		Allowed bool `json:"allowed"`
		Identity
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 || json.Unmarshal(body, &payload) != nil {
		return Identity{}, errUpstream
	}
	if !payload.Allowed || payload.UserID <= 0 || strings.TrimSpace(payload.Username) == "" {
		return Identity{}, errUpstream
	}
	return payload.Identity, nil
}
