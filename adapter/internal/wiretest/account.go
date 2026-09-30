package wiretest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// Conformance cases for the session-listing and account-management routes:
// GET /sessions, DELETE /sessions/{handle}, POST /sessions/cleanup,
// PATCH /profile, POST /add-phone and DELETE /account.
//
// These are the first authenticated state-changing routes in the port, so they
// are also the first place the CSRF double-submit is enforceable at all. Until
// now the machinery protected nothing.

// bareUserStore implements UserStore and nothing else. A store like this is what
// makes the account routes answer 501 instead of pretending to have written.
type bareUserStore struct{ inner *auth.MemoryUserStore }

func newBareUserStore() bareUserStore { return bareUserStore{inner: auth.NewMemoryUserStore()} }

func (s bareUserStore) CreateUser(ctx context.Context, user auth.User) (auth.User, error) {
	return s.inner.CreateUser(ctx, user)
}

func (s bareUserStore) GetUserByEmail(ctx context.Context, email, tenantID string) (auth.User, error) {
	return s.inner.GetUserByEmail(ctx, email, tenantID)
}

func (s bareUserStore) GetUserByID(ctx context.Context, id, tenantID string) (auth.User, error) {
	return s.inner.GetUserByID(ctx, id, tenantID)
}

// bareSessionStore implements SessionStore and nothing else: it can log a user
// in but cannot list, revoke or clean up.
type bareSessionStore struct{ inner *auth.MemorySessionStore }

func newBareSessionStore() bareSessionStore {
	return bareSessionStore{inner: auth.NewMemorySessionStore()}
}

func (s bareSessionStore) CreateSession(ctx context.Context, session auth.Session) (auth.Session, error) {
	return s.inner.CreateSession(ctx, session)
}

func (s bareSessionStore) GetSessionByRefreshTokenHash(ctx context.Context, hash string) (auth.Session, error) {
	return s.inner.GetSessionByRefreshTokenHash(ctx, hash)
}

func (s bareSessionStore) UpdateSession(ctx context.Context, session auth.Session) error {
	return s.inner.UpdateSession(ctx, session)
}

// nilSessionStore returns a nil slice from the list call, the way a driver that
// found no rows does. It exists to prove the route still serialises [].
type nilSessionStore struct{ *auth.MemorySessionStore }

func (nilSessionStore) ListSessionsForUser(context.Context, string, string) ([]auth.Session, error) {
	return nil, nil
}

func bearerRequest(method, url, token string) *http.Request {
	req := httptest.NewRequest(method, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// sessionEntries asserts the wrapped envelope and returns the entries.
func sessionEntries(t *testing.T, rec *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	body := Body(t, rec)
	AssertKeys(t, body, "sessions")
	raw, ok := body["sessions"].([]any)
	if !ok {
		t.Fatalf("sessions = %T, want a JSON array (body %s)", body["sessions"], rec.Body.String())
	}
	entries := make([]map[string]any, 0, len(raw))
	for i, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("sessions[%d] = %T, want an object", i, item)
		}
		entries = append(entries, entry)
	}
	return entries
}

func findSession(t *testing.T, entries []map[string]any, handle string) map[string]any {
	t.Helper()
	for _, entry := range entries {
		if entry["sessionHandle"] == handle {
			return entry
		}
	}
	t.Fatalf("no session %q in %v", handle, entries)
	return nil
}

// assertSessionAbsent is the shape of a revoked session in the reference: gone
// from the next list, not flagged in it. The reference's revokeSession deletes
// the record (session-store.interface.ts:70-76), so a client that lists sessions
// after revoking one never sees it again — and since SessionInfo has no
// revokedAt, no shipped client could filter it out itself.
func assertSessionAbsent(t *testing.T, entries []map[string]any, handle string) {
	t.Helper()
	for _, entry := range entries {
		if entry["sessionHandle"] == handle {
			t.Fatalf("session %q is still listed after being revoked: %v", handle, entry)
		}
	}
}

// listSessions fetches GET /sessions with a bearer credential and returns the
// entries, asserting the envelope and that no entry carries a key outside
// SessionInfo — revokedAt above all.
func listSessions(t *testing.T, env *Env, accessToken string) []map[string]any {
	t.Helper()
	rec := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/sessions", accessToken))
	AssertStatus(t, rec, http.StatusOK)
	entries := sessionEntries(t, rec)
	for i, entry := range entries {
		if _, extra := entry["revokedAt"]; extra {
			t.Fatalf("sessions[%d] carries revokedAt, which is not a SessionInfo field: %v", i, entry)
		}
	}
	return entries
}

func testSessions(t *testing.T, mount Mounter) {
	t.Run("the list is wrapped in a sessions key", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, tokens := env.Seed("sessions@example.com")

		rec := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/sessions", tokens.AccessToken))
		AssertStatus(t, rec, http.StatusOK)

		entries := sessionEntries(t, rec)
		if len(entries) != 1 {
			t.Fatalf("sessions = %d entries, want 1 (%s)", len(entries), rec.Body.String())
		}
		entry := entries[0]
		// The exact key set, so that a refresh-token hash or any other stored
		// column cannot be added to the projection without failing here.
		AssertKeys(t, entry, "sessionHandle", "userId", "tenantId", "createdAt", "expiresAt")
		if entry["userId"] != user.ID {
			t.Errorf("userId = %v, want %q", entry["userId"], user.ID)
		}
		if entry["tenantId"] != "t1" {
			t.Errorf("tenantId = %v, want \"t1\"", entry["tenantId"])
		}
		created := parseTimestamp(t, entry, "createdAt")
		expires := parseTimestamp(t, entry, "expiresAt")
		// The session outlives the refresh token by nothing: both are the
		// configured 30 days from creation.
		if lifetime := expires.Sub(created); lifetime > 30*24*time.Hour || lifetime < 30*24*time.Hour-2*time.Second {
			t.Errorf("expiresAt - createdAt = %s, want 30 days", lifetime)
		}
	})

	// The browser path, and the CSRF matrix row that says a cookie-authenticated
	// GET is not checked: the clients list sessions without a CSRF header.
	t.Run("cookie mode needs no CSRF header", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, _ := loginSession(t, env, "sessionscookie@example.com")

		rec := env.Do(Replay(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/sessions", nil), login))
		AssertStatus(t, rec, http.StatusOK)

		// Two: the seeding register issued one session and the login a second. The
		// route lists every live session of the user, not just the current one.
		if entries := sessionEntries(t, rec); len(entries) != 2 {
			t.Fatalf("sessions = %d entries, want 2 (%s)", len(entries), rec.Body.String())
		}
	})

	t.Run("an empty list serialises as [] and not null", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSessionStore(nilSessionStore{auth.NewMemorySessionStore()}))
		_, tokens := env.Seed("emptysessions@example.com")

		rec := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/sessions", tokens.AccessToken))
		AssertStatus(t, rec, http.StatusOK)
		if got := strings.TrimSpace(rec.Body.String()); got != `{"sessions":[]}` {
			t.Fatalf("body = %s, want {\"sessions\":[]}", got)
		}
	})

	t.Run("without a token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/sessions", nil))
		AssertError(t, rec, http.StatusForbidden, "No access token provided", "")
	})

	// The reference simply does not mount the session routes when the store
	// cannot serve them, so it answers 404. This port always mounts them and
	// reports the missing capability, which is the same 501 every other
	// store-gated route in this package returns.
	t.Run("501 when the session store cannot list", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSessionStore(newBareSessionStore()))
		_, tokens := env.Seed("nolist@example.com")
		rec := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/sessions", tokens.AccessToken))
		AssertError(t, rec, http.StatusNotImplemented, "Feature not supported by the configured stores", auth.CodeNotImplemented)
	})

	// One family client URI-escapes the handle and the other posts it verbatim;
	// both have to revoke the same session.
	for _, tc := range []struct {
		name    string
		handle  string
		request string
	}{
		{name: "verbatim handle", handle: "ses_plain+form:1", request: "ses_plain+form:1"},
		{name: "URI-escaped handle", handle: "ses_escaped+form:2", request: "ses_escaped%2Bform%3A2"},
		// A handle carrying a literal percent is the row that catches a *double*
		// decode. net/http and gin hand the segment over already unescaped, so
		// unescaping it again turns "ses_50%25off" into "ses_50%off" and 404s a
		// live session; chi and echo hand it over still encoded, so for them one
		// decode is right. The two rows above are both idempotent under a second
		// decode and so cannot tell the two cases apart at all.
		{name: "handle containing a percent", handle: "ses_50%25off", request: "ses_50%2525off"},
	} {
		t.Run("DELETE accepts a "+tc.name, func(t *testing.T) {
			store := auth.NewMemorySessionStore()
			env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSessionStore(store))
			user, tokens := env.Seed("revoke@example.com")
			seedSession(t, store, tc.handle, user)

			rec := env.Do(bearerRequest(http.MethodDelete, env.Config.Prefix()+"/sessions/"+tc.request, tokens.AccessToken))
			AssertStatus(t, rec, http.StatusOK)
			AssertKeys(t, Body(t, rec), "success")
			if Body(t, rec)["success"] != true {
				t.Fatalf("success = %v", Body(t, rec)["success"])
			}

			// The revoke really happened, and the way the reference shows it: the
			// handle is gone from the next list. Asserting a revokedAt key here
			// instead used to pin the opposite — a dead session still listed.
			assertSessionAbsent(t, listSessions(t, env, tokens.AccessToken), tc.handle)
		})
	}

	// GET /sessions serves active sessions only (getSessionsForUser is documented
	// "Return all active sessions for the given user",
	// session-store.interface.ts:58-61). This port's store tombstones rather than
	// deleting, so the filter lives above it — and it has to, because no client can
	// filter for itself: SessionInfo has no revokedAt.
	t.Run("a revoked session disappears from the list", func(t *testing.T) {
		store := auth.NewMemorySessionStore()
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSessionStore(store))
		user, tokens := env.Seed("revokedhidden@example.com")
		seedSession(t, store, "ses_doomed", user)
		seedSession(t, store, "ses_kept", user)

		// Three: the seeding register issued one, plus the two seeded here.
		if before := listSessions(t, env, tokens.AccessToken); len(before) != 3 {
			t.Fatalf("sessions = %d entries before the revoke, want 3", len(before))
		}

		rec := env.Do(bearerRequest(http.MethodDelete, env.Config.Prefix()+"/sessions/ses_doomed", tokens.AccessToken))
		AssertStatus(t, rec, http.StatusOK)

		after := listSessions(t, env, tokens.AccessToken)
		if len(after) != 2 {
			t.Fatalf("sessions = %d entries after the revoke, want 2: %v", len(after), after)
		}
		assertSessionAbsent(t, after, "ses_doomed")
		findSession(t, after, "ses_kept")
	})

	// An expired-but-not-revoked session stays listed: the reference's own store
	// does not filter those out of getSessionsForUser either — only
	// deleteExpiredSessions removes them — so a device manager sees them there too.
	t.Run("an expired session stays in the list", func(t *testing.T) {
		store := auth.NewMemorySessionStore()
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSessionStore(store))
		user, tokens := env.Seed("expiredlisted@example.com")
		seedExpiredSession(t, store, "ses_stale", user)

		findSession(t, listSessions(t, env, tokens.AccessToken), "ses_stale")
	})

	// The reference resolves the handle with getSession, documented to return null
	// "when the session does not exist or has expired"
	// (session-store.interface.ts:51-54), and its revokeSession deletes the record.
	// So a second DELETE of the same handle, and a DELETE of an expired one, both
	// take the same `if (!session || …) → 404` branch as an unknown handle
	// (auth.router.ts:762-767). Answering 200 twice told a device-manager UI it had
	// just killed a session that was already dead.
	t.Run("DELETE an already-revoked handle", func(t *testing.T) {
		store := auth.NewMemorySessionStore()
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSessionStore(store))
		user, tokens := env.Seed("doublerevoke@example.com")
		seedSession(t, store, "ses_twice", user)

		first := env.Do(bearerRequest(http.MethodDelete, env.Config.Prefix()+"/sessions/ses_twice", tokens.AccessToken))
		AssertStatus(t, first, http.StatusOK)

		second := env.Do(bearerRequest(http.MethodDelete, env.Config.Prefix()+"/sessions/ses_twice", tokens.AccessToken))
		AssertError(t, second, http.StatusNotFound, "Session not found", "")
	})

	t.Run("DELETE an expired handle", func(t *testing.T) {
		store := auth.NewMemorySessionStore()
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSessionStore(store))
		user, tokens := env.Seed("revokeexpired@example.com")
		seedExpiredSession(t, store, "ses_gone", user)

		rec := env.Do(bearerRequest(http.MethodDelete, env.Config.Prefix()+"/sessions/ses_gone", tokens.AccessToken))
		AssertError(t, rec, http.StatusNotFound, "Session not found", "")
	})

	// Not found and not yours are the same answer, so the route cannot be used
	// to probe for another account's live sessions.
	t.Run("DELETE an unknown handle", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("unknownhandle@example.com")
		rec := env.Do(bearerRequest(http.MethodDelete, env.Config.Prefix()+"/sessions/ses_nope", tokens.AccessToken))
		AssertError(t, rec, http.StatusNotFound, "Session not found", "")
	})

	t.Run("DELETE somebody else's handle", func(t *testing.T) {
		store := auth.NewMemorySessionStore()
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSessionStore(store))
		_, tokens := env.Seed("owner@example.com")
		stranger, _ := env.Seed("stranger@example.com")
		seedSession(t, store, "ses_stranger", stranger)

		rec := env.Do(bearerRequest(http.MethodDelete, env.Config.Prefix()+"/sessions/ses_stranger", tokens.AccessToken))
		AssertError(t, rec, http.StatusNotFound, "Session not found", "")
	})

	// The reference mounts cleanup with no auth gate at all (auth.router.ts:736):
	// no token, no admin secret, and — being absent from no middleware — no CSRF
	// check either. That is reproduced here rather than hardened, because a cron
	// job calling it unauthenticated has to keep working. Flagged for upstream.
	t.Run("cleanup is publicly callable", func(t *testing.T) {
		store := auth.NewMemorySessionStore()
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSessionStore(store))
		user, _ := env.Seed("cleanup@example.com")
		expired := auth.Session{
			ID:               "ses_expired",
			UserID:           user.ID,
			TenantID:         user.TenantID,
			RefreshTokenHash: "expired-hash",
			CreatedAt:        time.Now().Add(-48 * time.Hour),
			ExpiresAt:        time.Now().Add(-time.Hour),
		}
		if _, err := store.CreateSession(context.Background(), expired); err != nil {
			t.Fatalf("seed expired session: %v", err)
		}

		rec := env.Do(httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/sessions/cleanup", nil))
		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "deleted")
		if body["success"] != true {
			t.Errorf("success = %v", body["success"])
		}
		// Exactly the one expired session: the live one the seed created stays.
		if body["deleted"] != float64(1) {
			t.Errorf("deleted = %v, want 1", body["deleted"])
		}
	})
}

func seedSession(t *testing.T, store *auth.MemorySessionStore, handle string, user auth.User) {
	t.Helper()
	now := time.Now()
	session := auth.Session{
		ID:               handle,
		UserID:           user.ID,
		TenantID:         user.TenantID,
		RefreshTokenHash: "hash-" + handle,
		CreatedAt:        now,
		ExpiresAt:        now.Add(time.Hour),
	}
	if _, err := store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("seed session %q: %v", handle, err)
	}
}

// seedExpiredSession plants a session whose lifetime has already run out but
// which no cleanup has removed yet — the state the reference's getSession reports
// as null.
func seedExpiredSession(t *testing.T, store *auth.MemorySessionStore, handle string, user auth.User) {
	t.Helper()
	now := time.Now()
	session := auth.Session{
		ID:               handle,
		UserID:           user.ID,
		TenantID:         user.TenantID,
		RefreshTokenHash: "hash-" + handle,
		CreatedAt:        now.Add(-48 * time.Hour),
		ExpiresAt:        now.Add(-time.Hour),
	}
	if _, err := store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("seed expired session %q: %v", handle, err)
	}
}

func parseTimestamp(t *testing.T, entry map[string]any, key string) time.Time {
	t.Helper()
	raw, ok := entry[key].(string)
	if !ok {
		t.Fatalf("%s = %v, want an RFC 3339 string", key, entry[key])
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t.Fatalf("%s = %q: %v", key, raw, err)
	}
	return parsed
}

func testAccount(t *testing.T, mount Mounter) {
	t.Run("PATCH /profile", func(t *testing.T) { testUpdateProfile(t, mount) })
	t.Run("POST /add-phone", func(t *testing.T) { testAddPhone(t, mount) })
	t.Run("DELETE /account", func(t *testing.T) { testDeleteAccount(t, mount) })
	t.Run("the store capability gate", func(t *testing.T) { testAccountCapabilityGate(t, mount) })
}

// loginSession logs a seeded user in and returns the response to replay cookies
// from, together with the CSRF token the page would mirror into the header.
func loginSession(t *testing.T, env *Env, email string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	env.Seed(email)
	login := env.Do(env.Request(http.MethodPost, "/login", credentials(email)))
	AssertStatus(t, login, http.StatusOK)
	return login, Cookie(t, login, hostCSRF).Value
}

func meBody(t *testing.T, env *Env, login *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	rec := env.Do(Replay(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil), login))
	AssertStatus(t, rec, http.StatusOK)
	return Body(t, rec)
}

func testUpdateProfile(t *testing.T, mount Mounter) {
	// The first route in the port on which the double-submit is actually
	// enforced: a cookie-authenticated PATCH is exactly the request a
	// cross-site form post can forge.
	t.Run("cookie mode with a matching X-CSRF-Token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, csrf := loginSession(t, env, "profile@example.com")

		req := Replay(env.Request(http.MethodPatch, "/profile", map[string]string{"firstName": "Mario", "lastName": "Rossi"}), login)
		req.Header.Set(auth.CSRFHeaderName, csrf)
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success")
		if body["success"] != true {
			t.Fatalf("success = %v", body["success"])
		}

		me := meBody(t, env, login)
		if me["firstName"] != "Mario" || me["lastName"] != "Rossi" {
			t.Fatalf("profile not updated: %v / %v", me["firstName"], me["lastName"])
		}
	})

	t.Run("cookie mode without X-CSRF-Token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, _ := loginSession(t, env, "profilecsrf@example.com")

		req := Replay(env.Request(http.MethodPatch, "/profile", map[string]string{"firstName": "Forged", "lastName": "Request"}), login)
		rec := env.Do(req)

		AssertError(t, rec, http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)
		// Rejecting is only half of it: the write must not have happened.
		if me := meBody(t, env, login); me["firstName"] != nil {
			t.Fatalf("the rejected request still wrote the profile: %v", me["firstName"])
		}
	})

	t.Run("cookie mode with a mismatched X-CSRF-Token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, _ := loginSession(t, env, "profilemismatch@example.com")

		req := Replay(env.Request(http.MethodPatch, "/profile", map[string]string{"firstName": "Forged"}), login)
		req.Header.Set(auth.CSRFHeaderName, "0123456789abcdef0123456789abcdef")
		AssertError(t, env.Do(req), http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)
	})

	// A bearer caller cannot be driven by a cross-site form post and never reads
	// the CSRF cookie, so it is exempt — the reference skips the check entirely
	// for Authorization-header requests (auth.middleware.ts:35).
	t.Run("bearer mode needs no CSRF header", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, tokens := env.Seed("profilebearer@example.com")

		req := env.Request(http.MethodPatch, "/profile", map[string]string{"firstName": "Anna", "lastName": "Bianchi"})
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertNoCookies(t, rec)

		me := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/me", tokens.AccessToken))
		if Body(t, me)["firstName"] != "Anna" {
			t.Fatalf("profile not updated for %s: %s", user.ID, me.Body.String())
		}
	})

	// The X-Auth-Strategy header is set by the caller, so it must not be able to
	// switch the double-submit off: the reference exempts a request only when its
	// token actually came from the Authorization header (usingBearer,
	// auth.middleware.ts:22-35). This request authenticates entirely by cookie and
	// only *claims* to be a bearer client.
	t.Run("the bearer strategy header does not skip the CSRF check", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, _ := loginSession(t, env, "profilestrategy@example.com")

		req := Replay(env.Request(http.MethodPatch, "/profile", map[string]string{"firstName": "Forged"}), login)
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		AssertError(t, env.Do(req), http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)
		if me := meBody(t, env, login); me["firstName"] != nil {
			t.Fatalf("a header-only bearer claim still wrote the profile: %v", me["firstName"])
		}
	})

	// PATCH /profile is a *partial* update: §3.5 types both fields optional and
	// passes the body through verbatim, so a key the caller omitted reaches the
	// store as undefined and the stored column is left alone. Sending only
	// firstName used to wipe the stored lastName — silent data loss on the common
	// case, since a form that edits one field submits one field.
	t.Run("a partial patch leaves the omitted field alone", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, csrf := loginSession(t, env, "partialprofile@example.com")

		both := Replay(env.Request(http.MethodPatch, "/profile", map[string]string{"firstName": "Mario", "lastName": "Rossi"}), login)
		both.Header.Set(auth.CSRFHeaderName, csrf)
		AssertStatus(t, env.Do(both), http.StatusOK)

		only := Replay(env.Request(http.MethodPatch, "/profile", map[string]string{"firstName": "Luigi"}), login)
		only.Header.Set(auth.CSRFHeaderName, csrf)
		AssertStatus(t, env.Do(only), http.StatusOK)

		me := meBody(t, env, login)
		if me["firstName"] != "Luigi" {
			t.Errorf("firstName = %v, want \"Luigi\"", me["firstName"])
		}
		if me["lastName"] != "Rossi" {
			t.Fatalf("lastName = %v, want \"Rossi\": the omitted field was erased", me["lastName"])
		}
	})

	// An explicitly empty value still clears, which is what the reference's
	// nullable field does. This is the half a plain string could not express
	// separately from "omitted".
	t.Run("an explicit empty value clears the field", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, csrf := loginSession(t, env, "clearprofile@example.com")

		both := Replay(env.Request(http.MethodPatch, "/profile", map[string]string{"firstName": "Mario", "lastName": "Rossi"}), login)
		both.Header.Set(auth.CSRFHeaderName, csrf)
		AssertStatus(t, env.Do(both), http.StatusOK)

		clear := Replay(env.Request(http.MethodPatch, "/profile", map[string]string{"lastName": ""}), login)
		clear.Header.Set(auth.CSRFHeaderName, csrf)
		AssertStatus(t, env.Do(clear), http.StatusOK)

		me := meBody(t, env, login)
		if me["firstName"] != "Mario" {
			t.Errorf("firstName = %v, want \"Mario\"", me["firstName"])
		}
		if me["lastName"] != nil && me["lastName"] != "" {
			t.Fatalf("lastName = %v, want cleared", me["lastName"])
		}
	})

	// The names are stored as sent (#35). The reference passes the parsed body
	// to userStore.updateProfile untouched (awesome-node-auth v1.10.8
	// auth.router.ts:1214-1215); the port used to trim both.
	t.Run("names are stored as sent, whitespace included", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, csrf := loginSession(t, env, "spacedprofile@example.com")

		req := Replay(env.Request(http.MethodPatch, "/profile", map[string]string{"firstName": "  Mario  ", "lastName": " Rossi"}), login)
		req.Header.Set(auth.CSRFHeaderName, csrf)
		AssertStatus(t, env.Do(req), http.StatusOK)

		me := meBody(t, env, login)
		if me["firstName"] != "  Mario  " || me["lastName"] != " Rossi" {
			t.Fatalf("names = %q / %q, want %q / %q", me["firstName"], me["lastName"], "  Mario  ", " Rossi")
		}
	})

	// The reference runs behind express.json(), which leaves req.body = {} for a
	// request with no body; §3.5 then reads two optional fields off it, so a
	// bodyless PATCH is a 200 no-op. The four adapters used to disagree here —
	// echo answered 200 and net/http, chi and gin 400 INVALID_BODY — which is
	// exactly the drift this suite exists to prevent.
	t.Run("a bodyless PATCH is a 200 no-op", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, csrf := loginSession(t, env, "bodylessprofile@example.com")

		seed := Replay(env.Request(http.MethodPatch, "/profile", map[string]string{"firstName": "Mario", "lastName": "Rossi"}), login)
		seed.Header.Set(auth.CSRFHeaderName, csrf)
		AssertStatus(t, env.Do(seed), http.StatusOK)

		empty := Replay(env.Request(http.MethodPatch, "/profile", nil), login)
		empty.Header.Set(auth.CSRFHeaderName, csrf)
		rec := env.Do(empty)
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")

		// A no-op, not a clear: every field was omitted, so every field survives.
		me := meBody(t, env, login)
		if me["firstName"] != "Mario" || me["lastName"] != "Rossi" {
			t.Fatalf("a bodyless patch changed the profile: %v / %v", me["firstName"], me["lastName"])
		}
	})

	// Tolerating the *empty* body does not mean tolerating a broken one:
	// express.json() rejects malformed JSON too, and accepting it would apply a
	// typo'd payload as "change nothing".
	t.Run("a malformed body is refused", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, csrf := loginSession(t, env, "brokenprofile@example.com")

		req := Replay(rawRequest(env, http.MethodPatch, "/profile", `{"firstName":`), login)
		req.Header.Set(auth.CSRFHeaderName, csrf)
		AssertError(t, env.Do(req), http.StatusBadRequest, "Invalid request body", auth.CodeInvalidBody)
	})

	// The reference enforces CSRF inside its auth middleware, *after* the access
	// token has been extracted, so an unauthenticated PATCH is refused with
	// "No access token provided" and no code — it never reaches the CSRF branch
	// (auth.middleware.ts:29-32 then :33-42). The port keeps its CSRF middleware in
	// front of the auth middleware, which is what makes the cookie auto-init
	// router-level as the reference's is, and recovers the ordering by scoping
	// enforcement to requests that carry an access-token cookie. This used to be a
	// pinned deviation answering CSRF_INVALID.
	t.Run("without a token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPatch, "/profile", map[string]string{"firstName": "Nobody"}))
		AssertError(t, rec, http.StatusForbidden, "No access token provided", "")
	})
}

// rawRequest builds a request with a body this suite controls byte for byte,
// which env.Request cannot do because it marshals.
func rawRequest(env *Env, method, route, body string) *http.Request {
	req := httptest.NewRequest(method, env.Config.Prefix()+route, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func testAddPhone(t *testing.T, mount Mounter) {
	t.Run("bearer mode", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("phone@example.com")

		req := env.Request(http.MethodPost, "/add-phone", map[string]string{"phoneNumber": "+390123456789"})
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success")
		if body["success"] != true {
			t.Fatalf("success = %v", body["success"])
		}

		me := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/me", tokens.AccessToken))
		if Body(t, me)["phoneNumber"] != "+390123456789" {
			t.Fatalf("phone not stored: %s", me.Body.String())
		}
	})

	t.Run("cookie mode with a matching X-CSRF-Token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, csrf := loginSession(t, env, "phonecookie@example.com")

		req := Replay(env.Request(http.MethodPost, "/add-phone", map[string]string{"phoneNumber": "+390000000000"}), login)
		req.Header.Set(auth.CSRFHeaderName, csrf)
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		if me := meBody(t, env, login); me["phoneNumber"] != "+390000000000" {
			t.Fatalf("phone not stored: %v", me["phoneNumber"])
		}
	})

	// Stored as sent (#35): the reference passes the body value to
	// userStore.updatePhoneNumber untouched (awesome-node-auth v1.10.8
	// auth.router.ts:1229-1234). A number of only whitespace is a stored value
	// there, not a clear — null is the clear — so it is one here too.
	for _, number := range []string{" +39 012 345 ", " "} {
		t.Run("stored as sent: "+strconv.Quote(number), func(t *testing.T) {
			env := NewEnv(t, mount, auth.DefaultHTTPConfig())
			_, tokens := env.Seed("spacedphone@example.com")

			req := env.Request(http.MethodPost, "/add-phone", map[string]string{"phoneNumber": number})
			req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
			rec := env.Do(req)
			AssertStatus(t, rec, http.StatusOK)
			AssertKeys(t, Body(t, rec), "success")

			me := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/me", tokens.AccessToken))
			if got := Body(t, me)["phoneNumber"]; got != number {
				t.Fatalf("phoneNumber = %q, want %q stored as sent", got, number)
			}
		})
	}

	t.Run("cookie mode without X-CSRF-Token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, _ := loginSession(t, env, "phonecsrf@example.com")

		req := Replay(env.Request(http.MethodPost, "/add-phone", map[string]string{"phoneNumber": "+391111111111"}), login)
		AssertError(t, env.Do(req), http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)
		if me := meBody(t, env, login); me["phoneNumber"] != nil {
			t.Fatalf("the rejected request still wrote the phone number: %v", me["phoneNumber"])
		}
	})

	// The missing-header case above cannot tell a real comparison from "any header
	// passes"; this one can.
	t.Run("cookie mode with a mismatched X-CSRF-Token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, _ := loginSession(t, env, "phonemismatch@example.com")

		req := Replay(env.Request(http.MethodPost, "/add-phone", map[string]string{"phoneNumber": "+392222222222"}), login)
		req.Header.Set(auth.CSRFHeaderName, "0123456789abcdef0123456789abcdef")
		AssertError(t, env.Do(req), http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)
		if me := meBody(t, env, login); me["phoneNumber"] != nil {
			t.Fatalf("the rejected request still wrote the phone number: %v", me["phoneNumber"])
		}
	})

	// Same express.json() reasoning as PATCH /profile: a bodyless POST reads
	// phoneNumber off {} and answers 200 rather than 400. What the reference then
	// stores is genuinely undefined — it hands `undefined` to a store method typed
	// `string | null` — so only the status is pinned here, but it has to be the
	// same status on all four adapters.
	t.Run("a bodyless POST is accepted", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("bodylessphone@example.com")

		req := env.Request(http.MethodPost, "/add-phone", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
	})

	t.Run("a malformed body is refused", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("brokenphone@example.com")

		req := rawRequest(env, http.MethodPost, "/add-phone", `{"phoneNumber":`)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		AssertError(t, env.Do(req), http.StatusBadRequest, "Invalid request body", auth.CodeInvalidBody)
	})
}

func testDeleteAccount(t *testing.T, mount Mounter) {
	t.Run("cookie mode with a matching X-CSRF-Token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("delete@example.com")
		// A second credential for the same user, so that the cleanup can be
		// checked against a session the deleting request did not present.
		login := env.Do(env.Request(http.MethodPost, "/login", credentials("delete@example.com")))
		AssertStatus(t, login, http.StatusOK)
		csrf := Cookie(t, login, hostCSRF).Value

		req := Replay(httptest.NewRequest(http.MethodDelete, env.Config.Prefix()+"/account", nil), login)
		req.Header.Set(auth.CSRFHeaderName, csrf)
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success")
		if body["success"] != true {
			t.Fatalf("success = %v", body["success"])
		}
		// Every name variant is expired, exactly as logout does: a deleted
		// account must not leave the browser holding a credential.
		for _, name := range []string{
			hostAccess, "__Secure-accessToken", "accessToken",
			hostRefresh, "__Secure-refreshToken", "refreshToken",
			hostCSRF, "__Secure-csrf-token", "csrf-token",
		} {
			AssertCleared(t, rec, name)
		}

		// The user record is gone, so the access token no longer resolves.
		me := env.Do(Replay(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil), login))
		AssertError(t, me, http.StatusForbidden, "Invalid or expired access token", "")

		// And the session was revoked before the record was deleted, so the
		// refresh credential reports the family's fast-logout code.
		refresh := env.Do(Replay(httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/refresh", nil), login))
		AssertError(t, refresh, http.StatusUnauthorized, "Session has been revoked", auth.CodeSessionRevoked)
	})

	t.Run("cookie mode without X-CSRF-Token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, _ := loginSession(t, env, "deletecsrf@example.com")

		req := Replay(httptest.NewRequest(http.MethodDelete, env.Config.Prefix()+"/account", nil), login)
		AssertError(t, env.Do(req), http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)
		// The account survived the refused request.
		if me := meBody(t, env, login); me["email"] != "deletecsrf@example.com" {
			t.Fatalf("account was deleted by a request that was refused: %v", me["email"])
		}
	})

	// The one route that writes cookies to a bearer caller. §3.11 says the
	// clearTokenCookies call runs regardless of transport ("the Set-Cookie clears
	// are sent regardless (harmless to native clients)"), so this is the documented
	// exception to "bearer requests set no cookies" and needs its own row —
	// otherwise a future tightening of that rule would silently leave a browser
	// that authenticated by header holding live cookies for a deleted account.
	t.Run("bearer mode", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("deletebearer@example.com")

		rec := env.Do(bearerRequest(http.MethodDelete, env.Config.Prefix()+"/account", tokens.AccessToken))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		for _, name := range []string{
			hostAccess, "__Secure-accessToken", "accessToken",
			hostRefresh, "__Secure-refreshToken", "refreshToken",
			hostCSRF, "__Secure-csrf-token", "csrf-token",
		} {
			AssertCleared(t, rec, name)
		}

		me := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/me", tokens.AccessToken))
		AssertError(t, me, http.StatusForbidden, "Invalid or expired access token", "")
	})

	// No credential at all: the reference's authMiddleware answers
	// 403 {"error":"No access token provided"} with no code, the same precedence
	// PATCH /profile pins above. What matters most for the route is the second
	// half — nothing was deleted, whichever gate refused the request.
	t.Run("without a credential", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, _ := loginSession(t, env, "deletenocred@example.com")

		rec := env.Do(httptest.NewRequest(http.MethodDelete, env.Config.Prefix()+"/account", nil))
		AssertError(t, rec, http.StatusForbidden, "No access token provided", "")
		if me := meBody(t, env, login); me["email"] != "deletenocred@example.com" {
			t.Fatalf("an unauthenticated DELETE removed the account: %v", me["email"])
		}
	})
}

// A user store that cannot write the profile, the phone number or the deletion
// reports the missing capability rather than answering 200 without writing. The
// reference answers 501 here too, with its own per-method message.
func testAccountCapabilityGate(t *testing.T, mount Mounter) {
	for _, tc := range []struct {
		name   string
		method string
		route  string
		body   any
	}{
		{name: "PATCH /profile", method: http.MethodPatch, route: "/profile", body: map[string]string{"firstName": "Mario"}},
		{name: "POST /add-phone", method: http.MethodPost, route: "/add-phone", body: map[string]string{"phoneNumber": "+3900"}},
		{name: "DELETE /account", method: http.MethodDelete, route: "/account", body: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(newBareUserStore()))
			_, tokens := env.Seed("gate@example.com")

			req := env.Request(tc.method, tc.route, tc.body)
			req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
			rec := env.Do(req)

			AssertError(t, rec, http.StatusNotImplemented, "Feature not supported by the configured stores", auth.CodeNotImplemented)
		})
	}
}
