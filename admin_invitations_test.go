package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

// The three admin invitation routes (admin_invitations.go): registered only
// with a store, behind the guard, never answering a token unless the
// deployment has no sender and says the caller delivers it, and attributing
// every invitation to the principal the guard admitted.

// adminInvitationFixture is an invitationFixture with an admin mount: a policy
// that admits the user "usr_admin" alone, and MachineAccess admitting a request
// that carries X-Machine as the principal it names.
type adminInvitationFixture struct {
	*invitationFixture
	cfg HTTPConfig
}

func newAdminInvitationFixture(t *testing.T, tweak func(*AdminOptions), opts ...Option) *adminInvitationFixture {
	t.Helper()
	f := &adminInvitationFixture{invitationFixture: newInvitationFixture(t, opts...)}
	f.cfg = DefaultHTTPConfig()
	f.cfg.Admin = AdminOptions{
		Enabled: true,
		AccessPolicy: AdminPredicate(func(_ context.Context, user User, _ RolesPermissionsStore) (bool, error) {
			return user.ID == "usr_admin", nil
		}),
		MachineAccess: func(r *http.Request) (string, bool) {
			values, ok := r.Header["X-Machine"]
			if !ok || len(values) == 0 {
				return "", false
			}
			return values[0], true
		},
	}
	if tweak != nil {
		tweak(&f.cfg.Admin)
	}
	return f
}

func (f *adminInvitationFixture) do(method, path, body string, header map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/admin"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "invitations-test/1.0")
	req.RemoteAddr = "198.51.100.7:4242"
	for k, v := range header {
		req.Header[k] = []string{v}
	}
	rec := httptest.NewRecorder()
	f.auth.AdminHandler(f.cfg).ServeHTTP(rec, req)
	return rec
}

func (f *adminInvitationFixture) machine(method, path, body string) *httptest.ResponseRecorder {
	return f.do(method, path, body, map[string]string{"X-Machine": "svc:identity"})
}

func decodeAdmin(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return body
}

func keysOf(body map[string]any) string {
	keys := make([]string, 0, len(body))
	for k := range body {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

func TestAdminInvitationRoutesExistOnlyWithAStore(t *testing.T) {
	a, err := newTestAuth()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cfg := DefaultHTTPConfig()
	cfg.Admin = AdminOptions{Enabled: true, AccessPolicy: AdminOpen()}
	serve := func(handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(method, "/admin"+path, strings.NewReader(body)))
		return rec
	}
	without := a.AdminHandler(cfg)
	if rec := serve(without, http.MethodPost, AdminInvitationsPath, `{"email":"x@example.com"}`); rec.Code != http.StatusNotFound {
		t.Errorf("POST without a store = %d", rec.Code)
	}
	if rec := serve(without, http.MethodDelete, AdminInvitationsPath+"/inv_1", ""); rec.Code != http.StatusNotFound {
		t.Errorf("DELETE without a store = %d", rec.Code)
	}
	// Without a store the path is the user detail route's, as it always was.
	rec := serve(without, http.MethodGet, AdminInvitationsPath, "")
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "User not found") {
		t.Errorf("GET without a store = %d %s, want the detail route's 404", rec.Code, rec.Body.String())
	}

	b, err := newTestAuth(WithInvitationStore(NewMemoryInvitationStore()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec = serve(b.AdminHandler(cfg), http.MethodGet, AdminInvitationsPath, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"invitations":[]`) {
		t.Errorf("GET with a store = %d %s, want the empty listing", rec.Code, rec.Body.String())
	}
	// Other methods on the collection are still nobody's.
	if rec := serve(b.AdminHandler(cfg), http.MethodPut, AdminInvitationsPath, "{}"); rec.Code != http.StatusNotFound {
		t.Errorf("PUT = %d", rec.Code)
	}
}

func TestAdminInvitationRoutesAreGuarded(t *testing.T) {
	f := newAdminInvitationFixture(t, nil)
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, AdminInvitationsPath, `{"email":"x@example.com"}`},
		{http.MethodGet, AdminInvitationsPath, ""},
		{http.MethodDelete, AdminInvitationsPath + "/inv_1", ""},
	} {
		if rec := f.do(tc.method, tc.path, tc.body, nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with no credential = %d, want 401", tc.method, tc.path, rec.Code)
		}
	}
	if _, err := f.users.GetUserByEmail(context.Background(), "x@example.com", ""); err == nil {
		t.Fatal("an unauthenticated invitation created an account")
	}
}

// TestAdminCreateInvitationRevealsTheTokenInOneCellOnly: of sender × option,
// only "no sender, option on" answers the token; "no sender, option off"
// refuses before creating anything.
func TestAdminCreateInvitationRevealsTheTokenInOneCellOnly(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sender     bool
		reveal     bool
		wantStatus int
		wantToken  bool
	}{
		{"sender, option off", true, false, http.StatusCreated, false},
		{"sender, option on", true, true, http.StatusCreated, false},
		{"no sender, option on", false, true, http.StatusCreated, true},
		{"no sender, option off", false, false, http.StatusNotImplemented, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAdminInvitationFixture(t, func(o *AdminOptions) { o.RevealInvitationToken = tc.reveal },
				WithSiteURLs("https://console.example.com"))
			if !tc.sender {
				f.svc().cfg.SendInvitation = nil
			}
			rec := f.machine(http.MethodPost, AdminInvitationsPath, `{"email":"invitee@example.com","tenantId":"t1","role":"operator"}`)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d %s, want %d", rec.Code, rec.Body.String(), tc.wantStatus)
			}
			body := decodeAdmin(t, rec)
			if tc.wantStatus == http.StatusNotImplemented {
				if body["error"] != "Invitation delivery is not configured" {
					t.Errorf("body = %v", body)
				}
				if _, err := f.users.GetUserByEmail(context.Background(), invitedEmail, "t1"); err == nil {
					t.Error("an account was created for an invitation nobody can deliver")
				}
				return
			}
			want := "email,expiresAt,invitationId,success,userId"
			if tc.wantToken {
				want = "acceptUrl,email,expiresAt,invitationId,success,token,userId"
			}
			if got := keysOf(body); got != want {
				t.Fatalf("keys = %s, want %s", got, want)
			}
			if !tc.wantToken {
				if strings.Contains(rec.Body.String(), f.deliveries[0].Token) {
					t.Fatal("the delivered token is in the answer")
				}
				return
			}
			token, _ := body["token"].(string)
			if token == "" || body["acceptUrl"] != "https://console.example.com/auth/invitations/accept?token="+token {
				t.Fatalf("token/acceptUrl = %v / %v", body["token"], body["acceptUrl"])
			}
			// The revealed token is the real one.
			if _, err := f.accept(token, "a-new-password"); err != nil {
				t.Fatalf("accept with the revealed token: %v", err)
			}
		})
	}
}

func TestAdminCreateInvitationAnswers(t *testing.T) {
	t.Run("created, then 409 for the same address", func(t *testing.T) {
		f := newAdminInvitationFixture(t, nil)
		rec := f.machine(http.MethodPost, AdminInvitationsPath, `{"email":"Invitee@Example.com","tenantId":"t1","role":"operator","metadata":{"team":"ops"},"emailLang":"it"}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
		}
		body := decodeAdmin(t, rec)
		if body["email"] != invitedEmail || !strings.HasPrefix(body["invitationId"].(string), "inv_") || !strings.HasPrefix(body["userId"].(string), "usr_") {
			t.Errorf("body = %v", body)
		}
		d := f.deliveries[0]
		if d.Lang != "it" || d.Role != "operator" || d.Metadata["team"] != "ops" || d.TenantID != "t1" {
			t.Errorf("delivery = %+v", d)
		}
		rec = f.machine(http.MethodPost, AdminInvitationsPath, `{"email":"invitee@example.com","tenantId":"t1"}`)
		if rec.Code != http.StatusConflict || decodeAdmin(t, rec)["error"] != "User already exists" {
			t.Fatalf("second create = %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("re-invite answers 200 with the same account", func(t *testing.T) {
		f := newAdminInvitationFixture(t, nil, WithInvitationReinvite(true))
		first := decodeAdmin(t, f.machine(http.MethodPost, AdminInvitationsPath, `{"email":"invitee@example.com"}`))
		rec := f.machine(http.MethodPost, AdminInvitationsPath, `{"email":"invitee@example.com"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("re-invite = %d %s", rec.Code, rec.Body.String())
		}
		second := decodeAdmin(t, rec)
		if second["userId"] != first["userId"] || second["invitationId"] == first["invitationId"] {
			t.Fatalf("first %v, second %v", first, second)
		}
	})

	t.Run("400 without an address, whatever the body", func(t *testing.T) {
		f := newAdminInvitationFixture(t, nil)
		for _, body := range []string{"", "{}", `{"email":"  "}`, "not json", `{"email":42}`} {
			rec := f.machine(http.MethodPost, AdminInvitationsPath, body)
			if rec.Code != http.StatusBadRequest || decodeAdmin(t, rec)["error"] != "Email is required" {
				t.Errorf("body %q = %d %s", body, rec.Code, rec.Body.String())
			}
		}
	})

	t.Run("502 when the send fails, and the call can be repeated", func(t *testing.T) {
		f := newAdminInvitationFixture(t, nil)
		f.sendErr = errors.New("gateway down")
		rec := f.machine(http.MethodPost, AdminInvitationsPath, `{"email":"invitee@example.com"}`)
		if rec.Code != http.StatusBadGateway || decodeAdmin(t, rec)["error"] != "Invitation could not be delivered" {
			t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "gateway down") {
			t.Error("the sender's error reached the caller")
		}
		f.sendErr = nil
		if rec := f.machine(http.MethodPost, AdminInvitationsPath, `{"email":"invitee@example.com"}`); rec.Code != http.StatusCreated {
			t.Fatalf("retry = %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("501 for a store without the capabilities", func(t *testing.T) {
		f := newAdminInvitationFixture(t, nil)
		f.svc().users = narrowUserStore{f.users}
		rec := f.machine(http.MethodPost, AdminInvitationsPath, `{"email":"invitee@example.com"}`)
		if rec.Code != http.StatusNotImplemented || decodeAdmin(t, rec)["error"] != "UserStore does not implement UserPasswordStore" {
			t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
		}
	})
}

// TestAdminInvitationAudit: the invitation and its event name who invited —
// the machine principal or the signed-in user — and a machine call also
// leaves the guard's own audit event, with the request's provenance.
func TestAdminInvitationAudit(t *testing.T) {
	t.Run("a machine principal", func(t *testing.T) {
		f := newAdminInvitationFixture(t, nil)
		rec := f.machine(http.MethodPost, AdminInvitationsPath, `{"email":"invitee@example.com"}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
		}
		pending, _ := f.store.ListPendingInvitations(context.Background(), 10, 0)
		if len(pending) != 1 || pending[0].InvitedBy != "svc:identity" || pending[0].InvitedByKind != InvitedByMachine {
			t.Fatalf("record = %+v, want the machine principal", pending)
		}
		events := f.raised()
		if names := strings.Join(eventNamesOf(events), ","); names != EventAdminMachineAccess+","+EventUserInvited {
			t.Fatalf("raised %s, want the guard's audit, then the invitation", names)
		}
		invited := events[1]
		if invited.Data["invitedBy"] != "svc:identity" || invited.Data["invitedByKind"] != InvitedByMachine {
			t.Errorf("invited data = %v", invited.Data)
		}
		if invited.IP != "198.51.100.7" || invited.UserAgent != "invitations-test/1.0" {
			t.Errorf("provenance = %q / %q, want the request's", invited.IP, invited.UserAgent)
		}
	})

	t.Run("a signed-in administrator", func(t *testing.T) {
		f := newAdminInvitationFixture(t, nil)
		ctx := context.Background()
		hash, _ := hashPassword("admin-password", testBcryptCost)
		if _, err := f.users.CreateUser(ctx, User{ID: "usr_admin", Email: "admin@example.com", PasswordHash: hash, IsEmailVerified: true}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		_, tokens, err := f.auth.Login(ctx, LoginInput{Email: "admin@example.com", Password: "admin-password"})
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		bearer := map[string]string{"Authorization": "Bearer " + tokens.AccessToken}
		rec := f.do(http.MethodPost, AdminInvitationsPath, `{"email":"invitee@example.com"}`, bearer)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
		}
		pending, _ := f.store.ListPendingInvitations(ctx, 10, 0)
		if len(pending) != 1 || pending[0].InvitedBy != "usr_admin" || pending[0].InvitedByKind != InvitedByUser {
			t.Fatalf("record = %+v, want the administrator", pending)
		}
		rec = f.do(http.MethodDelete, AdminInvitationsPath+"/"+pending[0].ID, "", bearer)
		if rec.Code != http.StatusOK {
			t.Fatalf("revoke = %d %s", rec.Code, rec.Body.String())
		}
		var revoked *Event
		for _, ev := range f.raised() {
			if ev.Name == EventUserInvitationRevoked {
				ev := ev
				revoked = &ev
			}
		}
		if revoked == nil || revoked.Data["revokedBy"] != "usr_admin" || revoked.Data["revokedByKind"] != InvitedByUser {
			t.Fatalf("revoked event = %+v", revoked)
		}
	})
}

func TestAdminListInvitations(t *testing.T) {
	f := newAdminInvitationFixture(t, nil)
	start := time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)
	at := func(d time.Duration) { f.svc().now = func() time.Time { return start.Add(d) } }
	at(0)
	first := f.invite("first@example.com")
	at(time.Hour)
	second := f.invite("second@example.com")
	accepted := f.invite("accepted@example.com")
	if _, err := f.accept(accepted.Token, "a-new-password"); err != nil {
		t.Fatalf("accept: %v", err)
	}
	// By the clock the listing reads, the first is past its lifetime and the
	// second is not.
	at(DefaultInvitationTTL + time.Second)

	rec := f.machine(http.MethodGet, AdminInvitationsPath, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d %s", rec.Code, rec.Body.String())
	}
	for _, secret := range []string{first.Token, second.Token, first.Invitation.TokenHash, second.Invitation.TokenHash, "tokenHash", `"token"`} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("the listing carries %q: %s", secret, rec.Body.String())
		}
	}
	body := decodeAdmin(t, rec)
	rows, _ := body["invitations"].([]any)
	if len(rows) != 2 || body["total"] != float64(2) {
		t.Fatalf("listing = %v, want the two pending, not the accepted one", body)
	}
	row := rows[0].(map[string]any)
	if got := keysOf(row); got != "createdAt,email,expiresAt,id,invitedBy,invitedByKind,metadata,role,status,tenantId,userId" {
		t.Errorf("row keys = %s", got)
	}
	statuses := map[string]any{}
	for _, r := range rows {
		statuses[r.(map[string]any)["email"].(string)] = r.(map[string]any)["status"]
	}
	if statuses["first@example.com"] != "expired" || statuses["second@example.com"] != "pending" {
		t.Errorf("statuses = %v, want the first expired and the second pending", statuses)
	}

	paged := decodeAdmin(t, f.machine(http.MethodGet, AdminInvitationsPath+"?limit=1&offset=0", ""))
	if rows, _ := paged["invitations"].([]any); len(rows) != 1 || paged["total"] != float64(2) {
		t.Errorf("first page = %v, want one row and the best-effort total", paged)
	}
}

func TestAdminRevokeInvitation(t *testing.T) {
	f := newAdminInvitationFixture(t, nil)
	result := f.invite(invitedEmail)
	rec := f.machine(http.MethodDelete, AdminInvitationsPath+"/"+result.Invitation.ID, "")
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"accountRemoved":true,"success":true}` {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body.String())
	}
	rec = f.machine(http.MethodDelete, AdminInvitationsPath+"/"+result.Invitation.ID, "")
	if rec.Code != http.StatusConflict || decodeAdmin(t, rec)["error"] != "Invitation is no longer pending" {
		t.Fatalf("second revoke = %d %s", rec.Code, rec.Body.String())
	}
	rec = f.machine(http.MethodDelete, AdminInvitationsPath+"/inv_unknown", "")
	if rec.Code != http.StatusNotFound || decodeAdmin(t, rec)["error"] != "Invitation not found" {
		t.Fatalf("unknown = %d %s", rec.Code, rec.Body.String())
	}
	// A longer path is nobody's.
	if rec := f.machine(http.MethodDelete, AdminInvitationsPath+"/inv_1/more", ""); rec.Code != http.StatusNotFound {
		t.Errorf("DELETE with a tail = %d", rec.Code)
	}
}
