package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// machineFixture is an Auth with an admin mount whose MachineAccess admits a
// request carrying X-Machine as the principal it names, and an event bus that
// records what is raised.
type machineFixture struct {
	auth   *Auth
	users  *MemoryUserStore
	cfg    HTTPConfig
	mu     sync.Mutex
	events []Event
	logged []string
}

func newMachineFixture(t *testing.T, policy *AdminAccessPolicy, tweak func(*AdminOptions)) *machineFixture {
	t.Helper()
	f := &machineFixture{users: NewMemoryUserStore()}
	bus := NewEventBus()
	bus.Subscribe(EventBusWildcard, func(ev Event) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.events = append(f.events, ev)
	})
	a, err := New(WithUserStore(f.users), WithEventBus(bus), WithBcryptCost(testBcryptCost),
		WithLogger(func(format string, args ...any) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.logged = append(f.logged, format)
		}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.auth = a
	f.cfg = DefaultHTTPConfig()
	f.cfg.Admin = AdminOptions{
		Enabled:      true,
		AccessPolicy: policy,
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

func (f *machineFixture) serve(method, path, body string, header map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "machine-test/1.0")
	req.RemoteAddr = "198.51.100.9:4242"
	for k, v := range header {
		req.Header[k] = []string{v}
	}
	rec := httptest.NewRecorder()
	f.auth.AdminHandler(f.cfg).ServeHTTP(rec, req)
	return rec
}

func (f *machineFixture) raised() []Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Event(nil), f.events...)
}

func denyAll() *AdminAccessPolicy {
	return AdminPredicate(func(context.Context, User, RolesPermissionsStore) (bool, error) { return false, nil })
}

// TestAdminMachineAccess pins the three outcomes of the function, its place
// ahead of the policy, the principal it installs and the audit event.
func TestAdminMachineAccess(t *testing.T) {
	t.Run("an admitted caller is granted, recorded and audited", func(t *testing.T) {
		f := newMachineFixture(t, denyAll(), nil)
		rec := f.serve(http.MethodGet, "/admin/api/users", "", map[string]string{"X-Machine": "svc:identity"})
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/users as a machine = %d %s", rec.Code, rec.Body.String())
		}
		events := f.raised()
		if len(events) != 1 {
			t.Fatalf("raised %v, want one %s", eventNamesOf(events), EventAdminMachineAccess)
		}
		ev := events[0]
		if ev.Name != EventAdminMachineAccess || ev.UserID != "" || ev.TenantID != "" {
			t.Errorf("event = %+v, want %s naming no user and no tenant", ev, EventAdminMachineAccess)
		}
		want := map[string]any{"principal": "svc:identity", "method": http.MethodGet, "path": "/api/users"}
		if len(ev.Data) != len(want) {
			t.Errorf("data = %v, want exactly %v", ev.Data, want)
		}
		for k, v := range want {
			if ev.Data[k] != v {
				t.Errorf("data[%q] = %v, want %v", k, ev.Data[k], v)
			}
		}
		if ev.IP != "198.51.100.9" || ev.UserAgent != "machine-test/1.0" {
			t.Errorf("provenance = %q / %q, want the request's", ev.IP, ev.UserAgent)
		}
	})

	t.Run("the handler sees the principal and no user", func(t *testing.T) {
		f := newMachineFixture(t, denyAll(), nil)
		guard := f.auth.AdminGuard(f.cfg)
		var principal string
		var machine, person bool
		h := guard.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, machine = AdminMachinePrincipalFromContext(r.Context())
			_, person = AdminUserFromContext(r.Context())
			w.WriteHeader(http.StatusNoContent)
		}))
		req := httptest.NewRequest(http.MethodGet, "/admin/api/ping", nil)
		req.Header.Set("X-Machine", "svc:identity")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent || !machine || principal != "svc:identity" || person {
			t.Fatalf("status %d, principal %q (%v), user %v", rec.Code, principal, machine, person)
		}
		if _, ok := AdminMachinePrincipalFromContext(context.Background()); ok {
			t.Error("a bare context reports a machine principal")
		}
	})

	t.Run("a declining function leaves the guard as it was", func(t *testing.T) {
		f := newMachineFixture(t, AdminIsAdminFlag(), nil)
		rec := f.serve(http.MethodGet, "/admin/api/users", "", nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("no credential = %d, want the guard's 401", rec.Code)
		}
		if len(f.raised()) != 0 {
			t.Errorf("a declined request was audited: %v", eventNamesOf(f.raised()))
		}
	})

	t.Run("a nil function is the guard as it was", func(t *testing.T) {
		f := newMachineFixture(t, AdminIsAdminFlag(), func(o *AdminOptions) { o.MachineAccess = nil })
		rec := f.serve(http.MethodGet, "/admin/api/users", "", map[string]string{"X-Machine": "svc:identity"})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("with no MachineAccess = %d, want the guard's 401", rec.Code)
		}
	})

	t.Run("an admission that names nobody grants nothing", func(t *testing.T) {
		f := newMachineFixture(t, AdminIsAdminFlag(), nil)
		rec := f.serve(http.MethodGet, "/admin/api/users", "", map[string]string{"X-Machine": ""})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("empty principal = %d, want the guard's 401", rec.Code)
		}
		if len(f.raised()) != 0 {
			t.Errorf("an anonymous admission was audited: %v", eventNamesOf(f.raised()))
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.logged) == 0 || !strings.Contains(f.logged[len(f.logged)-1], "without naming a principal") {
			t.Errorf("logged %v, want the empty principal reported", f.logged)
		}
	})

	t.Run("it is asked before the policy and before the legacy secret", func(t *testing.T) {
		f := newMachineFixture(t, nil, func(o *AdminOptions) { o.Secret = "legacy-shared-secret" })
		rec := f.serve(http.MethodGet, "/admin/api/users", "", map[string]string{"X-Machine": "svc:identity"})
		if rec.Code != http.StatusOK {
			t.Fatalf("machine caller under the legacy secret = %d, want 200 without the secret", rec.Code)
		}
	})

	t.Run("a machine write needs no cookie and no CSRF pair", func(t *testing.T) {
		f := newMachineFixture(t, denyAll(), nil)
		if _, err := f.users.CreateUser(context.Background(), User{ID: "usr_gone", Email: "gone@example.com", TenantID: "t1"}); err != nil {
			t.Fatal(err)
		}
		rec := f.serve(http.MethodDelete, "/admin/api/users/usr_gone", "", map[string]string{"X-Machine": "svc:identity"})
		if rec.Code != http.StatusOK {
			t.Fatalf("machine DELETE = %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("with no event bus the grant is logged instead", func(t *testing.T) {
		f := newMachineFixture(t, denyAll(), nil)
		f.auth.service.cfg.Events = nil
		rec := f.serve(http.MethodGet, "/admin/api/users", "", map[string]string{"X-Machine": "svc:identity"})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		if len(f.raised()) != 0 {
			t.Errorf("raised %v on a detached bus", eventNamesOf(f.raised()))
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.logged) == 0 || !strings.Contains(f.logged[len(f.logged)-1], "machine access granted") {
			t.Errorf("logged %v, want the grant recorded through Config.Logger", f.logged)
		}
	})

	t.Run("with an event bus the grant is not logged", func(t *testing.T) {
		f := newMachineFixture(t, denyAll(), nil)
		rec := f.serve(http.MethodGet, "/admin/api/users", "", map[string]string{"X-Machine": "svc:identity"})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, line := range f.logged {
			if strings.Contains(line, "machine access granted") {
				t.Errorf("logged %q beside the event", line)
			}
		}
	})

	t.Run("a request a browser originated is not offered to the function", func(t *testing.T) {
		// An operator's browser may hold the ambient credential the function
		// trusts — a client certificate, a network position — so a cross-site
		// form post must not become a machine call. The function is not asked,
		// and the request meets the session policy, here a 401.
		for name, header := range map[string]map[string]string{
			"Origin":                     {"Origin": "https://evil.example"},
			"Sec-Fetch-Site cross-site":  {"Sec-Fetch-Site": "cross-site"},
			"Sec-Fetch-Site same-site":   {"Sec-Fetch-Site": "same-site"},
			"Sec-Fetch-Site same-origin": {"Sec-Fetch-Site": "same-origin"},
		} {
			t.Run(name, func(t *testing.T) {
				asked := false
				f := newMachineFixture(t, AdminIsAdminFlag(), func(o *AdminOptions) {
					inner := o.MachineAccess
					o.MachineAccess = func(r *http.Request) (string, bool) {
						asked = true
						return inner(r)
					}
				})
				header["X-Machine"] = "svc:identity"
				rec := f.serve(http.MethodDelete, "/admin/api/users/usr_x", "", header)
				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("browser-originated machine call = %d %s, want the guard's 401", rec.Code, rec.Body.String())
				}
				if asked {
					t.Error("MachineAccess was asked about a browser-originated request")
				}
				if len(f.raised()) != 0 {
					t.Errorf("a refused request was audited: %v", eventNamesOf(f.raised()))
				}
			})
		}
		// A navigation the user typed (Sec-Fetch-Site: none) is not cross-site,
		// and is offered.
		f := newMachineFixture(t, denyAll(), nil)
		rec := f.serve(http.MethodGet, "/admin/api/users", "", map[string]string{"X-Machine": "svc:identity", "Sec-Fetch-Site": "none"})
		if rec.Code != http.StatusOK {
			t.Fatalf("Sec-Fetch-Site none = %d, want the machine grant", rec.Code)
		}
	})

	t.Run("the event is outside the reference's vocabulary", func(t *testing.T) {
		if IsEventName(EventAdminMachineAccess) {
			t.Errorf("%s is in EventNames, which is the reference's list alone", EventAdminMachineAccess)
		}
	})
}

// noLookupUserStore is MemoryUserStore's account, flag and listing writers
// without UserLookupStore.
type noLookupUserStore struct{ inner *MemoryUserStore }

func (s noLookupUserStore) CreateUser(ctx context.Context, u User) (User, error) {
	return s.inner.CreateUser(ctx, u)
}
func (s noLookupUserStore) GetUserByEmail(ctx context.Context, email, tenantID string) (User, error) {
	return s.inner.GetUserByEmail(ctx, email, tenantID)
}
func (s noLookupUserStore) GetUserByID(ctx context.Context, id, tenantID string) (User, error) {
	return s.inner.GetUserByID(ctx, id, tenantID)
}
func (s noLookupUserStore) UpdateProfile(ctx context.Context, id, tenantID, first, last string) (User, error) {
	return s.inner.UpdateProfile(ctx, id, tenantID, first, last)
}
func (s noLookupUserStore) DeleteUser(ctx context.Context, id, tenantID string) error {
	return s.inner.DeleteUser(ctx, id, tenantID)
}
func (s noLookupUserStore) UpdateIsAdmin(ctx context.Context, id, tenantID string, isAdmin bool) error {
	return s.inner.UpdateIsAdmin(ctx, id, tenantID, isAdmin)
}

// TestAdminUserWritesResolveTheTenant is the MI-05 fix: DELETE
// <admin>/api/users/{id} and promote with method=flag reach a user stored
// under a tenant, through UserLookupStore, and answer exactly as before when
// the store has no lookup or no tenant holds the id.
func TestAdminUserWritesResolveTheTenant(t *testing.T) {
	ctx := context.Background()
	open := DefaultHTTPConfig()
	open.Admin = AdminOptions{Enabled: true, AccessPolicy: AdminOpen()}
	serve := func(a *Auth, method, path, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		a.AdminHandler(open).ServeHTTP(rec, req)
		return rec.Code
	}

	t.Run("with a lookup store", func(t *testing.T) {
		users := NewMemoryUserStore()
		a, err := newTestAuth(WithUserStore(users))
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"usr_del", "usr_flag"} {
			if _, err := users.CreateUser(ctx, User{ID: id, Email: id + "@example.com", TenantID: "t1"}); err != nil {
				t.Fatal(err)
			}
		}
		if code := serve(a, http.MethodDelete, "/admin/api/users/usr_del", ""); code != http.StatusOK {
			t.Fatalf("DELETE a user in t1 = %d, want 200", code)
		}
		if _, err := users.FindUserByID(ctx, "usr_del"); err == nil {
			t.Fatal("the user in t1 survived the delete")
		}
		if code := serve(a, http.MethodPost, "/admin/users/usr_flag/promote", `{"method":"flag"}`); code != http.StatusOK {
			t.Fatalf("promote a user in t1 = %d, want 200", code)
		}
		if u, _ := users.FindUserByID(ctx, "usr_flag"); !u.IsAdmin {
			t.Fatal("the flag was not written on the row in t1")
		}
		// An id no tenant holds keeps the store's own answer.
		if code := serve(a, http.MethodDelete, "/admin/api/users/usr_nobody", ""); code != http.StatusInternalServerError {
			t.Errorf("DELETE an unknown id = %d, want the store's 500 as before", code)
		}
		if code := serve(a, http.MethodPost, "/admin/users/usr_nobody/promote", `{"method":"flag"}`); code != http.StatusInternalServerError {
			t.Errorf("promote an unknown id = %d, want the store's 500 as before", code)
		}
	})

	t.Run("without one, the empty tenant as before", func(t *testing.T) {
		inner := NewMemoryUserStore()
		a, err := newTestAuth(WithUserStore(noLookupUserStore{inner}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := inner.CreateUser(ctx, User{ID: "usr_t1", Email: "t1@example.com", TenantID: "t1"}); err != nil {
			t.Fatal(err)
		}
		if code := serve(a, http.MethodDelete, "/admin/api/users/usr_t1", ""); code != http.StatusInternalServerError {
			t.Errorf("DELETE without a lookup store = %d, want the empty tenant's 500 as before", code)
		}
		if _, err := inner.FindUserByID(ctx, "usr_t1"); err != nil {
			t.Error("a store without a lookup had a user deleted in another tenant")
		}
	})
}
