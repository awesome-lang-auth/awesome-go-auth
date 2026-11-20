package wiretest

import (
	"context"
	"net/http"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// Machine access to the admin API (admin_machine.go in the root package), and
// the two user writes that resolve their tenant through UserLookupStore.
//
// The function under test trusts a header, which is what a deployment does
// when a gateway in front of it verified the caller and injected the result;
// the header is a stand-in for that guarantee, not a recommendation to trust a
// header an internet caller can set.

const machineHeader = "X-Wiretest-Machine"

// headerMachineAccess admits a request that carries machineHeader, as the
// principal the header names — an empty value included, which is the "admits
// but names nobody" case.
func headerMachineAccess(r *http.Request) (string, bool) {
	values, ok := r.Header[http.CanonicalHeaderKey(machineHeader)]
	if !ok || len(values) == 0 {
		return "", false
	}
	return values[0], true
}

// machineOptions is a console no person can enter — a predicate that admits
// no session — with the machine path beside it: the deployment the field's
// documentation describes for machine-only access.
func machineOptions() auth.AdminOptions {
	return auth.AdminOptions{
		Enabled: true,
		AccessPolicy: auth.AdminPredicate(func(context.Context, auth.User, auth.RolesPermissionsStore) (bool, error) {
			return false, nil
		}),
		MachineAccess: headerMachineAccess,
	}
}

func (e *adminEnv) machineRequest(method, route, body, principal string) *http.Request {
	req := e.adminRequest(method, route, body)
	req.Header.Set(machineHeader, principal)
	return req
}

func testAdminMachineAccess(t *testing.T, mount Mounter) {
	seeds := []adminSeed{
		{email: "staff-a@wiretest.example", tenantID: "t1"},
		{email: "staff-b@wiretest.example", tenantID: "t1"},
	}

	t.Run("a machine caller reaches the guarded routes, and nobody else does", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{admin: machineOptions(), seeds: seeds})
		rec := env.Do(env.machineRequest(http.MethodGet, auth.AdminUsersPath, "", "svc:identity"))
		AssertStatus(t, rec, http.StatusOK)
		if users := adminEntries(t, Body(t, rec), "users"); len(users) != 2 {
			t.Errorf("users = %v, want the two seeded in tenant t1", users)
		}
		// Without the credential the policy decides, and it admits nobody.
		AssertError(t, env.Do(env.adminRequest(http.MethodGet, auth.AdminUsersPath, "")),
			http.StatusUnauthorized, "Unauthorized", "")
		// A function that admits the request without naming a principal grants
		// nothing: an audit record that names nobody is not one.
		AssertError(t, env.Do(env.machineRequest(http.MethodGet, auth.AdminUsersPath, "", "")),
			http.StatusUnauthorized, "Unauthorized", "")
	})

	t.Run("a machine write needs no cookie and no CSRF pair, and reaches the user's tenant", func(t *testing.T) {
		users := auth.NewMemoryUserStore()
		env := newAdminEnv(t, mount, adminEnvOptions{admin: machineOptions(), seeds: seeds,
			wrapUsers: func(m *auth.MemoryUserStore) auth.UserStore { users = m; return m }})

		// DELETE resolves the tenant through UserLookupStore: the user lives in
		// t1, and before this the route asked for the empty tenant and answered
		// 500 for a user the listing shows.
		rec := env.Do(env.machineRequest(http.MethodDelete, auth.AdminUsersPath+"/a-user", "", "svc:identity"))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		if _, err := users.FindUserByID(context.Background(), "a-user"); err == nil {
			t.Fatal("the user is still there after a 200 delete")
		}

		// promote with method=flag likewise writes the flag on the t1 row.
		rec = env.Do(env.machineRequest(http.MethodPost, adminPromotePath("b-user"), `{"method":"flag"}`, "svc:identity"))
		AssertStatus(t, rec, http.StatusOK)
		promoted, err := users.FindUserByID(context.Background(), "b-user")
		if err != nil || !promoted.IsAdmin {
			t.Fatalf("b-user = %+v, %v, want IsAdmin set on the row in t1", promoted, err)
		}

		// An id no tenant holds still gets the store's own answer.
		rec = env.Do(env.machineRequest(http.MethodDelete, auth.AdminUsersPath+"/nobody", "", "svc:identity"))
		AssertError(t, rec, http.StatusInternalServerError, "Internal server error", "")
	})

	t.Run("a request a browser originated is never a machine call", func(t *testing.T) {
		// An operator's browser can hold what the function trusts — a client
		// certificate, a network position — and a cross-site form post would
		// carry it. Such a request is not offered to the function: here the
		// policy admits nobody, so it is the guard's 401, and nothing is deleted.
		env := newAdminEnv(t, mount, adminEnvOptions{admin: machineOptions(), seeds: seeds})
		for name, header := range map[string][2]string{
			"Origin":         {"Origin", "https://attacker.example"},
			"Sec-Fetch-Site": {"Sec-Fetch-Site", "cross-site"},
		} {
			req := env.machineRequest(http.MethodDelete, auth.AdminUsersPath+"/a-user", "", "svc:identity")
			req.Header.Set(header[0], header[1])
			rec := env.Do(req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s: %d %s, want the guard's 401", name, rec.Code, rec.Body.String())
			}
		}
		rec := env.Do(env.machineRequest(http.MethodGet, auth.AdminUsersPath, "", "svc:identity"))
		AssertStatus(t, rec, http.StatusOK)
		if users := adminEntries(t, Body(t, rec), "users"); len(users) != 2 {
			t.Errorf("users = %v, want both seeds still there", users)
		}
	})

	t.Run("a function that declines leaves the session policy in charge", func(t *testing.T) {
		// The open policy, so the fall-through is visible as a grant: a request
		// the machine function does not admit is the request the guard always
		// saw.
		options := adminOpenOptions()
		options.MachineAccess = func(*http.Request) (string, bool) { return "", false }
		env := newAdminEnv(t, mount, adminEnvOptions{admin: options, seeds: seeds})
		AssertStatus(t, env.Do(env.adminRequest(http.MethodGet, auth.AdminUsersPath, "")), http.StatusOK)
	})
}
