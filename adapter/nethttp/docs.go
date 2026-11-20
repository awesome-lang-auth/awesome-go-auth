package nethttp

import (
	"net/http"

	auth "github.com/nik2208/awesome-go-auth"
)

// The documentation group: the generated OpenAPI document and the Swagger UI
// page that reads it, mounted under HTTPConfig.Docs.Enabled
// (auth.router.ts:1651-1677). The handlers themselves are auth.OpenAPIHandler
// and auth.SwaggerUIHandler; what this file adds is the one thing an adapter
// knows and the root package does not — how this instance was mounted.
//
// As with every other group, the handlers are written once here and the chi,
// gin and echo mounts re-register these.

// OpenAPIInfo is the document this adapter describes: its own mount, read off
// the HTTPConfig it was built with and the Auth behind it.
//
// It is exported because a host that serves the document from its own route, or
// writes it to a file at build time, needs exactly this value. APIPrefix is the
// documented base path: the mount prefix, unless DocsOptions.BasePath moves the
// description somewhere else — which is what that option is for, so this one
// field is allowed to differ from the mount and says so. IDProvider, JWKSPath,
// ResourceServer and ClosedRegistration are read off the mount itself and
// cannot disagree with it.
// Title, Description, Version and ServerURL are left at their defaults: they
// name the host's API, not this library, so a caller that wants them fills them
// in on the copy.
func (a *Adapter) OpenAPIInfo() auth.OpenAPIInfo {
	info := auth.OpenAPIInfo{
		APIPrefix:          a.cfg.DocsBasePath(),
		ResourceServer:     a.cfg.ResourceServer,
		ClosedRegistration: a.cfg.ClosedRegistration,
		Docs:               a.cfg.Docs.Enabled,
	}
	if idp := a.auth.IDP(); idp != nil {
		info.IDProvider = true
		info.JWKSPath = idp.JWKSPath()
	}
	return info
}

// OpenAPIHandler serves GET <prefix>/openapi.json: the document for this mount,
// as application/json (auth.router.ts:1658-1671).
//
// It goes through guard, like every other route of this adapter bar the JWKS
// one, and for the reason spelled out there: the reference's routes carry no
// guard of their own, but its router-level CSRF auto-init is a router.use
// registered at auth.router.ts:529-538 — about eleven hundred lines before
// these two — and Express runs every earlier use-layer for a route registered
// after it. So a bare GET of either documentation route answers with a fresh
// csrf-token cookie there when csrf is enabled, and answers with one here.
// Nothing can be rejected on the way in: csrfEnforced passes every non-mutating
// method straight through, so a GET or a HEAD only ever reaches the cookie
// distribution half of the middleware.
func (a *Adapter) OpenAPIHandler() http.Handler {
	return a.guard(auth.OpenAPIHandler(a.OpenAPIInfo()))
}

// SwaggerUIHandler serves GET <prefix>/docs: the reference's Swagger UI page,
// pointed at the document next door (auth.router.ts:1674-1677). The spec URL is
// built from DocsOptions.BasePath, as the reference builds it from
// swaggerBasePath (:1657, :1676), so a deployment that is reachable under
// another path from outside hands the page a URL its readers can fetch.
//
// Through guard, for the same reason OpenAPIHandler is — and with the same
// consequence, since the page is fetched with GET.
func (a *Adapter) SwaggerUIHandler() http.Handler {
	return a.guard(auth.SwaggerUIHandler(a.cfg.DocsBasePath() + auth.DocsSpecPath))
}
