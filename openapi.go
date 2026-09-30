package auth

import (
	"net/http"
	"strconv"
	"strings"
)

// The generated OpenAPI description of the mounted routes.
//
// It describes the contract the adapters actually serve — the same shapes
// wire.go, passwordless.go, wire_password_email.go, account.go and oauth_wire.go
// implement — rather than the pre-0.2.0 spec this file used to carry, which
// documented four routes nobody mounted and none of the ones added since.
//
// Two things keep it from drifting again: every path here is registered by
// Adapter.Mount, and the wiretest suite replays each documented operation
// against every adapter to prove it is not a 404. A spec that advertises an
// endpoint nobody serves is worse than a short one, and this one is now checked
// in both directions — see documentedRoutes in the suite.
//
// Routes the reference has and this port does not (the admin router) are absent.

// OpenAPIInfo holds metadata for the generated OpenAPI spec.
type OpenAPIInfo struct {
	Title       string
	Description string
	Version     string
	ServerURL   string
	// APIPrefix is where the routes are mounted. Empty means DefaultAPIPrefix,
	// and it must match the HTTPConfig the adapter was mounted with, otherwise
	// the spec documents paths the server does not serve.
	APIPrefix string
	// IDProvider adds the IdP's public JWKS route to the document. Set it when
	// the adapter was mounted on an Auth built WithIDP, and leave it false
	// otherwise: that route exists only under that configuration, so a document
	// that always carried it would advertise an endpoint most deployments
	// answer 404 for.
	IDProvider bool
	// JWKSPath is where that route is served below APIPrefix. Empty means
	// DefaultJWKSPath, and it must match the IDPConfig.JWKSPath of the IdP the
	// adapter was mounted with. Read only when IDProvider is true.
	//
	// A missing leading "/" is added, since the value is a path below the
	// prefix. A value that collides with a route this document already
	// describes is ignored rather than allowed to replace it, which would drop
	// a real endpoint from the spec; NewIDP refuses such a JWKSPath outright,
	// so the collision can only come from this field disagreeing with the IdP.
	JWKSPath string
	// OIDC adds the IdP's other four routes — the discovery document,
	// authorize, token and userinfo — to the document, at the fixed paths
	// OIDCDiscoveryPath, OIDCAuthorizePath, OIDCTokenPath and
	// OIDCUserInfoPath below APIPrefix. Set it when the adapter was mounted on
	// an Auth built WithIDP, and leave it false otherwise: those routes exist
	// only under that configuration, exactly as the JWKS route does.
	//
	// It is a second flag rather than more of IDProvider because the two
	// describe different things to different readers. IDProvider publishes a
	// key so that somebody else's resource server can verify this IdP's
	// tokens, and a deployment may well want that route documented and no
	// more — it is the only one a verifier calls. OIDC advertises an
	// authorization server a relying party is invited to drive. A deployment
	// that serves the OIDC endpoints on a mux of its own, through
	// (*IDP).RegisterHandlers under some other base path, leaves this false
	// and documents them where it mounted them.
	//
	// Unlike JWKSPath these paths are not configurable, so there is nothing to
	// tell this document; see the OIDC path constants.
	//
	// Setting ResourceServer alongside it drops OIDCAuthorizePath and
	// OIDCTokenPath again, because the adapters do not mount those two in that
	// mode; the discovery document and userinfo stay. See OIDCMount.
	OIDC bool

	// Docs mirrors HTTPConfig.Docs.Enabled: the two documentation routes the
	// adapters then mount, GET <prefix>/openapi.json and GET <prefix>/docs, are
	// described by the document too. Set the two together, or the spec omits
	// two routes the server serves — or documents two it does not.
	//
	// The reference's generator describes neither, under any option: it emits
	// the auth routes and stops (openapi.ts:68 onwards), so a document with
	// this flag carries two path items the reference's never has. That half of
	// the docs-routes-are-opt-in deviation is registered in compatibility.go.
	// A document that hid the endpoint it is served from would be a document
	// the conformance suite could not hold to the mount in both directions,
	// which is the check that keeps the rest of it honest.
	Docs bool
	// ResourceServer mirrors HTTPConfig.ResourceServer: the credential routes
	// the adapters then leave unmounted are left out of the spec too. Set the
	// two together, or the spec documents routes that answer 404.
	ResourceServer bool
	// UI mirrors HTTPConfig.UI.Enabled: it adds GET <prefix>/ui/config, the
	// document the built-in UI reads its branding and feature flags from. The
	// adapters mount that route only under that flag, so set the two together.
	UI bool
}

// GenerateOpenAPISpec returns an OpenAPI 3.0 spec for the mounted auth endpoints.
func GenerateOpenAPISpec(info OpenAPIInfo) map[string]any {
	if info.Title == "" {
		info.Title = "awesome-go-auth"
	}
	if info.Version == "" {
		info.Version = "1.0.0"
	}
	if info.Description == "" {
		info.Description = "Authentication & Authorization API"
	}

	servers := []map[string]any{}
	if info.ServerURL != "" {
		servers = append(servers, map[string]any{"url": info.ServerURL})
	}

	// The conditional groups — the JWKS route and the four OIDC endpoints an
	// IdP adds, the credential routes resource-server mode takes away — are all
	// in openAPIPathsFor. See OpenAPIInfo.IDProvider, OpenAPIInfo.OIDC and
	// OpenAPIInfo.ResourceServer, and the "jwks", "oidc" and "ResourceServer"
	// sets in the wiretest harness, which hold those flags and the adapters'
	// mounts to each other in both directions.
	paths := openAPIPathsFor(info)
	schemas := openAPISchemas()
	// The two schemas nothing but the JWKS path item references follow that
	// item rather than the flag: a JWKSPath colliding with a documented route
	// adds no item, and definitions nothing points at are worse than none.
	if openAPIDocumentsJWKS(info, paths) {
		for name, schema := range openAPIJWKSSchemas() {
			schemas[name] = schema
		}
	}

	return map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       info.Title,
			"description": info.Description,
			"version":     info.Version,
		},
		"servers": servers,
		"components": map[string]any{
			"securitySchemes": map[string]any{
				// Two ways to present the same access token, and the reason both
				// are listed: a bearer client sends the Authorization header, a
				// browser client sends the cookie the server set. The cookie name
				// shown is the default; it resolves to __Secure- or the bare name
				// under other cookie configurations (see CookieOptions.CookieName).
				"BearerAuth": map[string]any{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
				},
				"CookieAuth": map[string]any{
					"type": "apiKey",
					"in":   "cookie",
					"name": hostCookiePrefix + AccessTokenCookieName,
				},
				"ApiKeyAuth": map[string]any{
					"type": "apiKey",
					"in":   "header",
					"name": "X-Api-Key",
				},
			},
			"parameters": openAPIParameters(),
			"schemas":    schemas,
		},
		"paths": paths,
	}
}

// openAPIHasPath reports whether the document already describes this path, so a
// conditional group can leave a documented route alone instead of replacing it.
func openAPIHasPath(paths map[string]any, key string) bool {
	_, taken := paths[key]
	return taken
}

// openAPIJWKSRoute is where the JWKS document sits below the prefix for this
// info: OpenAPIInfo.JWKSPath, or DefaultJWKSPath when it is empty.
//
// The field is a path below the prefix, like every other path in this
// document. A caller who dropped the leading "/" meant the same path, and
// would otherwise get the nonsense <prefix>jwks.json, so normalise it rather
// than emit that.
func openAPIJWKSRoute(info OpenAPIInfo) string {
	path := info.JWKSPath
	if path == "" {
		path = DefaultJWKSPath
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

// openAPIJWKSOperationID identifies the JWKS path item, both in the document
// and to openAPIDocumentsJWKS.
const openAPIJWKSOperationID = "jwks"

// openAPIDocumentsJWKS reports whether the built paths really carry the JWKS
// path item, which is a narrower question than info.IDProvider: a JWKSPath
// that collides with a documented route leaves that route in place and adds
// nothing, and the schemas only that item references must not be shipped
// pointing at nothing.
func openAPIDocumentsJWKS(info OpenAPIInfo, paths map[string]any) bool {
	if !info.IDProvider {
		return false
	}
	item, ok := paths[openAPIPrefix(info.APIPrefix)+openAPIJWKSRoute(info)].(map[string]any)
	if !ok {
		return false
	}
	get, ok := item["get"].(map[string]any)
	return ok && get["operationId"] == openAPIJWKSOperationID
}

// openAPIJWKSPath describes GET <prefix><JWKSPath>, the IdP's public signing
// keys. It is a path item on its own because it is added conditionally.
func openAPIJWKSPath() map[string]any {
	return map[string]any{
		"get": map[string]any{
			"summary": "The IdP's public signing keys (JWKS)",
			"description": "Public: no credential, no CSRF, no session. Answers `Cache-Control: " +
				jwksCacheControl + "`, and `Access-Control-Allow-Origin: *` unless " +
				"`IDPConfig.JWKSCORSOrigins` restricts it, in which case a listed `Origin` is " +
				"echoed back and an unlisted one gets no such header. Mounted only when the " +
				"`Auth` was built with `WithIDP`.",
			"operationId": openAPIJWKSOperationID,
			"tags":        []string{"IdP"},
			"responses": map[string]any{
				"200": map[string]any{
					"description": "The signing keys",
					"content": map[string]any{
						"application/json": map[string]any{
							"schema": map[string]any{"$ref": "#/components/schemas/JWKS"},
						},
					},
					"headers": map[string]any{
						"Cache-Control": map[string]any{
							"description": "Always `" + jwksCacheControl + "`.",
							"schema":      map[string]any{"type": "string"},
						},
						"Access-Control-Allow-Origin": map[string]any{
							"description": "Absent when the request's `Origin` is not allowlisted. No " +
								"`Vary: Origin` is sent — the reference sends none either — so a response " +
								"produced under an allowlist must not be stored by a shared cache.",
							"schema": map[string]any{"type": "string"},
						},
					},
				},
			},
		},
	}
}

// openAPIPathsFor is openAPIPaths plus and minus what the configuration
// changes. Five things do so far: resource-server mode drops the credential
// routes, which is the same list the adapters skip registering
// (ResourceServerGatedRoutes), an IdP adds the JWKS route and the four OIDC
// endpoints — both mounted by the adapters from auth.WithIDP — an enabled UI
// adds the config route they mount from HTTPConfig.UI.Enabled, and the two
// documentation routes join them under HTTPConfig.Docs.Enabled, so the spec
// and the mount stay in step under any of them, or all of them.
//
// The subtraction runs first, in the order the adapters mount in: they
// register the JWKS route whether or not resource-server mode is on, and skip
// the credential routes it gates. A JWKSPath pointing at a gated route is
// therefore served by the JWKS handler in that mode, and this documents it
// that way; with the additions first the route would instead be deleted out
// from under the JWKS item.
func openAPIPathsFor(info OpenAPIInfo) map[string]any {
	prefix := openAPIPrefix(info.APIPrefix)
	paths := openAPIPaths(prefix)
	if info.ResourceServer {
		for route, method := range ResourceServerGatedRoutes() {
			removeOpenAPIOperation(paths, prefix+route, method)
		}
	}
	// A JWKSPath colliding with a route this document still describes would
	// otherwise replace it silently, dropping a real endpoint from the spec.
	// The documented route wins: it is the one the adapter certainly serves,
	// whereas a colliding JWKSPath is a misconfiguration the host has to see.
	if info.IDProvider {
		if key := prefix + openAPIJWKSRoute(info); !openAPIHasPath(paths, key) {
			paths[key] = openAPIJWKSPath()
		}
	}
	// The other four IdP routes, on the same terms — minus the two the adapters
	// skip under resource-server mode, which is the same oidcResourceServerGated
	// map they read. Their paths are constants, so none of them can collide with
	// a documented route today; the guard is kept anyway, so that a future route
	// named /token or /authorize is a missing path item here rather than a
	// silently replaced one.
	if info.OIDC {
		for route, item := range openAPIOIDCPaths() {
			if info.ResourceServer && oidcResourceServerGated[route] {
				continue
			}
			if key := prefix + route; !openAPIHasPath(paths, key) {
				paths[key] = item
			}
		}
	}
	// The UI config route sits below <prefix>/ui, which no unconditional route
	// uses, so there is nothing for it to collide with.
	if info.UI {
		paths[prefix+UIConfigRoute] = openAPIUIConfigPath()
	}
	// The two documentation routes, mounted last and added last, guarded the
	// same way and for the same reason. Their own paths are constants, but the
	// JWKSPath above is not: a host that points it at "/openapi.json" or
	// "/docs" collides with them, and the JWKS item — written first, as the
	// adapters mount that route first — must survive, exactly as a credential
	// route does. The collision is a misconfiguration the host has to see
	// rather than one this document papers over: on the mount side the same
	// pair of values is fatal, because net/http and chi both panic on a
	// duplicate pattern, so Mount crashes at startup.
	if info.Docs {
		if key := prefix + DocsSpecPath; !openAPIHasPath(paths, key) {
			paths[key] = openAPIDocsSpecPath()
		}
		if key := prefix + DocsUIPath; !openAPIHasPath(paths, key) {
			paths[key] = openAPIDocsUIPath()
		}
	}
	return paths
}

// openAPIOIDCPaths describes the four OIDC endpoints, keyed by the path below
// the mount prefix.
//
// Each carries exactly one operation: the method a relying party uses to drive
// the flow. The handlers answer any method — see OIDCMounts for why — but
// documenting a second one would describe the same handler twice, and the
// conformance suite compares a documented path to one method.
//
// The endpoints have no counterpart in the reference, which ships no OIDC
// authorization server, so nothing here is cited: it describes what idp.go's
// handlers do. That includes the unhappy paths. Those of authorize and
// userinfo are the standard library's http.Error — a plain-text line, not the
// family's JSON error envelope — and are documented as the text/plain bodies
// they are. Those of the token endpoint are the OAuth error body of RFC 6749
// §5.2, and are documented as that.
func openAPIOIDCPaths() map[string]any {
	jsonContent := func(s map[string]any) map[string]any {
		return map[string]any{"application/json": map[string]any{"schema": s}}
	}
	// text is one http.Error answer: a plain-text line, the OAuth 2.0 error
	// identifier where the handler uses one.
	text := func(description string) map[string]any {
		return map[string]any{
			"description": description,
			"content": map[string]any{
				"text/plain": map[string]any{"schema": map[string]any{"type": "string"}},
			},
		}
	}
	object := func(props map[string]any) map[string]any {
		return map[string]any{"type": "object", "properties": props}
	}
	str := map[string]any{"type": "string"}
	strs := map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
	// oauthError is one refusal of the token endpoint: the RFC 6749 §5.2 body.
	oauthError := func(description string) map[string]any {
		return map[string]any{
			"description": description,
			"content": jsonContent(map[string]any{
				"type":     "object",
				"required": []string{"error"},
				"properties": map[string]any{
					"error":             str,
					"error_description": str,
				},
			}),
		}
	}

	return map[string]any{
		OIDCDiscoveryPath: map[string]any{
			"get": map[string]any{
				"summary": "OIDC discovery document",
				"description": "Public: no credential, no CSRF, no session. Every URL in it is derived " +
					"from `IDPConfig.Issuer`, so `Issuer` has to carry the mount prefix for the " +
					"advertised endpoints to resolve; `jwks_uri` alone can be overridden, with " +
					"`IDPConfig.JWKSURL`. Mounted only when the `Auth` was built with `WithIDP`.",
				"operationId": "oidcDiscovery",
				"tags":        []string{"IdP"},
				"responses": map[string]any{
					"200": map[string]any{
						"description": "The discovery document",
						"content": jsonContent(object(map[string]any{
							"issuer":                                str,
							"authorization_endpoint":                str,
							"token_endpoint":                        str,
							"userinfo_endpoint":                     str,
							"jwks_uri":                              str,
							"response_types_supported":              strs,
							"subject_types_supported":               strs,
							"id_token_signing_alg_values_supported": strs,
							"scopes_supported":                      strs,
							"grant_types_supported":                 strs,
							"token_endpoint_auth_methods_supported": strs,
							"code_challenge_methods_supported":      strs,
							"claims_supported":                      strs,
						})),
					},
				},
			},
		},
		OIDCAuthorizePath: map[string]any{
			"get": map[string]any{
				"summary": "Authorization endpoint: the sign-in form",
				"description": "Public. `GET` renders a minimal HTML sign-in form; `POST` to the same " +
					"path, with `email`, `password` and `tenant_id` as form fields and the same query " +
					"string, checks the credentials and redirects to the registered `redirect_uri` with " +
					"`code` and the echoed `state`. Both refuse an unregistered `client_id` and a " +
					"`redirect_uri` that is not exactly one of that client's registered URIs. `code`, " +
					"`state`, `nonce`, `scope`, `code_challenge` and `code_challenge_method` are " +
					"recorded with the authorization code. PKCE is `S256` only: a `plain` method, a " +
					"challenge without a method (RFC 7636 §4.3 reads that as `plain`), a method without a " +
					"challenge, or a challenge that is not an unpadded base64url SHA-256 is answered with " +
					"the RFC 6749 §4.1.2.1 error redirect to the registered `redirect_uri`, carrying " +
					"`error=invalid_request`, `error_description` and `state`. `offline_access` in `scope` " +
					"is what makes the token endpoint issue a refresh token. A public client (registered with " +
					"no secret) must send an `S256` challenge, or it gets the same redirect. Mounted only when the `Auth` " +
					"was built with `WithIDP`.",
				"operationId": "oidcAuthorize",
				"tags":        []string{"IdP"},
				"parameters": []map[string]any{
					{"name": "client_id", "in": "query", "required": true, "schema": str},
					{"name": "redirect_uri", "in": "query", "required": true, "schema": str},
					{"name": "state", "in": "query", "required": false, "schema": str},
					{"name": "nonce", "in": "query", "required": false, "schema": str},
					{"name": "scope", "in": "query", "required": false, "schema": str},
					{"name": "code_challenge", "in": "query", "required": false, "schema": str},
					{"name": "code_challenge_method", "in": "query", "required": false, "schema": str},
				},
				"responses": map[string]any{
					"200": map[string]any{
						"description": "The sign-in form",
						"content": map[string]any{
							"text/html": map[string]any{"schema": map[string]any{"type": "string"}},
						},
					},
					"302": map[string]any{"description": "`POST`: to the registered `redirect_uri` with `code` and `state`. " +
						"`GET` or `POST` with unsupported PKCE parameters: to the same URI with `error=invalid_request`, " +
						"`error_description` and `state`."},
					"400": text("`unknown client`, or `redirect_uri not allowed`"),
				},
			},
		},
		OIDCTokenPath: map[string]any{
			"post": map[string]any{
				"summary": "Token endpoint: redeem an authorization code or a refresh token",
				"description": "Public, and authenticated by the client's own credentials, by exactly one " +
					"method: `client_secret_basic` (`Authorization: Basic`, id and secret each " +
					"form-urlencoded first, RFC 6749 §2.3.1), `client_secret_post` (`client_id` and " +
					"`client_secret` in the body), or, for a public client registered with no secret, " +
					"`none` (`client_id` alone; any secret it presents, even an empty one, is refused). Both " +
					"Basic and `client_secret` at once is `invalid_request`. `POST` only, any other method " +
					"is `405` with `Allow: POST`; the body is `application/x-www-form-urlencoded`, and a " +
					"`client_id`, `client_secret`, `code`, `code_verifier` or `refresh_token` in the URL " +
					"query is `invalid_request` (RFC 6749 §2.3.1, §3.2).\n\n" +
					"`grant_type=authorization_code` redeems `code`: single use, across processes when " +
					"`IDPConfig.Codes` is a shared store, issued to the same client, and with `redirect_uri` " +
					"identical to the authorization request's (RFC 6749 §4.1.3). A code issued with an " +
					"`S256` `code_challenge` needs the matching `code_verifier` (RFC 7636 §4.6); a " +
					"`code_verifier` sent for a code issued without one is refused as a PKCE downgrade " +
					"(RFC 9700 §2.1.1). A code presented a second time also revokes the session and refresh " +
					"tokens it produced when the code store is an `AuthCodeReplayStore` (RFC 6749 §4.1.2). " +
					"`access_token` is the HS256 session access token and `expires_in` its lifetime, " +
					"`Config.AccessTokenTTL`; `id_token` is the RS256 ID token, signed with " +
					"`IDPConfig.Signer` under `KeyID`. `refresh_token` is present only when the code was " +
					"granted `offline_access` (OIDC Core §11) and the grant is served, and it is an opaque " +
					"token for the grant below, not the session's own.\n\n" +
					"`grant_type=refresh_token` — served unless `IDPConfig.DisableRefreshTokenGrant` is set " +
					"or the session store cannot look sessions up, and advertised in discovery exactly then — " +
					"redeems `refresh_token` for a new access token of the same session and a new refresh " +
					"token: every token is single use, and one presented again, or by another client, or " +
					"once the session has ended, revokes every token of its grant. `scope` may narrow the " +
					"granted scope and not widen it; the answer carries the effective `scope`, and an " +
					"`id_token` while that scope includes `openid`. The family lives as long as the session, " +
					"`Config.RefreshTokenTTL`, and rotation does not extend it.\n\n" +
					"Every answer carries `Cache-Control: no-store` and `Pragma: no-cache`, and every " +
					"`invalid_grant` the same `error_description`, whatever the reason. " +
					"Mounted only when the `Auth` was built with `WithIDP`.",
				"operationId": "oidcToken",
				"tags":        []string{"IdP"},
				"requestBody": map[string]any{
					"required": true,
					"content": map[string]any{
						"application/x-www-form-urlencoded": map[string]any{
							"schema": map[string]any{
								"type":     "object",
								"required": []string{"grant_type"},
								"properties": map[string]any{
									"grant_type": map[string]any{"type": "string",
										"enum": []string{"authorization_code", "refresh_token"}},
									"code":          str,
									"code_verifier": str,
									"redirect_uri":  str,
									"refresh_token": str,
									"scope":         str,
									"client_id":     str,
									"client_secret": str,
								},
							},
						},
					},
				},
				"responses": map[string]any{
					"200": map[string]any{
						"description": "The token response",
						"content": jsonContent(object(map[string]any{
							"access_token":  str,
							"refresh_token": str,
							"id_token":      str,
							"token_type":    map[string]any{"type": "string", "enum": []string{"Bearer"}},
							"expires_in":    map[string]any{"type": "integer"},
							"scope":         str,
						})),
					},
					"400": oauthError("`unsupported_grant_type`; `invalid_request` — both client " +
						"authentication methods at once, a `client_id` that contradicts the Basic one, a credential " +
						"or token in the URL query, or no `refresh_token`; `invalid_grant` — a code or refresh " +
						"token that was never issued, was already used, has expired, belongs to another client, " +
						"was redeemed with another `redirect_uri`, whose `code_verifier` is missing, wrong or " +
						"unexpected, or whose session has ended; `invalid_scope` — a refresh `scope` " +
						"beyond the granted one"),
					"401": oauthError("`invalid_client`, with `WWW-Authenticate: Basic` when the client " +
						"tried `client_secret_basic`"),
					"405": oauthError("`invalid_request` — any method but `POST`; `Allow: POST`"),
					"500": oauthError("`server_error`"),
				},
			},
		},
		OIDCUserInfoPath: map[string]any{
			"get": map[string]any{
				"summary": "UserInfo endpoint",
				"description": "Requires `Authorization: Bearer <access_token>` — the access token the " +
					"token endpoint returned, verified the way every other bearer route verifies one. " +
					"No CSRF and no cookie credential: the header is the only one read. " +
					"Mounted only when the `Auth` was built with `WithIDP`.",
				"operationId": "oidcUserInfo",
				"tags":        []string{"IdP"},
				"security":    []map[string]any{{"BearerAuth": []string{}}},
				"responses": map[string]any{
					"200": map[string]any{
						"description": "The profile claims",
						"content": jsonContent(object(map[string]any{
							"sub":   str,
							"email": str,
							"name":  str,
						})),
					},
					"401": text("`unauthorized` — no `Bearer` header, or a token this deployment cannot verify"),
				},
			},
		},
	}
}

// removeOpenAPIOperation drops one operation from the spec, and the path item
// with it only when no operation is left.
//
// The gated set is method-keyed, so the removal has to be too. Today every
// gated path carries a single operation and deleting the whole path item would
// give the same answer; the day one of them gains a second method that is not
// gated, deleting the path would quietly undocument a route the adapters still
// serve — a spec that lies in the direction nothing checks, since the
// conformance suite compares a path to one method.
func removeOpenAPIOperation(paths map[string]any, path, method string) {
	item, ok := paths[path].(map[string]any)
	if !ok {
		return
	}
	delete(item, strings.ToLower(method))
	if len(item) == 0 {
		delete(paths, path)
	}
}

// openAPIPrefix normalises the mount prefix the same way HTTPConfig.Prefix does,
// so a spec and a mount built from the same string agree.
func openAPIPrefix(prefix string) string {
	return HTTPConfig{APIPrefix: prefix}.Prefix()
}

func openAPIParameters() map[string]any {
	return map[string]any{
		"AuthStrategy": map[string]any{
			"name": AuthStrategyHeader,
			"in":   "header",
			"description": "Send `" + AuthStrategyBearer + "` (exact, case-sensitive) to receive the token pair " +
				"in the response body and no cookies. Any other value, or the header's absence, selects cookie delivery.",
			"required": false,
			"schema":   map[string]any{"type": "string", "enum": []string{AuthStrategyBearer}},
		},
		"CSRFToken": map[string]any{
			"name": CSRFHeaderName,
			"in":   "header",
			"description": "Double-submit token. Required only for a cookie-authenticated request to a route behind " +
				"the access-token middleware; mirror the `" + CSRFTokenCookieName + "` cookie value here.",
			"required": false,
			"schema":   map[string]any{"type": "string"},
		},
	}
}

// openAPIJWKSSchemas are the two schemas only the JWKS path item references.
// They are merged into the component schemas alongside that path item and are
// absent otherwise, so a deployment with no IdP does not ship a spec carrying
// two definitions nothing points at.
func openAPIJWKSSchemas() map[string]any {
	return map[string]any{
		"JWK": map[string]any{
			"type":        "object",
			"description": "One RSA public key, RFC 7517.",
			"required":    []string{"kty", "use", "alg", "kid", "n", "e"},
			"properties": map[string]any{
				"kty": map[string]any{"type": "string", "enum": []string{"RSA"}},
				"use": map[string]any{"type": "string", "enum": []string{"sig"}},
				"alg": map[string]any{"type": "string", "enum": []string{"RS256"}},
				"kid": map[string]any{"type": "string", "description": "Matches the `kid` header of the tokens this key signed."},
				"n":   map[string]any{"type": "string", "description": "Modulus, unpadded base64url of the big-endian bytes."},
				"e":   map[string]any{"type": "string", "description": "Exponent, unpadded base64url of the big-endian bytes."},
			},
		},
		"JWKS": map[string]any{
			"type":     "object",
			"required": []string{"keys"},
			"properties": map[string]any{
				"keys": map[string]any{
					"type":        "array",
					"description": "The signing key first, then `IDPConfig.PublicKeys` in order.",
					"items":       map[string]any{"$ref": "#/components/schemas/JWK"},
				},
			},
		},
	}
}

func openAPISchemas() map[string]any {
	str := map[string]any{"type": "string"}
	return map[string]any{
		"RegisterInput": map[string]any{
			"type":     "object",
			"required": []string{"email", "password"},
			"properties": map[string]any{
				"email":    map[string]any{"type": "string", "format": "email"},
				"password": map[string]any{"type": "string", "minLength": 8},
				"tenantId": str,
			},
		},
		"LoginInput": map[string]any{
			"type":     "object",
			"required": []string{"email", "password"},
			"properties": map[string]any{
				"email":    map[string]any{"type": "string", "format": "email"},
				"password": str,
				"tenantId": str,
			},
		},
		// Success is what a route answers when it has nothing to hand back. Every
		// non-token route below returns exactly this object and no more.
		"Success": map[string]any{
			"type":       "object",
			"required":   []string{"success"},
			"properties": map[string]any{"success": map[string]any{"type": "boolean", "enum": []bool{true}}},
		},
		// AuthResult is the token-issuing answer. accessToken and refreshToken are
		// present only for a bearer caller; a cookie caller gets Set-Cookie
		// headers and a body with nothing but success.
		"AuthResult": map[string]any{
			"type":     "object",
			"required": []string{"success"},
			"properties": map[string]any{
				"success":      map[string]any{"type": "boolean", "enum": []bool{true}},
				"accessToken":  map[string]any{"type": "string", "description": "Bearer callers only."},
				"refreshToken": map[string]any{"type": "string", "description": "Bearer callers only."},
			},
		},
		// The two second-factor answers POST /login can give instead of a session.
		// Neither is the Error envelope: the first is a 200 with no error member at
		// all, the second a 403 with a code and no message. See login_2fa.go.
		"TwoFactorChallenge": map[string]any{
			"type":     "object",
			"required": []string{"requiresTwoFactor", "tempToken", "available2faMethods"},
			"properties": map[string]any{
				"requiresTwoFactor": map[string]any{"type": "boolean", "enum": []bool{true}},
				"tempToken":         map[string]any{"type": "string", "description": "Step-up token; present it to the route for the method the client picks."},
				"available2faMethods": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string", "enum": []string{TwoFactorMethodTOTP, TwoFactorMethodSMS, TwoFactorMethodMagicLink}},
					"description": "The factors this account can present. Never empty; an account with none gets TwoFactorSetupRequired instead.",
				},
			},
		},
		"TwoFactorSetupRequired": map[string]any{
			"type":     "object",
			"required": []string{"requires2FASetup", "tempToken", "code"},
			"properties": map[string]any{
				"requires2FASetup": map[string]any{"type": "boolean", "enum": []bool{true}},
				"tempToken":        str,
				"code":             map[string]any{"type": "string", "enum": []string{CodeTwoFactorSetupRequired}},
			},
		},
		"RegisterResult": map[string]any{
			"type":     "object",
			"required": []string{"success", "userId"},
			"properties": map[string]any{
				"success":      map[string]any{"type": "boolean", "enum": []bool{true}},
				"userId":       str,
				"accessToken":  map[string]any{"type": "string", "description": "Bearer callers only."},
				"refreshToken": map[string]any{"type": "string", "description": "Bearer callers only."},
			},
		},
		// Session is one entry of GET /sessions. It is the response-safe
		// projection: the refresh-token hash that identifies the row server-side
		// is never serialised, which is why revocation takes an opaque handle.
		"Session": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"handle":     str,
				"userAgent":  str,
				"ip":         str,
				"createdAt":  map[string]any{"type": "string", "format": "date-time"},
				"expiresAt":  map[string]any{"type": "string", "format": "date-time"},
				"revokedAt":  map[string]any{"type": "string", "format": "date-time"},
				"lastUsedAt": map[string]any{"type": "string", "format": "date-time"},
			},
		},
		"SessionList": map[string]any{
			"type":       "object",
			"required":   []string{"sessions"},
			"properties": map[string]any{"sessions": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/Session"}}},
		},
		"CleanupResult": map[string]any{
			"type":     "object",
			"required": []string{"success", "deleted"},
			"properties": map[string]any{
				"success": map[string]any{"type": "boolean", "enum": []bool{true}},
				"deleted": map[string]any{"type": "integer"},
			},
		},
		"LinkedAccount": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"provider":          str,
				"providerAccountId": str,
				"email":             str,
				"createdAt":         map[string]any{"type": "string", "format": "date-time"},
			},
		},
		// TOTPSetup is the one route with no success envelope: the enrolment
		// material is the whole body.
		"TOTPSetup": map[string]any{
			"type":     "object",
			"required": []string{"secret", "otpauthUrl"},
			"properties": map[string]any{
				"secret":     str,
				"otpauthUrl": map[string]any{"type": "string", "description": "Provisioning URI; render it as a QR code client-side."},
			},
		},
		"User": map[string]any{
			"type":     "object",
			"required": []string{"id", "email", "loginProvider", "isEmailVerified", "isTotpEnabled", "createdAt"},
			"properties": map[string]any{
				"id":              str,
				"email":           map[string]any{"type": "string", "format": "email"},
				"loginProvider":   map[string]any{"type": "string", "description": "The provider that created the account; `local` for a password registration."},
				"tenantId":        str,
				"firstName":       str,
				"lastName":        str,
				"phoneNumber":     str,
				"isEmailVerified": map[string]any{"type": "boolean"},
				"isTotpEnabled":   map[string]any{"type": "boolean"},
				"roles":           map[string]any{"type": "array", "items": str},
				"permissions":     map[string]any{"type": "array", "items": str},
				"metadata":        map[string]any{"type": "object"},
				"customClaims":    map[string]any{"type": "object"},
				"createdAt":       map[string]any{"type": "string", "format": "date-time"},
			},
		},
		// Error carries the reference's message, and its code where the reference
		// emits one — several failures are deliberately code-less, so clients are
		// documented not to pattern-match on an absent code.
		"Error": map[string]any{
			"type":     "object",
			"required": []string{"error"},
			"properties": map[string]any{
				"error": str,
				"code":  map[string]any{"type": "string", "description": "Absent where the reference emits no code."},
			},
		},
	}
}

func openAPIPaths(prefix string) map[string]any {
	schema := func(name string) map[string]any {
		return map[string]any{"$ref": "#/components/schemas/" + name}
	}
	param := func(name string) map[string]any {
		return map[string]any{"$ref": "#/components/parameters/" + name}
	}
	jsonContent := func(s map[string]any) map[string]any {
		return map[string]any{"application/json": map[string]any{"schema": s}}
	}
	body := func(s map[string]any) map[string]any {
		return map[string]any{"required": true, "content": jsonContent(s)}
	}
	inline := func(required []string, props map[string]any) map[string]any {
		out := map[string]any{"type": "object", "properties": props}
		if len(required) > 0 {
			out["required"] = required
		}
		return out
	}
	// fail renders one error response from the catalog entry the route actually
	// writes, so the documented status and code cannot disagree with wire.go.
	fail := func(entries ...HTTPError) map[string]any {
		out := map[string]any{}
		for _, e := range entries {
			description := e.Message
			if e.Code != "" {
				description += " (`" + e.Code + "`)"
			}
			key := strconv.Itoa(e.Status)
			if existing, ok := out[key].(map[string]any); ok {
				out[key] = map[string]any{
					"description": existing["description"].(string) + "; " + description,
					"content":     jsonContent(schema("Error")),
				}
				continue
			}
			out[key] = map[string]any{"description": description, "content": jsonContent(schema("Error"))}
		}
		return out
	}
	respond := func(status int, description string, s map[string]any, errs ...HTTPError) map[string]any {
		out := fail(errs...)
		out[strconv.Itoa(status)] = map[string]any{"description": description, "content": jsonContent(s)}
		return out
	}

	str := map[string]any{"type": "string"}
	mode := map[string]any{
		"type":        "string",
		"enum":        []string{"login", StepUpMode},
		"description": "Only the literal `" + StepUpMode + "` selects the step-up branch; absent, empty and anything else mean login.",
	}
	// emailLang is the body field the four mailing routes share. It is passed to
	// the configured sender as the delivery's Lang; the built-in mailers honour
	// `it` and `en` and fall back to their configured locale for anything else.
	emailLang := map[string]any{
		"type":        "string",
		"description": "Language of the mail: `it` or `en`; anything else means the deployment's default.",
	}
	// POST /login is the one route with two answers per status, which the catalog
	// cannot express: a 200 is either a session or a second-factor challenge, and a
	// 403 is either EMAIL_NOT_VERIFIED or the 2FA_SETUP_REQUIRED envelope. Neither
	// challenge body is the error envelope — see login_2fa.go — so both statuses are
	// written out here rather than through fail().
	loginResponses := respond(http.StatusOK, "Session issued, or a second-factor challenge (`requiresTwoFactor`)",
		map[string]any{"oneOf": []any{schema("AuthResult"), schema("TwoFactorChallenge")}},
		HTTPErrInvalidBody, HTTPErrInvalidCredentials)
	loginResponses[strconv.Itoa(http.StatusForbidden)] = map[string]any{
		"description": HTTPErrEmailNotVerified.Message + " (`" + CodeEmailNotVerified + "`); or a second factor is required and this account has none enrolled (`" + CodeTwoFactorSetupRequired + "`)",
		"content":     jsonContent(map[string]any{"oneOf": []any{schema("Error"), schema("TwoFactorSetupRequired")}}),
	}

	tokenDelivery := []map[string]any{param("AuthStrategy")}
	protected := []map[string]any{param("AuthStrategy"), param("CSRFToken")}
	anyCredential := []map[string]any{{"BearerAuth": []string{}}, {"CookieAuth": []string{}}}

	return map[string]any{
		prefix + "/register": map[string]any{
			"post": map[string]any{
				"summary":     "Register a new user and open a session",
				"operationId": "register",
				"tags":        []string{"Auth"},
				"parameters":  tokenDelivery,
				"requestBody": body(schema("RegisterInput")),
				"responses": respond(http.StatusCreated, "Registered", schema("RegisterResult"),
					HTTPErrInvalidBody, HTTPErrInvalidInput, HTTPErrWeakPassword, HTTPErrUserExists),
			},
		},
		prefix + "/login": map[string]any{
			"post": map[string]any{
				"summary":     "Log in with email and password",
				"operationId": "login",
				"tags":        []string{"Auth"},
				"parameters":  tokenDelivery,
				"requestBody": body(schema("LoginInput")),
				"responses":   loginResponses,
			},
		},

		prefix + "/sessions": map[string]any{
			"get": map[string]any{
				"summary":     "List the caller's sessions",
				"operationId": "listSessions",
				"tags":        []string{"Sessions"},
				"security":    anyCredential,
				"parameters":  protected,
				"responses": respond(http.StatusOK, "The caller's sessions", schema("SessionList"),
					HTTPErrNoAccessToken, HTTPErrInvalidAccessToken),
			},
		},
		prefix + "/sessions/{handle}": map[string]any{
			"delete": map[string]any{
				"summary":     "Revoke one of the caller's sessions",
				"description": "The handle is opaque; a session that does not exist and one that belongs to somebody else are deliberately indistinguishable.",
				"operationId": "revokeSession",
				"tags":        []string{"Sessions"},
				"security":    anyCredential,
				"parameters": append([]map[string]any{{
					"name": "handle", "in": "path", "required": true, "schema": str,
				}}, protected...),
				"responses": respond(http.StatusOK, "Session revoked", schema("Success"),
					HTTPErrSessionNotFound, HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/sessions/cleanup": map[string]any{
			"post": map[string]any{
				"summary": "Delete expired sessions",
				"description": "Unauthenticated, as in the reference: anyone who can reach the router can trigger a cleanup. " +
					"Reproduced deliberately so an existing cron job keeps working.",
				"operationId": "cleanupSessions",
				"tags":        []string{"Sessions"},
				"responses":   respond(http.StatusOK, "Expired sessions deleted", schema("CleanupResult")),
			},
		},
		prefix + "/profile": map[string]any{
			"patch": map[string]any{
				"summary":     "Update the caller's profile",
				"description": "A partial update: an absent field is left alone, so it is not the same as sending it empty. The updated user is not echoed back — re-read /me.",
				"operationId": "updateProfile",
				"tags":        []string{"Account"},
				"security":    anyCredential,
				"parameters":  protected,
				"requestBody": body(inline(nil, map[string]any{"firstName": str, "lastName": str})),
				"responses": respond(http.StatusOK, "Profile updated", schema("Success"),
					HTTPErrInvalidBody, HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/add-phone": map[string]any{
			"post": map[string]any{
				"summary":     "Set or clear the caller's phone number",
				"description": "An empty phoneNumber clears it. The number is what /sms/send texts.",
				"operationId": "addPhone",
				"tags":        []string{"Account"},
				"security":    anyCredential,
				"parameters":  protected,
				"requestBody": body(inline([]string{"phoneNumber"}, map[string]any{"phoneNumber": str})),
				"responses": respond(http.StatusOK, "Phone number updated", schema("Success"),
					HTTPErrInvalidBody, HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/account": map[string]any{
			"delete": map[string]any{
				"summary":     "Delete the caller's account",
				"description": "The auth cookies are cleared on the way out even for a bearer caller, so nobody is left holding live cookies for a deleted account.",
				"operationId": "deleteAccount",
				"tags":        []string{"Account"},
				"security":    anyCredential,
				"parameters":  protected,
				"responses": respond(http.StatusOK, "Account deleted", schema("Success"),
					HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},

		prefix + "/oauth/{provider}": map[string]any{
			"get": map[string]any{
				"summary":     "Begin an OAuth login",
				"description": "Redirects to the provider. The `state` parameter is minted here and verified on the callback.",
				"operationId": "oauthAuthorize",
				"tags":        []string{"OAuth"},
				"parameters": []map[string]any{{
					"name": "provider", "in": "path", "required": true, "schema": str,
				}},
				"responses": map[string]any{
					"302": map[string]any{"description": "Redirect to the provider"},
					"400": map[string]any{"description": "Unknown or unconfigured provider", "content": jsonContent(schema("Error"))},
				},
			},
		},
		prefix + "/oauth/{provider}/callback": map[string]any{
			"get": map[string]any{
				"summary":     "Complete an OAuth login",
				"description": "Verifies the state, issues a session and redirects back to the origin the state names. Under `OAuthProvisioning.OnEmailMatch: \"conflict\"` a provider account asserting an address another account holds redirects to `/account-conflict?provider=<p>&code=" + CodeOAuthAccountConflict + "[&email=<e>]` instead, with no session; the provisioning refusals are JSON.",
				"operationId": "oauthCallback",
				"tags":        []string{"OAuth"},
				"parameters": []map[string]any{
					{"name": "provider", "in": "path", "required": true, "schema": str},
					{"name": "code", "in": "query", "required": false, "schema": str},
					{"name": "state", "in": "query", "required": false, "schema": str},
				},
				"responses": respond(http.StatusFound, "Redirect back to the application, or to the account-conflict page", schema("Success"),
					HTTPErrOAuthState, HTTPErrOAuthEmailNotVerified, HTTPErrOAuthEmailDomainNotAllowed,
					HTTPErrOAuthUserNotProvisioned),
			},
		},
		prefix + "/linked-accounts": map[string]any{
			"get": map[string]any{
				"summary":     "List the caller's linked OAuth accounts",
				"operationId": "listLinkedAccounts",
				"tags":        []string{"OAuth"},
				"security":    anyCredential,
				"parameters":  protected,
				"responses": respond(http.StatusOK, "Linked accounts",
					inline(nil, map[string]any{"linkedAccounts": map[string]any{"type": "array", "items": schema("LinkedAccount")}}),
					HTTPErrNoAccessToken, HTTPErrInvalidAccessToken),
			},
		},
		prefix + "/linked-accounts/{provider}/{providerAccountId}": map[string]any{
			"delete": map[string]any{
				"summary":     "Unlink an OAuth account",
				"operationId": "unlinkAccount",
				"tags":        []string{"OAuth"},
				"security":    anyCredential,
				"parameters": append([]map[string]any{
					{"name": "provider", "in": "path", "required": true, "schema": str},
					{"name": "providerAccountId", "in": "path", "required": true, "schema": str},
				}, protected...),
				"responses": respond(http.StatusOK, "Account unlinked", schema("Success"),
					HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/link-request": map[string]any{
			"post": map[string]any{
				"summary": "Request a link between two accounts",
				"description": "The one unauthenticated route that is still CSRF-checked, via a double-submit inside the handler: " +
					"without it a cross-site form post could overwrite an in-flight link token.",
				"operationId": "linkRequest",
				"tags":        []string{"OAuth"},
				"parameters":  []map[string]any{param("CSRFToken")},
				"requestBody": body(inline([]string{"email"}, map[string]any{"email": map[string]any{"type": "string", "format": "email"}})),
				"responses": respond(http.StatusOK, "Link email sent", schema("Success"),
					HTTPErrInvalidBody, HTTPErrLinkEmailRequired, HTTPErrTargetUserNotFound, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/link-verify": map[string]any{
			"post": map[string]any{
				"summary":     "Complete an account link",
				"operationId": "linkVerify",
				"tags":        []string{"OAuth"},
				"requestBody": body(inline([]string{"token"}, map[string]any{"token": str})),
				"responses": respond(http.StatusOK, "Accounts linked", schema("Success"),
					HTTPErrInvalidBody, HTTPErrTokenRequired, HTTPErrInvalidLinkToken,
					HTTPErrLinkTokenExpired, HTTPErrLinkUnauthorized),
			},
		},

		prefix + "/forgot-password": map[string]any{
			"post": map[string]any{
				"summary":     "Request a password-reset email",
				"description": "Answers 200 for an address the store does not have, so the route cannot be used to discover who is registered.",
				"operationId": "forgotPassword",
				"tags":        []string{"Password"},
				"requestBody": body(inline([]string{"email"}, map[string]any{
					"email":     map[string]any{"type": "string", "format": "email"},
					"tenantId":  str,
					"emailLang": emailLang,
				})),
				"responses": respond(http.StatusOK, "Reset email sent, or the address is unknown", schema("Success"),
					HTTPErrInvalidBody, HTTPErrResetTokenStoreMissing),
			},
		},
		prefix + "/reset-password": map[string]any{
			"post": map[string]any{
				"summary":     "Reset a password with a token",
				"description": "The new password field is named `password`, not `newPassword`: that is what the served auth.js and the Flutter client send.",
				"operationId": "resetPassword",
				"tags":        []string{"Password"},
				"requestBody": body(inline([]string{"token", "password"}, map[string]any{"token": str, "password": str})),
				"responses": respond(http.StatusOK, "Password reset", schema("Success"),
					HTTPErrInvalidBody, HTTPErrInvalidResetToken, HTTPErrWeakPassword, HTTPErrResetTokenStoreMissing),
			},
		},
		prefix + "/change-password": map[string]any{
			"post": map[string]any{
				"summary":     "Change the caller's password",
				"operationId": "changePassword",
				"tags":        []string{"Password"},
				"security":    anyCredential,
				"parameters":  protected,
				"requestBody": body(inline([]string{"currentPassword", "newPassword"}, map[string]any{
					"currentPassword": str,
					"newPassword":     str,
				})),
				"responses": respond(http.StatusOK, "Password changed", schema("Success"),
					HTTPErrInvalidBody, HTTPErrCurrentPasswordIncorrect, HTTPErrNewPasswordRequired,
					HTTPErrWeakPassword, HTTPErrUserNotFound, HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/send-verification-email": map[string]any{
			"post": map[string]any{
				"summary":     "Send the caller a verification email",
				"operationId": "sendVerificationEmail",
				"tags":        []string{"Email"},
				"security":    anyCredential,
				"parameters":  protected,
				"requestBody": map[string]any{
					"required": false,
					"content":  jsonContent(inline(nil, map[string]any{"emailLang": emailLang})),
				},
				"responses": respond(http.StatusOK, "Verification email sent", schema("Success"),
					HTTPErrEmailAlreadyVerified, HTTPErrEmailVerificationStoreMissing,
					HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/verify-email": map[string]any{
			"get": map[string]any{
				"summary":     "Confirm an email address",
				"description": "A GET because the link is opened from a mailbox.",
				"operationId": "verifyEmail",
				"tags":        []string{"Email"},
				"parameters": []map[string]any{{
					"name": "token", "in": "query", "required": true, "schema": str,
				}},
				"responses": respond(http.StatusOK, "Email verified", schema("Success"),
					HTTPErrVerifyTokenRequired, HTTPErrInvalidVerifyToken, HTTPErrEmailVerificationStoreMissing),
			},
		},
		prefix + "/change-email/request": map[string]any{
			"post": map[string]any{
				"summary":     "Request an email-address change",
				"operationId": "changeEmailRequest",
				"tags":        []string{"Email"},
				"security":    anyCredential,
				"parameters":  protected,
				"requestBody": body(inline([]string{"newEmail"}, map[string]any{
					"newEmail":  map[string]any{"type": "string", "format": "email"},
					"emailLang": emailLang,
				})),
				"responses": respond(http.StatusOK, "Confirmation email sent", schema("Success"),
					HTTPErrInvalidBody, HTTPErrEmailInUse, HTTPErrPasswordRequired,
					HTTPErrChangeEmailStoreMissing, HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/change-email/confirm": map[string]any{
			"post": map[string]any{
				"summary":     "Confirm an email-address change",
				"description": "No auth gate, and therefore no CSRF check: the confirmation token is the credential. Once the change is applied, the previous address is mailed a notice through the configured email-changed sender; a deployment without one mails nothing and still answers 200.",
				"operationId": "changeEmailConfirm",
				"tags":        []string{"Email"},
				"requestBody": body(inline([]string{"token"}, map[string]any{"token": str})),
				"responses": respond(http.StatusOK, "Email address changed", schema("Success"),
					HTTPErrInvalidBody, HTTPErrInvalidEmailChangeToken, HTTPErrChangeEmailStoreMissing),
			},
		},
		prefix + "/refresh": map[string]any{
			"post": map[string]any{
				"summary":     "Exchange a refresh token for a new session",
				"operationId": "refresh",
				"tags":        []string{"Auth"},
				"parameters":  tokenDelivery,
				"requestBody": map[string]any{
					"required":    false,
					"description": "Optional. A cookie caller sends no body; a bearer caller sends the token here.",
					"content":     jsonContent(inline(nil, map[string]any{"refreshToken": str})),
				},
				"responses": respond(http.StatusOK, "Session refreshed", schema("AuthResult"),
					HTTPErrNoRefreshToken, HTTPErrExpiredRefreshToken, HTTPErrInvalidRefreshToken, HTTPErrSessionRevoked),
			},
		},
		prefix + "/logout": map[string]any{
			"post": map[string]any{
				"summary":     "Revoke the caller's session and clear the auth cookies",
				"description": "Best effort: it answers 200 and clears cookies even without a usable credential, so a caller is never stranded logged in.",
				"operationId": "logout",
				"tags":        []string{"Auth"},
				"responses":   respond(http.StatusOK, "Logged out", schema("Success")),
			},
		},
		prefix + "/me": map[string]any{
			"get": map[string]any{
				"summary":     "Get the authenticated user",
				"description": "The user object is the whole body — it is not wrapped in an envelope.",
				"operationId": "me",
				"tags":        []string{"Auth"},
				"security":    anyCredential,
				"responses": respond(http.StatusOK, "The authenticated user", schema("User"),
					HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrSessionRevoked),
			},
		},

		prefix + "/magic-link/send": map[string]any{
			"post": map[string]any{
				"summary": "Mail a magic link",
				"description": "Answers 200 for an address the store does not have, so the route cannot be used to " +
					"discover who is registered. Requires Config.SendMagicLink; without it the answer is 500 " +
					CodeEmailNotConfigured + ", for an unknown address too.",
				"operationId": "sendMagicLink",
				"tags":        []string{"Passwordless"},
				"requestBody": body(inline(nil, map[string]any{
					"email":     map[string]any{"type": "string", "format": "email", "description": "Login mode only; the 2fa branch takes the address from the tempToken and ignores this field."},
					"mode":      mode,
					"tempToken": map[string]any{"type": "string", "description": "Required in `" + StepUpMode + "` mode."},
					"tenantId":  str,
					"emailLang": emailLang,
				})),
				"responses": respond(http.StatusOK, "Link sent, or the address is unknown", schema("Success"),
					HTTPErrInvalidBody, HTTPErrPasswordlessEmailRequired, HTTPErrTempTokenRequired,
					HTTPErrInvalidTempToken, HTTPErrUserNotFound, HTTPErrEmailNotConfigured),
			},
		},
		prefix + "/magic-link/verify": map[string]any{
			"post": map[string]any{
				"summary":     "Consume a magic link and open a session",
				"description": "Single use: the link is burned whether or not the rest of the request succeeds.",
				"operationId": "verifyMagicLink",
				"tags":        []string{"Passwordless"},
				"parameters":  tokenDelivery,
				"requestBody": body(inline([]string{"token"}, map[string]any{
					"token":     str,
					"mode":      mode,
					"tempToken": map[string]any{"type": "string", "description": "Required in `" + StepUpMode + "` mode."},
				})),
				"responses": respond(http.StatusOK, "Session issued", schema("AuthResult"),
					HTTPErrInvalidBody, HTTPErrTempTokenRequired, HTTPErrInvalidTempToken,
					HTTPErrInvalidMagicLink, HTTPErrTokenMismatch),
			},
		},
		prefix + "/sms/send": map[string]any{
			"post": map[string]any{
				"summary": "Text a one-time code",
				"description": "An unknown address answers 200; an unknown userId answers 404. Requires " +
					"Config.SendSMSCode; without it every request answers 500 " + CodeSMSNotConfigured + " before anything else is checked.",
				"operationId": "sendSMSCode",
				"tags":        []string{"Passwordless"},
				"requestBody": body(inline(nil, map[string]any{
					"userId":    map[string]any{"type": "string", "description": "Login mode: one of userId or email. An email outranks a userId."},
					"email":     map[string]any{"type": "string", "format": "email"},
					"mode":      mode,
					"tempToken": map[string]any{"type": "string", "description": "Required in `" + StepUpMode + "` mode."},
					"tenantId":  str,
				})),
				"responses": respond(http.StatusOK, "Code sent, or the address is unknown", schema("Success"),
					HTTPErrInvalidBody, HTTPErrUserIDOrEmailRequired, HTTPErrPhoneNotSet,
					HTTPErrTempTokenRequired, HTTPErrInvalidTempToken, HTTPErrUserNotFound, HTTPErrSMSNotConfigured),
			},
		},
		prefix + "/sms/verify": map[string]any{
			"post": map[string]any{
				"summary":     "Verify a one-time code and open a session",
				"operationId": "verifySMSCode",
				"tags":        []string{"Passwordless"},
				"parameters":  tokenDelivery,
				"requestBody": body(inline([]string{"code"}, map[string]any{
					"userId":    map[string]any{"type": "string", "description": "Required outside `" + StepUpMode + "` mode."},
					"code":      str,
					"mode":      mode,
					"tempToken": map[string]any{"type": "string", "description": "Required in `" + StepUpMode + "` mode."},
					"tenantId":  str,
				})),
				"responses": respond(http.StatusOK, "Session issued", schema("AuthResult"),
					HTTPErrInvalidBody, HTTPErrUserIDRequired, HTTPErrTempTokenRequired,
					HTTPErrInvalidTempToken, HTTPErrInvalidSMSCode, HTTPErrUserNotFound),
			},
		},

		prefix + "/2fa/setup": map[string]any{
			"post": map[string]any{
				"summary":     "Begin authenticator enrolment",
				"description": "Stateless: nothing is persisted until the secret comes back to /2fa/verify-setup with a code that verifies against it.",
				"operationId": "setupTwoFactor",
				"tags":        []string{"TwoFactor"},
				"security":    anyCredential,
				"parameters":  protected,
				"responses": respond(http.StatusOK, "Enrolment material", schema("TOTPSetup"),
					HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/2fa/verify-setup": map[string]any{
			"post": map[string]any{
				"summary":     "Complete authenticator enrolment",
				"description": "The code field is named `token` on this route — not `code`, and not `totpCode`.",
				"operationId": "verifyTwoFactorSetup",
				"tags":        []string{"TwoFactor"},
				"security":    anyCredential,
				"parameters":  protected,
				"requestBody": body(inline([]string{"token", "secret"}, map[string]any{
					"token":  map[string]any{"type": "string", "description": "The code from the authenticator app."},
					"secret": map[string]any{"type": "string", "description": "The secret returned by /2fa/setup."},
				})),
				"responses": respond(http.StatusOK, "Second factor enabled", schema("Success"),
					HTTPErrInvalidBody, HTTPErrInvalidTOTPSetupCode, HTTPErrNoAccessToken,
					HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/2fa/verify": map[string]any{
			"post": map[string]any{
				"summary": "Complete a step-up challenge and open a session",
				"description": "The code field is named `totpCode` here. A bad tempToken answers `" + CodeInvalidAccessToken +
					"` on this route where its siblings answer `" + CodeInvalidTempToken + "`; the clients are written against the difference.",
				"operationId": "verifyTwoFactor",
				"tags":        []string{"TwoFactor"},
				"parameters":  tokenDelivery,
				"requestBody": body(inline([]string{"tempToken", "totpCode"}, map[string]any{
					"tempToken": str,
					"totpCode":  str,
				})),
				"responses": respond(http.StatusOK, "Session issued", schema("AuthResult"),
					HTTPErrInvalidBody, HTTPErrInvalidStepUpToken, HTTPErrInvalidTOTPCode, HTTPErrTOTPNotSetUp),
			},
		},
		prefix + "/2fa/disable": map[string]any{
			"post": map[string]any{
				"summary":     "Turn the second factor off",
				"description": "Refused when the user or the deployment requires 2FA. The user is re-read from the store, so a flag set after the access token was issued is still honoured.",
				"operationId": "disableTwoFactor",
				"tags":        []string{"TwoFactor"},
				"security":    anyCredential,
				"parameters":  protected,
				"responses": respond(http.StatusOK, "Second factor disabled", schema("Success"),
					HTTPErrTwoFactorRequiredForUser, HTTPErrTwoFactorRequiredByPolicy,
					HTTPErrUserNotFound, HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
	}
}

// openAPIUIConfigPath describes GET <prefix>/ui/config, the document the
// built-in UI reads before it renders. It is a path item on its own because it
// is added conditionally.
func openAPIUIConfigPath() map[string]any {
	// One string member with its description. It says nothing about whether the
	// member is required — three of the eight below are, and are listed in
	// required.
	stringProp := func(description string) map[string]any {
		return map[string]any{"type": "string", "description": description}
	}
	return map[string]any{
		"get": map[string]any{
			"summary": "The built-in UI's configuration document",
			"description": "Public: no credential and no CSRF pair, since the login page fetches it " +
				"before any session exists. Mounted only when the adapter was mounted with " +
				"`HTTPConfig.UI.Enabled`. Values stored in the `SettingsStore` override the static " +
				"`UIOptions.Branding`; `translations` are the `TemplateStore` UI page `config` for " +
				"`lang`, falling back to `en` and then to an empty object. When a store fails, the " +
				"answer is still 200 and still this shape, with `features` reduced to `register`, " +
				"`google` and `github` — the reference does the same.",
			"operationId": "uiConfig",
			"tags":        []string{"UI"},
			"parameters": []map[string]any{{
				"name":        "lang",
				"in":          "query",
				"required":    false,
				"description": "Translation language. Defaults to `UIOptions.DefaultLang`, then `en`.",
				"schema":      map[string]any{"type": "string"},
			}},
			"responses": map[string]any{
				"200": map[string]any{
					"description": "The UI configuration",
					"content": map[string]any{
						"application/json": map[string]any{
							"schema": map[string]any{
								"type":     "object",
								"required": []string{"apiPrefix", "features", "ui", "translations", "lang", "headless"},
								"properties": map[string]any{
									"apiPrefix": map[string]any{
										"type":        "string",
										"description": "Where the auth routes are mounted.",
									},
									"features": map[string]any{
										"type": "object",
										"description": "Which affordances the deployment can perform. Reduced to " +
											"`register`, `google` and `github` on the store-failure path.",
										"properties": map[string]any{
											"register":       map[string]any{"type": "boolean"},
											"magicLink":      map[string]any{"type": "boolean"},
											"sms":            map[string]any{"type": "boolean"},
											"google":         map[string]any{"type": "boolean"},
											"github":         map[string]any{"type": "boolean"},
											"forgotPassword": map[string]any{"type": "boolean"},
											"verifyEmail":    map[string]any{"type": "boolean"},
											"twoFactor":      map[string]any{"type": "boolean"},
										},
									},
									"ui": map[string]any{
										"type": "object",
										"description": "The branding. The five optional members are absent rather " +
											"than null when nothing configured them.",
										"required": []string{"primaryColor", "secondaryColor", "siteName"},
										"properties": map[string]any{
											"primaryColor":   stringProp("Default `" + UIDefaultPrimaryColor + "`."),
											"secondaryColor": stringProp("Default `" + UIDefaultSecondaryColor + "`."),
											"logoUrl":        stringProp("Stored logo, then `UIBranding.CustomLogo`, then `UIBranding.LogoURL`."),
											"siteName":       stringProp("Default `" + UIDefaultSiteName + "`."),
											"customCss":      stringProp("`UIOptions.CustomCSS`; a settings store cannot override it."),
											"bgColor":        stringProp("Page background colour."),
											"bgImage":        stringProp("Page background image URL."),
											"cardBg":         stringProp("Form card background colour."),
										},
									},
									"translations": map[string]any{
										"type":                 "object",
										"description":          "Flat key to value map for `lang`; an empty object when none is stored.",
										"additionalProperties": map[string]any{"type": "string"},
									},
									"lang": map[string]any{
										"type":        "string",
										"description": "The language the translations are in.",
									},
									"headless": map[string]any{
										"type":        "boolean",
										"description": "`UIOptions.Headless`, which tells `auth.js` not to redirect on session loss.",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// openAPIDocsSpecPath describes GET <prefix>/openapi.json: this document,
// serving itself. It is a path item on its own because it is added
// conditionally.
func openAPIDocsSpecPath() map[string]any {
	return map[string]any{
		"get": map[string]any{
			"summary": "This OpenAPI document",
			"description": "Public: no credential, no CSRF token, no session — a `GET` is never " +
				"CSRF-checked, though a reader arriving without the `csrf-token` cookie is " +
				"given one. Mounted only when `HTTPConfig.Docs.Enabled` is set, and described " +
				"here only when `OpenAPIInfo.Docs` is.",
			"operationId": "openapiDocument",
			"tags":        []string{"Docs"},
			"responses": map[string]any{
				"200": map[string]any{
					"description": "The generated OpenAPI 3.0.3 document",
					"content": map[string]any{
						"application/json": map[string]any{
							"schema": map[string]any{"type": "object", "additionalProperties": true},
						},
					},
				},
			},
		},
	}
}

// openAPIDocsUIPath describes GET <prefix>/docs, the Swagger UI page that reads
// the document next door.
func openAPIDocsUIPath() map[string]any {
	return map[string]any{
		"get": map[string]any{
			"summary": "Swagger UI for this document",
			"description": "Public: no credential, no CSRF token, no session — a `GET` is never " +
				"CSRF-checked, though a reader arriving without the `csrf-token` cookie is " +
				"given one. Serves the reference's " +
				"Swagger UI page, which loads `swagger-ui-dist@5` from the unpkg CDN and " +
				"fetches the document from `" + DocsSpecPath + "` below `DocsOptions.BasePath`. " +
				"Mounted only when `HTTPConfig.Docs.Enabled` is set.",
			"operationId": "swaggerUI",
			"tags":        []string{"Docs"},
			"responses": map[string]any{
				"200": map[string]any{
					"description": "The Swagger UI page",
					"content": map[string]any{
						"text/html": map[string]any{
							"schema": map[string]any{"type": "string"},
						},
					},
				},
			},
		},
	}
}
