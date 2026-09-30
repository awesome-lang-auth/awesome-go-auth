package auth

import (
	"context"
	"encoding/json"
	"net/http"
)

// MCPServer exposes auth configuration as MCP tools for AI editors.
// It speaks JSON-RPC 2.0 over HTTP and implements the Model Context Protocol
// tools/list and tools/call methods.
//
// Deprecated: MCPServer has no authorization of any kind: auth_create_tenant,
// auth_create_role, auth_register and auth_login are callable by anyone who
// reaches the handler. It is a v0.1 addition outside the parity scope (the
// reference's MCP server is a separate package, and the family has retired it),
// and it is removed in v1.0.0. Do not mount it.
type MCPServer struct {
	authSvc *Service
}

// NewMCPServer creates an MCP server wrapping an auth service.
//
// Deprecated: see [MCPServer]. It has no authorization and is removed in v1.0.0.
func NewMCPServer(authSvc *Service) *MCPServer {
	return &MCPServer{authSvc: authSvc}
}

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type mcpResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *mcpError `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// ServeHTTP handles MCP JSON-RPC 2.0 requests (tools/list, tools/call).
func (m *MCPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req mcpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mcpWriteJSON(w, mcpResponse{
			JSONRPC: "2.0",
			Error:   &mcpError{Code: -32700, Message: "parse error"},
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch req.Method {
	case "tools/list":
		m.handleToolsList(w, req)
	case "tools/call":
		m.handleToolsCall(w, r, req)
	default:
		mcpWriteJSON(w, mcpResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &mcpError{Code: -32601, Message: "method not found"},
		})
	}
}

func (m *MCPServer) handleToolsList(w http.ResponseWriter, req mcpRequest) {
	tools := []mcpTool{
		{
			Name: "auth_get_config",
			Description: "Returns the current auth service configuration (issuer, TTLs, feature flags). " +
				"require_2fa is the static configuration term; require_2fa_effective is the policy " +
				"actually enforced, which also reflects the runtime settings store, and is absent " +
				"when that store cannot be read.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			Name:        "auth_register",
			Description: "Registers a new user with email and password.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"email":     map[string]any{"type": "string", "description": "User email address"},
					"password":  map[string]any{"type": "string", "description": "User password"},
					"tenant_id": map[string]any{"type": "string", "description": "Tenant ID"},
				},
				"required": []string{"email", "password"},
			},
		},
		{
			Name:        "auth_login",
			Description: "Authenticates a user and returns access/refresh tokens.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"email":     map[string]any{"type": "string"},
					"password":  map[string]any{"type": "string"},
					"tenant_id": map[string]any{"type": "string"},
				},
				"required": []string{"email", "password"},
			},
		},
		{
			Name:        "auth_create_tenant",
			Description: "Creates a new tenant/organization.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{"type": "string", "description": "Tenant name"},
				},
				"required": []string{"name"},
			},
		},
		{
			Name:        "auth_create_role",
			Description: "Creates a role with the given permissions.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"role":        map[string]any{"type": "string"},
					"permissions": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				},
				"required": []string{"role"},
			},
		},
	}
	mcpWriteJSON(w, mcpResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  map[string]any{"tools": tools},
	})
}

func (m *MCPServer) handleToolsCall(w http.ResponseWriter, r *http.Request, req mcpRequest) {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		mcpWriteJSON(w, mcpResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &mcpError{Code: -32602, Message: "invalid params"},
		})
		return
	}

	ctx := r.Context()
	switch params.Name {
	case "auth_get_config":
		result := map[string]any{
			"issuer":            m.authSvc.cfg.Issuer,
			"access_token_ttl":  m.authSvc.cfg.AccessTokenTTL.String(),
			"refresh_token_ttl": m.authSvc.cfg.RefreshTokenTTL.String(),
			// The static Config.Require2FA, which is what this tool has always
			// reported and what its name has always meant: a configuration value,
			// in a tool that returns configuration. It stopped being the whole of
			// the policy when the settings store landed — POST <prefix>/2fa/disable
			// refuses on Config.Require2FA OR the stored require2FA — so the
			// effective answer is reported beside it rather than in place of it,
			// which would have been a silent change of meaning for a field a client
			// already reads.
			"require_2fa":      m.authSvc.cfg.Require2FA,
			"min_password_len": m.authSvc.cfg.MinPasswordLen,
		}
		// Absent rather than wrong when the settings store cannot be read: the
		// policy is unknown at that point, and the route it governs answers 500
		// rather than guessing, so this must not guess either.
		if effective, err := m.authSvc.twoFactorPolicy(ctx); err == nil {
			result["require_2fa_effective"] = effective
		}
		mcpWriteJSON(w, mcpResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"content": result}})

	case "auth_register":
		mcpHandleRegister(ctx, w, m.authSvc, req, params.Arguments)

	case "auth_login":
		mcpHandleLogin(ctx, w, m.authSvc, req, params.Arguments)

	case "auth_create_tenant":
		mcpHandleCreateTenant(ctx, w, m.authSvc, req, params.Arguments)

	case "auth_create_role":
		mcpHandleCreateRole(ctx, w, m.authSvc, req, params.Arguments)

	default:
		mcpWriteJSON(w, mcpResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &mcpError{Code: -32601, Message: "tool not found: " + params.Name},
		})
	}
}

func mcpHandleRegister(ctx context.Context, w http.ResponseWriter, svc *Service, req mcpRequest, args map[string]any) {
	email, _ := args["email"].(string)
	password, _ := args["password"].(string)
	tenantID, _ := args["tenant_id"].(string)
	user, tokens, err := svc.Register(ctx, RegisterInput{
		Email: email, Password: password, TenantID: tenantID,
	})
	if err != nil {
		mcpWriteJSON(w, mcpResponse{JSONRPC: "2.0", ID: req.ID,
			Error: &mcpError{Code: -32000, Message: err.Error()}})
		return
	}
	mcpWriteJSON(w, mcpResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
		"content": map[string]any{
			"user_id":       user.ID,
			"email":         user.Email,
			"access_token":  tokens.AccessToken,
			"refresh_token": tokens.RefreshToken,
		},
	}})
}

func mcpHandleLogin(ctx context.Context, w http.ResponseWriter, svc *Service, req mcpRequest, args map[string]any) {
	email, _ := args["email"].(string)
	password, _ := args["password"].(string)
	tenantID, _ := args["tenant_id"].(string)
	user, tokens, err := svc.Login(ctx, LoginInput{
		Email: email, Password: password, TenantID: tenantID,
	})
	if err != nil {
		mcpWriteJSON(w, mcpResponse{JSONRPC: "2.0", ID: req.ID,
			Error: &mcpError{Code: -32000, Message: err.Error()}})
		return
	}
	mcpWriteJSON(w, mcpResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
		"content": map[string]any{
			"user_id":       user.ID,
			"email":         user.Email,
			"access_token":  tokens.AccessToken,
			"refresh_token": tokens.RefreshToken,
		},
	}})
}

func mcpHandleCreateTenant(ctx context.Context, w http.ResponseWriter, svc *Service, req mcpRequest, args map[string]any) {
	name, _ := args["name"].(string)
	tenant, err := svc.CreateTenant(ctx, name, nil)
	if err != nil {
		mcpWriteJSON(w, mcpResponse{JSONRPC: "2.0", ID: req.ID,
			Error: &mcpError{Code: -32000, Message: err.Error()}})
		return
	}
	mcpWriteJSON(w, mcpResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
		"content": map[string]any{"tenant_id": tenant.ID, "name": tenant.Name},
	}})
}

func mcpHandleCreateRole(ctx context.Context, w http.ResponseWriter, svc *Service, req mcpRequest, args map[string]any) {
	role, _ := args["role"].(string)
	var perms []string
	if raw, ok := args["permissions"].([]any); ok {
		for _, p := range raw {
			if s, ok := p.(string); ok {
				perms = append(perms, s)
			}
		}
	}
	if err := svc.CreateRole(ctx, role, perms); err != nil {
		mcpWriteJSON(w, mcpResponse{JSONRPC: "2.0", ID: req.ID,
			Error: &mcpError{Code: -32000, Message: err.Error()}})
		return
	}
	mcpWriteJSON(w, mcpResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
		"content": map[string]any{"role": role, "permissions": perms},
	}})
}

func mcpWriteJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}
