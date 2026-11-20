package auth

// This file is closed registration: HTTPConfig.ClosedRegistration, the switch
// that takes POST <prefix>/register off the wire while leaving
// Service.Register to the host.
//
// The reference has the same switch, spelled differently. It mounts /register
// only when the host supplies options.onRegister (auth.router.ts:712-715) and
// reports that same condition as features.register (ui.router.ts:115), so a
// node-auth deployment with no hook answers 404 on the route and tells its UI
// to hide sign-up. This port ships registration instead of asking for it —
// there is no hook that can be absent — so the condition is a flag, and the
// flag reproduces the hookless deployment: no route, features.register false,
// and no path item in the OpenAPI document.
//
// What it does not touch is listed on the field: Service.Register stays
// callable, and an OAuth callback under OAuthProvisioning.AutoCreate is a
// second self-registration path that this flag does not close.

// RegisterRoute is where POST <prefix>/register sits below the mount prefix.
// It is exported for the reason UIConfigRoute is: the adapters mount it, the
// OpenAPI generator describes it and the conformance suite replays it, and one
// constant is what keeps the three from parting company.
const RegisterRoute = "/register"

// RegisterMounted reports whether the adapters register POST <prefix>/register:
// neither resource-server mode, which gates every credential route, nor closed
// registration has taken it away.
//
// It is a method rather than a condition each adapter spells for itself, so
// that the four mounts cannot come to disagree about it — the reason
// AdminMounted is one too — and so that a host serving its own documentation
// can ask the same question.
func (c HTTPConfig) RegisterMounted() bool {
	return !c.ResourceServer && !c.ClosedRegistration
}
