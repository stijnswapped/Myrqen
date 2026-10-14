// Package auth carries the authenticated identity of a request.
//
// The session middleware in internal/http/authn resolves the bearer token to an
// Actor exactly once per request and stashes it on the context; everything
// downstream reads it back with FromContext. Handlers must never take a tenant
// id from the request body — the only trustworthy copy is the one here.
package auth

import "context"

// Role is the coarse permission level attached to a session.
type Role string

const (
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
	RoleCarrier  Role = "carrier"
)

// Actor is the resolved caller: which tenant they belong to, who they are, and
// what they may do.
type Actor struct {
	TenantID string
	UserID   string
	Role     Role
}

type contextKey struct{}

// WithActor returns a copy of ctx carrying the resolved caller.
func WithActor(ctx context.Context, actor Actor) context.Context {
	return context.WithValue(ctx, contextKey{}, actor)
}

// FromContext returns the caller resolved by the session middleware. The second
// result is false for routes mounted outside the authenticated group, which is
// the only reason a handler should ever see it be false.
func FromContext(ctx context.Context) (Actor, bool) {
	actor, ok := ctx.Value(contextKey{}).(Actor)
	return actor, ok
}

// CanManageCarriers reports whether the actor may change carrier integration
// settings. Read-only shipment routes deliberately do not consult this.
func (a Actor) CanManageCarriers() bool {
	return a.Role == RoleAdmin
}
