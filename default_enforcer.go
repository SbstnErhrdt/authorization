package authorization

import "github.com/casbin/casbin/v2"

// DefaultEnforcer is the default enforcer
var DefaultEnforcer *casbin.Enforcer

// SetDefaultEnforcer sets the default enforcer
func SetDefaultEnforcer(e *casbin.Enforcer) {
	DefaultEnforcer = e
}
