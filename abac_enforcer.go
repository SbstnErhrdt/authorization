package authorization

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"log/slog"
)

const AbacModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub_rule, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = eval(p.sub_rule) && r.obj.Name == p.obj && r.act == p.act
`

func NewAbacEnforcer() (e *casbin.Enforcer) {
	m, err := model.NewModelFromString(AbacModel)
	if err != nil {
		slog.With("err", err).Error("can not create abac model")
		return
	}

	e, err = casbin.NewEnforcer(m)
	if err != nil {
		slog.With("err", err).Error("can not create abac enforcer")
		return
	}
	return
}

type AbacPolicy struct {
	SubRule string
	Obj     string
	Act     string
}
