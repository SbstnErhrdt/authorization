package gql_authorization

import (
	"github.com/SbstnErhrdt/authorization"
	"github.com/casbin/casbin/v2"
	"github.com/graphql-go/graphql"
)

type Request struct {
	Sub string `json:"sub"`
	Obj string `json:"obj"`
	Act string `json:"act"`
	OK  bool   `json:"ok"`
}

type UpdatePolicy struct {
	Sub string `json:"sub"`
	Obj string `json:"obj"`
	Act string `json:"act"`

	OldSub string `json:"oldSub"`
	OldObj string `json:"oldObj"`
	OldAct string `json:"oldAct"`
	Ok     bool   `json:"ok"`
}

type Policy struct {
	Sub string `json:"sub"`
	Obj string `json:"obj"`
	Act string `json:"act"`
}

func StringArrToPolicy(arr []string) Policy {
	return Policy{
		Sub: arr[0],
		Obj: arr[1],
		Act: arr[2],
	}
}

var requestType = graphql.NewObject(
	graphql.ObjectConfig{
		Name: "AuthRequest",
		Fields: graphql.Fields{
			"sub": &graphql.Field{
				Type: graphql.String,
			},
			"obj": &graphql.Field{
				Type: graphql.String,
			},
			"act": &graphql.Field{
				Type: graphql.String,
			},
			"ok": &graphql.Field{
				Type: graphql.Boolean,
			},
		},
	},
)

var policyType = graphql.NewObject(
	graphql.ObjectConfig{
		Name: "AuthPolicy",
		Fields: graphql.Fields{
			"sub": &graphql.Field{
				Type: graphql.String,
			},
			"obj": &graphql.Field{
				Type: graphql.String,
			},
			"act": &graphql.Field{
				Type: graphql.String,
			},
		},
	},
)

var updatePolicyType = graphql.NewObject(
	graphql.ObjectConfig{
		Name: "AuthUpdatePolicy",
		Fields: graphql.Fields{
			"sub": &graphql.Field{
				Type: graphql.String,
			},
			"obj": &graphql.Field{
				Type: graphql.String,
			},
			"act": &graphql.Field{
				Type: graphql.String,
			},
			"oldSub": &graphql.Field{
				Type: graphql.String,
			},
			"oldObj": &graphql.Field{
				Type: graphql.String,
			},
			"oldAct": &graphql.Field{
				Type: graphql.String,
			},
			"ok": &graphql.Field{
				Type: graphql.Boolean,
			},
		},
	},
)

// InitModuleQueries initializes the queries for the authorization module
func InitModuleQueries(rootQueryObject *graphql.Object, enforcerGraphQLFieldName string, e *casbin.Enforcer) {
	// enforce
	rootQueryObject.AddFieldConfig(enforcerGraphQLFieldName, &graphql.Field{
		Type: requestType,
		Args: graphql.FieldConfigArgument{
			"sub": &graphql.ArgumentConfig{
				Type: graphql.String,
			},
			"obj": &graphql.ArgumentConfig{
				Type: graphql.String,
			},
			"act": &graphql.ArgumentConfig{
				Type: graphql.String,
			},
		},
		Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			sub := p.Args["sub"].(string)
			obj := p.Args["obj"].(string)
			act := p.Args["act"].(string)
			res, err := e.Enforce(sub, obj, act)
			if err != nil {
				return nil, err
			}
			return Request{sub, obj, act, res}, nil
		},
	})
	// show all policies
	rootQueryObject.AddFieldConfig(enforcerGraphQLFieldName+"Policies", &graphql.Field{
		Type:        graphql.NewList(policyType),
		Description: "Get all policies",
		Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			policies := e.GetPolicy()
			result := make([]Policy, 0)
			for _, policy := range policies {
				result = append(result, StringArrToPolicy(policy))
			}
			return result, nil
		},
	})
	// show all modules
	rootQueryObject.AddFieldConfig(enforcerGraphQLFieldName+"Modules", &graphql.Field{
		Type:        graphql.NewList(graphql.String),
		Description: "Get all modules",
		Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			modules := authorization.GetAllModules()
			results := make([]string, 0)
			for _, m := range modules {
				results = append(results, m.GetName())
			}
			return results, nil
		},
	})
}

// InitModuleMutations initializes the mutations for the authorization module
func InitModuleMutations(rootMutationObject *graphql.Object, enforcerGraphQLFieldName string, e *casbin.Enforcer) {
	rootMutationObject.AddFieldConfig(enforcerGraphQLFieldName+"AuthAddPolicy", &graphql.Field{
		Type:        requestType,
		Description: "Add a policy",
		Args: graphql.FieldConfigArgument{
			"sub": &graphql.ArgumentConfig{
				Type: graphql.String,
			},
			"obj": &graphql.ArgumentConfig{
				Type: graphql.String,
			},
			"act": &graphql.ArgumentConfig{
				Type: graphql.String,
			},
		},
		Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			sub, obj, act := p.Args["sub"].(string), p.Args["obj"].(string), p.Args["act"].(string)
			ok, err := e.AddPolicy(sub, obj, act)
			if err != nil {
				return nil, err
			}
			return Request{sub, obj, act, ok}, nil
		},
	})
	rootMutationObject.AddFieldConfig(enforcerGraphQLFieldName+"AuthDeletePolicy", &graphql.Field{
		Type:        requestType,
		Description: "Delete a policy",
		Args: graphql.FieldConfigArgument{
			"sub": &graphql.ArgumentConfig{
				Type: graphql.String,
			},
			"obj": &graphql.ArgumentConfig{
				Type: graphql.String,
			},
			"act": &graphql.ArgumentConfig{
				Type: graphql.String,
			},
		},
		Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			sub, obj, act := p.Args["sub"].(string), p.Args["obj"].(string), p.Args["act"].(string)
			ok, err := e.RemovePolicy(sub, obj, act)
			if err != nil {
				return nil, err
			}
			return Request{sub, obj, act, ok}, nil
		},
	})
	rootMutationObject.AddFieldConfig(enforcerGraphQLFieldName+"AuthUpdatePolicy", &graphql.Field{
		Type:        updatePolicyType,
		Description: "Update a policy",
		Args: graphql.FieldConfigArgument{
			"sub": &graphql.ArgumentConfig{
				Type: graphql.String,
			},
			"obj": &graphql.ArgumentConfig{
				Type: graphql.String,
			},
			"act": &graphql.ArgumentConfig{
				Type: graphql.String,
			},
			"oldSub": &graphql.ArgumentConfig{
				Type: graphql.String,
			},
			"oldObj": &graphql.ArgumentConfig{
				Type: graphql.String,
			},
			"oldAct": &graphql.ArgumentConfig{
				Type: graphql.String,
			},
		},
		Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			sub, obj, act := p.Args["sub"].(string), p.Args["obj"].(string), p.Args["act"].(string)
			oldSub, oldObj, oldAct := p.Args["oldSub"].(string), p.Args["oldObj"].(string), p.Args["oldAct"].(string)
			res, err := e.UpdatePolicy([]string{oldSub, oldObj, oldAct}, []string{sub, obj, act})
			if err != nil {
				return nil, err
			}
			return UpdatePolicy{sub, obj, act, oldSub, oldObj, oldAct, res}, nil
		},
	})
}
