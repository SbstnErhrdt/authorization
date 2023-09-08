package gql_authorization

import (
	"github.com/SbstnErhrdt/authorization"
	"github.com/SbstnErhrdt/gql_auto"
	"github.com/graphql-go/graphql"
	"log/slog"
)

// AppModuleGraphQlModel is a struct for the Module GraphQL model
var AppSubModuleGraphQlModel, _ = gql_auto.DefaultEncoder.Struct(&AppSubModule{},
	gql_auto.WithName("AuthorizationSubModule"),
	gql_auto.WithDescription("Authorization sub module is a child of a module"),
)

type AppSubModule struct {
	Name      string
	Order     int
	Policies  [][]string
	Actions   map[string]string
	Functions map[string]*AppFunction
}

func (am *AppSubModule) GetName() string {
	return am.Name
}

func (am *AppSubModule) GetOrder() int {
	return am.Order
}

func (am *AppSubModule) GetAllPolicies() ([][]string, error) {
	results := [][]string{}
	for _, f := range am.Functions {
		policies, err := f.GetAllPolicies()
		if err != nil {
			return nil, err
		}
		results = append(results, policies...)
	}
	results = append(results, am.Policies...)
	return am.Policies, nil
}

func (am *AppSubModule) GetAllFunctions() (results []authorization.Function) {
	results = []authorization.Function{}
	for _, f := range am.Functions {
		results = append(results, f)
	}
	return
}

func (am *AppSubModule) AddGqlField(field *graphql.Field, action string, policies [][]string) {
	if field == nil {
		slog.With("subModuleName", am.Name).Warn("can not add field to sub module")
		return
	}
	if am.Functions == nil {
		am.Functions = map[string]*AppFunction{}
	}
	// check if field.Name is already in functions
	am.Functions[field.Name] = &AppFunction{
		Name:        field.Name,
		Description: field.Name,
		Action:      action,
		Policies:    policies,
	}
}
