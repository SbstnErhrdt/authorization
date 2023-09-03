package gql_authorization

import (
	"github.com/SbstnErhrdt/authorization"
	"github.com/graphql-go/graphql"
	"log/slog"
)

type AppModule struct {
	Name       string
	Order      int
	Policies   [][]string
	Functions  map[string]*AppFunction
	SubModules map[string]*AppSubModule
}

func (am *AppModule) GetName() string {
	return am.Name
}

func (am *AppModule) GetOrder() int {
	return am.Order
}

func (am *AppModule) GetAllPolicies() ([][]string, error) {
	return am.Policies, nil
}

func (am *AppModule) GetAllSubModules() (results []authorization.SubModule) {
	results = []authorization.SubModule{}
	for _, sm := range am.SubModules {
		results = append(results, sm)
	}
	return
}

func (am *AppModule) GetAllFunctions() (results []authorization.Function) {
	results = []authorization.Function{}
	for _, f := range am.Functions {
		results = append(results, f)
	}
	return
}

func (am *AppModule) AddGqlField(field *graphql.Field, action string, policies [][]string) {
	if field == nil {
		slog.With("moduleName", am.Name).Warn("can not add field to module")
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
