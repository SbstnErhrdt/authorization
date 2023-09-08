package gql_authorization

import (
	"github.com/SbstnErhrdt/authorization"
	"github.com/graphql-go/graphql"
	"log/slog"
	"sync"
)

/*
// AppModuleGraphQlModel is a struct for the Module GraphQL model
var AppModuleGraphQlModel, _ = gql_auto.DefaultEncoder.Struct(&AppModule{},
	gql_auto.WithName("AuthorizationModule"),
	gql_auto.WithDescription("Authorization module encapsulates a part of the application"),
)
*/

type AppModule struct {
	lock       sync.RWMutex
	Name       string
	Order      int
	Policies   [][]string
	Functions  map[string]*AppFunction
	SubModules map[string]*AppSubModule
	Actions    map[string]string
}

func (am *AppModule) GetName() string {
	am.lock.RLock()
	defer am.lock.RUnlock()
	return am.Name
}

func (am *AppModule) GetOrder() int {
	am.lock.RLock()
	defer am.lock.RUnlock()
	return am.Order
}

func (am *AppModule) GetAllPolicies() ([][]string, error) {
	am.lock.RLock()
	defer am.lock.RUnlock()
	return am.Policies, nil
}

func (am *AppModule) GetActions() []string {
	am.lock.RLock()
	defer am.lock.RUnlock()
	results := []string{}
	for _, action := range am.Actions {
		results = append(results, action)
	}
	return results
}

func (am *AppModule) GetAllSubModules() (results []authorization.SubModule) {
	am.lock.RLock()
	defer am.lock.RUnlock()
	results = []authorization.SubModule{}
	for _, sm := range am.SubModules {
		results = append(results, sm)
	}
	return
}

func (am *AppModule) GetAllFunctions() (results []authorization.Function) {
	am.lock.RLock()
	defer am.lock.RUnlock()
	results = []authorization.Function{}
	for _, f := range am.Functions {
		results = append(results, f)
	}
	return
}

func (am *AppModule) AddGqlField(field *graphql.Field, action string, policies [][]string) {
	am.lock.Lock()
	defer am.lock.Unlock()

	// add function
	if field == nil {
		slog.With("moduleName", am.Name).Warn("can not add field to module")
		return
	}
	if am.Functions == nil {
		am.Functions = map[string]*AppFunction{}
	}
	// add function to module
	am.Functions[field.Name] = &AppFunction{
		Name:        field.Name,
		Description: field.Name,
		Action:      action,
		Policies:    policies,
	}
}
