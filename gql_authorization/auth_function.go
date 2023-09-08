package gql_authorization

/*
var AppFunctionGraphQlModel, _ = gql_auto.DefaultEncoder.Struct(&AppModule{},
	gql_auto.WithName("AuthorizationFunction"),
	gql_auto.WithDescription("Authorization functions represent a function in the application"),
)
*/

type AppFunction struct {
	Name        string
	Description string
	Action      string
	Policies    [][]string
}

func (af *AppFunction) GetName() string {
	return af.Name
}

func (af *AppFunction) GetDescription() string {
	return af.Description
}

func (af *AppFunction) GetAction() string {
	return af.Action
}

func (af *AppFunction) GetAllPolicies() ([][]string, error) {
	return af.Policies, nil
}
