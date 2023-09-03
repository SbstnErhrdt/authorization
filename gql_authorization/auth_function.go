package gql_authorization

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
