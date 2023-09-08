package authorization

import (
	"math/rand"
	"strconv"
	"sync"
	"testing"
	"time"
)

type TestModule struct {
	Name       string
	Order      int
	Policies   [][]string
	SubModules []SubModule
}

func (tm *TestModule) GetActions() (results []string) {
	//TODO implement me
	panic("implement me")
}

func (tm *TestModule) GetName() string {
	return tm.Name
}

func (tm *TestModule) GetOrder() int {
	return tm.Order
}

func (tm *TestModule) GetAllPolicies() ([][]string, error) {
	return tm.Policies, nil
}

func (tm *TestModule) GetAllSubModules() (results []SubModule) {
	return
}

func (tm *TestModule) GetAllFunctions() (results []Function) {
	return
}

type TestSubModule struct {
	Name     string
	Order    int
	Policies [][]string
}

func TestRegister(t *testing.T) {
	Register(&TestModule{
		Name:  "TestModule",
		Order: 1,
		Policies: [][]string{
			{`r.sub.MandateUID == r.obj.MandateUID && r.obj.ClientUID in (r.sub.ClientUIDs)`, "MandateClientModule", "read"},
		},
	})

	ms := GetAllModules()
	if len(ms) != 1 {
		t.Error("should have one module")
		return
	}

	// register module at registry
	Register(&TestModule{
		Name:  "TestModule2",
		Order: 2,
		Policies: [][]string{
			{`r.sub.IdentityUID == r.obj.IdentityUID`, "IdentityModule", "read"},
		},
	})

	ms = GetAllModules()
	if len(ms) != 2 {
		t.Error("should have two modules")
		return
	}

	ps, err := GetAllPolicies()
	if err != nil {
		t.Error(err)
		return
	}
	if len(ps) != 2 {
		t.Error("should have two policies")
		return
	}
}

func TestGetAllModules(t *testing.T) {
	const amount = 100
	var s sync.WaitGroup
	for i := 0; i < amount; i++ {
		s.Add(1)
		go func(i int) {
			sleep := time.Duration(rand.Intn(1000)) * time.Millisecond
			time.Sleep(sleep)
			Register(&TestModule{
				Name:  "TestModule" + strconv.Itoa(i),
				Order: i,
			})
			s.Done()
		}(i)
	}
	s.Wait()

	ms := GetAllModules()
	if len(ms) != amount {
		t.Error("should have 1000 modules")
		return
	}
	// check order
	for i := 0; i < amount; i++ {
		if ms[i].GetOrder() != i {
			t.Error("should have correct order")
			return
		}
	}

}
