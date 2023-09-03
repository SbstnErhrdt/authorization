package authorization

import (
	"fmt"
	"github.com/google/uuid"
	"log/slog"
	"sort"
	"sync"
)

// lock is the lock for registryModules
var lock sync.Mutex

// registryModules is the registry for modules
var registryModules = map[string]Module{}

// Register registers a module
func Register(module Module) {
	lock.Lock()
	registryModules[module.GetName()] = module
	lock.Unlock()
}

// GetAllPolicies returns all policies from all modules
func GetAllPolicies() (results [][]string, err error) {
	results = [][]string{}
	for _, module := range registryModules {
		policies, errPolicy := module.GetAllPolicies()
		if errPolicy != nil {
			slog.With("err", errPolicy).Error("could not get policies")
			return nil, errPolicy
		}
		// append policies
		results = append(results, policies...)
	}
	return results, nil
}

func GetAllModules() (results []Module) {
	results = []Module{}
	lock.Lock()
	for _, module := range registryModules {
		results = append(results, module)
	}
	lock.Unlock()
	// sort the modules
	sort.Slice(results, func(i, j int) bool {
		return results[i].GetOrder() < results[j].GetOrder()
	})
	return
}

func PrintRegistry() {
	for _, module := range GetAllModules() {
		fmt.Println("module:", module.GetName())
		for si, subModule := range module.GetAllSubModules() {
			if si == 0 {
				fmt.Println("sub modules:")
			}
			fmt.Println("\t", subModule.GetName())
			for fi, function := range subModule.GetAllFunctions() {
				if fi == 0 {
					fmt.Println("\t\tfunctions:")
				}
				fmt.Println("\t\t\t", function.GetName())
			}
		}
		for fi, function := range module.GetAllFunctions() {
			if fi == 0 {
				fmt.Println("\tfunctions:")
			}
			fmt.Println("\t\t", function.GetName())
		}
	}
}

// Module is the interface for authorization modules
type Module interface {
	GetName() string
	GetOrder() int
	GetAllPolicies() ([][]string, error)
	GetAllSubModules() (results []SubModule)
	GetAllFunctions() (results []Function)
}

// SubModule is the interface for authorization sub modules
type SubModule interface {
	GetName() string
	GetOrder() int
	GetAllPolicies() ([][]string, error)
	GetAllFunctions() (results []Function)
}

type Function interface {
	GetName() string
	GetDescription() string
	GetAction() string
	GetAllPolicies() ([][]string, error)
}

type Resource interface {
	GetUID() uuid.UUID
	GetType() string
}
