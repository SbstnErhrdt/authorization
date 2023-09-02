package authorization

import (
	"github.com/stretchr/testify/assert"
	"log/slog"
	"testing"
)

func TestABAC(t *testing.T) {
	ass := assert.New(t)

	// mandates clients identities
	mandate1 := "f9178657-6829-4329-946e-d2a14baab99f"
	client1 := "22f1eba6-d98b-42ab-8071-1760034c6982"
	identity1 := "bd920ebb-5eba-4958-a178-9b14162fcc93"

	mandate2 := "3def47b8-cbf5-4a2c-9d43-308bfd3abed5"
	client2 := "4d19007a-de03-4e78-9f4e-aeb36d71f254"
	identity2 := "ca2acdc8-b63b-4291-8535-9abaa4afa075"

	// mandateModule checks if mandate params are set
	mandateModule := TestModule{
		Name:  "MandateModule1",
		Order: 1,
		Policies: [][]string{
			{`r.sub.MandateUID in (r.obj.MandateUIDs)`, "MandateModule1", "read"},
		},
	}
	// Register Module
	Register(&mandateModule)

	// register module at registry
	mandateClientModule := TestModule{
		Name:  "MandateClientModule",
		Order: 1,
		Policies: [][]string{
			{`r.sub.MandateUID == r.obj.MandateUID && r.obj.ClientUID in (r.sub.ClientUIDs)`, "MandateClientModule", "read"},
		},
	}
	Register(&mandateClientModule)

	// register module at registry
	identityModule := TestModule{
		Name:  "IdentityModule",
		Order: 1,
		Policies: [][]string{
			{`r.sub.IdentityUID == r.obj.IdentityUID`, "IdentityModule", "read"},
		},
	}
	Register(&identityModule)

	// init enforcer

	e := NewAbacEnforcer()
	SetDefaultEnforcer(e)

	ps, err := GetAllPolicies()
	if err != nil {
		t.Error(err)
		return
	}
	_, _ = DefaultEnforcer.AddPolicies(ps)

	type testReq struct {
		MandateUID  string
		ClientUIDs  []interface{}
		IdentityUID string
	}

	r1 := testReq{
		MandateUID:  mandate1,
		ClientUIDs:  []interface{}{client1},
		IdentityUID: identity1,
	}

	r2 := testReq{
		MandateUID:  mandate2,
		ClientUIDs:  []interface{}{client2},
		IdentityUID: identity2,
	}

	type testObj struct {
		Name         string
		IdentityUID  string
		IdentityUIDs []interface{}
		MandateUID   string
		MandateUIDs  []interface{}
		ClientUID    string
		ClientUIDs   []interface{}
	}

	obj1 := testObj{
		Name:        "MandateModule1",
		MandateUIDs: []interface{}{mandate1},
	}

	// check if request 1 can access obj1
	ok, err := e.Enforce(r1, obj1, "read")
	if err != nil {
		slog.With("err", err).Error("")
		ass.NoError(err)
		return
	}
	ass.True(ok) // YES

	// check if different request can access the same obj
	ok, err = e.Enforce(r2, obj1, "read")
	if err != nil {
		slog.With("err", err).Error("")
		ass.NoError(err)
		return
	}
	ass.False(ok) // NO

	// check if different operation
	ok, err = e.Enforce(r1, obj1, "xxx")
	if err != nil {
		slog.With("err", err).Error("")
		ass.NoError(err)
		return
	}
	ass.False(ok) // NO

	// check if different object
	ok, err = e.Enforce(r1, testObj{Name: "Module2", MandateUIDs: []interface{}{mandate2}}, "read")
	if err != nil {
		slog.With("err", err).Error("")
		ass.NoError(err)
		return
	}
	ass.False(ok) // NO

	// Check Mandate client Module
	// here the mandate uid and the client uid must match

	ok, err = e.Enforce(r1, testObj{Name: "MandateClientModule", MandateUID: mandate1, ClientUID: client1}, "read")
	if err != nil {
		slog.With("err", err).Error("")
		ass.NoError(err)
		return
	}
	ass.True(ok) // Yes

	// now with a different request
	ok, err = e.Enforce(r2, testObj{Name: "MandateClientModule", MandateUID: mandate1, ClientUID: client1}, "read")
	if err != nil {
		slog.With("err", err).Error("")
		ass.NoError(err)
		return
	}
	ass.False(ok)

	// now with a different request
	ok, err = e.Enforce(
		testReq{
			MandateUID:  mandate2,
			ClientUIDs:  []interface{}{client1, client2},
			IdentityUID: identity1,
		},
		testObj{
			Name:       "MandateClientModule",
			MandateUID: mandate2,
			ClientUID:  client1,
		},
		"read")
	if err != nil {
		slog.With("err", err).Error("")
		ass.NoError(err)
		return
	}
	ass.True(ok)

	// Identities test
	// now with a different request
	ok, err = e.Enforce(
		testReq{
			MandateUID:  mandate2,
			ClientUIDs:  []interface{}{client1, client2},
			IdentityUID: identity1,
		},
		testObj{
			Name:        "IdentityModule",
			IdentityUID: identity1,
		},
		"read")
	if err != nil {
		slog.With("err", err).Error("")
		ass.NoError(err)
		return
	}
	ass.True(ok) // YES

	// now with a different obj identity
	ok, err = e.Enforce(
		testReq{
			MandateUID:  mandate2,
			ClientUIDs:  []interface{}{client1, client2},
			IdentityUID: identity1,
		},
		testObj{
			Name:        "IdentityModule",
			IdentityUID: identity2,
		},
		"read")
	if err != nil {
		slog.With("err", err).Error("")
		ass.NoError(err)
		return
	}
	ass.False(ok) // NO

	/*

		ok, err = e.AddPolicy(`r.sub.MandateUID == "`+mandate1+`"`, "data1", "write")
		if err != nil {
			slog.With("err", err).Error("")
			return
		}

		ok, err = e.AddPolicy(`r.sub.MandateUID == "`+mandate2+`"`, "data2", "read")
		if err != nil {
			slog.With("err", err).Error("")
			return
		}

		ok, err = e.AddPolicy(`r.sub.MandateUID == "`+mandate2+`"`, "data2", "write")
		if err != nil {
			slog.With("err", err).Error("")
			return
		}

		// bob is not in mandate1
		ok, err = e.Enforce(r1, obj1, "read")
		if err != nil {
			slog.With("err", err).Error("")
			ass.NoError(err)
			return
		}
		ass.False(ok)

		// bob is can not access d1
		ok, err = e.Enforce(r2, obj1, "read")
		if err != nil {
			slog.With("err", err).Error("")
			ass.NoError(err)
			return
		}
		ass.False(ok)

		// bob is can access d2
		ok, err = e.Enforce(r2, obj1, "read")
		if err != nil {
			slog.With("err", err).Error("")
			ass.NoError(err)
			return
		}
		ass.True(ok)

		// Modify the policy.
		// e.AddPolicy(...)
		// e.RemovePolicy(...)
	*/

	slog.Info("done")
}
