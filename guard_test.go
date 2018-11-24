package acl

import "testing"

const (
	TestRes1 = 3
	TestRes2 = 4

	TestRight1001    = 1001
	TestRight100101  = 100101
	TestRight1001011 = 1001011
)

type testUser struct {
	rights []int
}

func (tu *testUser) SetRights(rights []int) {
	tu.rights = rights
}

func (tu testUser) GetRights() []int {
	return tu.rights
}

func (tu testUser) HasResourceAccess(resourceType, accessType int) bool {
	return HasResourceAccess(resourceType, accessType, tu.GetRights())
}

type testResourceGuard struct {
}

func (rg *testResourceGuard) CheckResourceTypeAccess(accessType, resourceType int, context Resource, user User) bool {
	return true
}

func (rg *testResourceGuard) CheckResourceAccess(accessType int, resource, context Resource, user User) bool {
	return true
}

func TestGuard_AddResourceGuard_GetResourceGuard(t *testing.T) {
	t.Parallel()

	acl := GetInstance()

	resources := acl.getResourceGuards(TestRes1)
	if len(resources) != 1 {
		t.Error("Expected 1")
	}
	if _, ok := resources[0].(*DefaultResourceGuard); !ok {
		t.Error("Expected DefaultResourceGuard struct")
	}

	acl.AddResourceGuard(TestRes2, &testResourceGuard{})
	resources = acl.getResourceGuards(TestRes2)
	if len(resources) != 1 {
		t.Error("Expected 1")
	}
	if _, ok := resources[0].(*testResourceGuard); !ok {
		t.Error("Expected testResourceGuard struct")
	}
}

func TestGuard_CanRead(t *testing.T) {
	t.Parallel()

	AddResourceAccess(ResGuestPages, ResourceAccess{
		ARead: []int{RGuest},
	})
	AddResourceAccess(ResUserPages, ResourceAccess{
		ARead: []int{RUser},
	})

	user := testUser{}
	user.SetRights([]int{RGuest})

	acl := GetInstance()
	if !acl.CanRead(ResGuestPages, nil, user) {
		t.Error("Expected true")
	}

	user.SetRights([]int{})
	if acl.CanRead(ResUserPages, nil, user) {
		t.Error("Expected false")
	}
}

func TestGuard_CanCreate(t *testing.T) {
	t.Parallel()

	AddResourceAccess(ResGuestPages, ResourceAccess{
		ACreate: []int{RUser},
	})
	AddResourceAccess(ResUserPages, ResourceAccess{
		ACreate: []int{RSA},
	})

	user := testUser{}
	user.SetRights([]int{RSA})

	acl := GetInstance()
	if !acl.CanCreate(ResGuestPages, nil, user) {
		t.Error("Expected true")
	}

	user.SetRights([]int{RUser})
	if acl.CanCreate(ResUserPages, nil, user) {
		t.Error("Expected false")
	}
}

func TestGuard_CanUpdate(t *testing.T) {
	t.Parallel()

	AddResourceAccess(ResGuestPages, ResourceAccess{
		AUpdate: []int{TestRight100101},
	})
	AddResourceAccess(ResUserPages, ResourceAccess{
		AUpdate: []int{TestRight1001},
	})

	user := testUser{}
	user.SetRights([]int{TestRight1001})

	acl := GetInstance()
	if !acl.CanUpdate(ResGuestPages, nil, user) {
		t.Error("Expected true")
	}

	user.SetRights([]int{TestRight100101})
	if acl.CanUpdate(ResUserPages, nil, user) {
		t.Error("Expected false")
	}
}

func TestGuard_CanDelete(t *testing.T) {
	t.Parallel()

	AddResourceAccess(ResGuestPages, ResourceAccess{
		ADelete: []int{RSA},
	})
	AddResourceAccess(ResUserPages, ResourceAccess{
		ADelete: []int{TestRight1001011},
	})

	user := testUser{}
	user.SetRights([]int{RSA})

	acl := GetInstance()
	if !acl.CanDelete(ResGuestPages, nil, user) {
		t.Error("Expected true")
	}

	user.SetRights([]int{RUser})
	if acl.CanDelete(ResUserPages, nil, user) {
		t.Error("Expected false")
	}
}
