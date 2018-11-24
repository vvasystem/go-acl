## go-acl

[![MIT License](http://img.shields.io/badge/license-MIT-9370d8.svg?style=flat)](http://opensource.org/licenses/MIT)

ACLs (Access Control Lists) is a lightweight acl manager for go

### Using the Package

To use the package add the following imports:

```go
import (
    acl "github.com/vvasystem/go-acl"
)
```

### Examples

#### Access to controller actions
```go
acl.AddResourceAccess(acl.ResUserPages, acl.ResourceAccess{
    acl.ARead: []int{acl.RUser},
    acl.ACreate: []int{acl.RSA},
    acl.AUpdate: []int{acl.RSA},
    acl.ADelete: []int{acl.RSA},
})
acl.AddActionAccess("index", "details", acl.ActionAccess{
    acl.ResUserPages: acl.ARead,
})

//or getting from session user
rights := []int{acl.RUser}

//and check access
if acl.HasActionAccess("index", "details", rights) {
    //...
}
```

#### Access to resource

add some constants
```go
const (
    TestRight1001    = 1001
    TestRight100101  = 100101
)
```

implementation User interface
```go
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
    return acl.HasResourceAccess(resourceType, accessType, tu.GetRights())
}
```

next...
```go
acl.AddResourceAccess(acl.ResUserPages, acl.ResourceAccess{
    acl.ARead: []int{TestRight100101},
    acl.ACreate: []int{TestRight1001},
    acl.AUpdate: []int{TestRight1001},
    acl.ADelete: []int{TestRight1001},
})

user := testUser{}
user.SetRights([]int{acl.RSA})

a := acl.GetInstance()
if a.CanDelete(acl.ResGuestPages, nil, user) {
    //...
}
```

#### Add own guards

implementation ResourceGuard interface
```go
type testResourceGuard struct {
}

func (rg *testResourceGuard) CheckResourceTypeAccess(accessType, resourceType int, context Resource, user User) bool {
    // some logic
    return true
}

func (rg *testResourceGuard) CheckResourceAccess(accessType int, resource, context Resource, user User) bool {
    // some logic
    return true
}
```

next...
```go
//use own guard or embedding DefaultResourceGuard
acl.AddResourceGuard(acl.ResUserPages, &testResourceGuard{})

user := testUser{}
user.SetRights([]int{acl.RUser})

a := acl.GetInstance()
if a.CanUpdate(acl.ResUserPages, nil, user) {
    //...
}
```