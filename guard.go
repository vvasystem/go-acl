package acl

import (
	"sync"
)

type Resource interface {
	GetResourceType() int
}

type Guard struct {
	mu            sync.RWMutex
	resourceGuard map[int][]ResourceGuard
}

var instance *Guard
var once sync.Once

func GetInstance() *Guard {
	once.Do(func() {
		instance = &Guard{
			resourceGuard: make(map[int][]ResourceGuard),
		}
	})
	return instance
}

func (g *Guard) AddResourceGuard(resourceType int, resourceGuard ResourceGuard) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.resourceGuard[resourceType] = append(g.resourceGuard[resourceType], resourceGuard)
}

func (g *Guard) getResourceGuards(resourceType int) []ResourceGuard {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if _, ok := g.resourceGuard[resourceType]; !ok {
		return []ResourceGuard{&DefaultResourceGuard{}}
	}
	return g.resourceGuard[resourceType]
}

func (g *Guard) CanRead(resourceType int, context Resource, user User) bool {
	return g.checkResourceTypeAccess(ARead, resourceType, context, user)
}

func (g *Guard) CanCreate(resourceType int, context Resource, user User) bool {
	return g.checkResourceTypeAccess(ACreate, resourceType, context, user)
}

func (g *Guard) CanUpdate(resourceType int, context Resource, user User) bool {
	return g.checkResourceTypeAccess(AUpdate, resourceType, context, user)
}

func (g *Guard) CanDelete(resourceType int, context Resource, user User) bool {
	return g.checkResourceTypeAccess(ADelete, resourceType, context, user)
}

func (g *Guard) checkResourceTypeAccess(accessType, resourceType int, context Resource, user User) bool {
	resourceGuards := g.getResourceGuards(resourceType)
	for _, resourceGuard := range resourceGuards {
		if resourceGuard.CheckResourceTypeAccess(accessType, resourceType, context, user) {
			return true
		}
	}
	return false
}

func (g *Guard) CheckRead(resource Resource, context Resource, user User) bool {
	return g.CanRead(resource.GetResourceType(), context, user)
}

func (g *Guard) CheckCreate(resource Resource, context Resource, user User) bool {
	return g.CanCreate(resource.GetResourceType(), context, user)
}

func (g *Guard) CheckUpdate(resource Resource, context Resource, user User) bool {
	return g.CanUpdate(resource.GetResourceType(), context, user)
}

func (g *Guard) CheckDelete(resource Resource, context Resource, user User) bool {
	return g.CanDelete(resource.GetResourceType(), context, user)
}
