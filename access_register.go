package acl

import (
	"sync"
)

const (
	//RSA Super admin right
	RSA = 0
	//RUser auth user right
	RUser = 9
	//RGuest unauth user right
	RGuest = 99

	//ResGuestPages resource for guest
	ResGuestPages = 1
	//ResUserPages resource for auth user
	ResUserPages = 2

	//ACreate create access
	ACreate = 1
	//ARead read access
	ARead = 2
	//AUpdate update access
	AUpdate = 4
	//ADelete delete access
	ADelete = 8
)

type ActionAccess map[int]int

type ResourceAccess map[int][]int

type AccessRegister struct {
	mu             sync.RWMutex
	actionAccess   map[string]map[string]ActionAccess
	resourceAccess map[int]ResourceAccess
}

func (ar *AccessRegister) AddActionAccess(controllerName, actionName string, actionAccess ActionAccess) {
	ar.mu.Lock()
	defer ar.mu.Unlock()

	aa := make(map[string]ActionAccess)
	aa[actionName] = actionAccess
	ar.actionAccess[controllerName] = aa
}

func (ar *AccessRegister) AddResourceAccess(resourceType int, resourceAccess ResourceAccess) {
	ar.mu.Lock()
	defer ar.mu.Unlock()
	ar.resourceAccess[resourceType] = resourceAccess
}

func (ar *AccessRegister) GetActionAccesses() map[string]map[string]ActionAccess {
	ar.mu.RLock()
	defer ar.mu.RUnlock()
	return ar.actionAccess
}

func (ar *AccessRegister) GetResourceAccesses() map[int]ResourceAccess {
	ar.mu.RLock()
	defer ar.mu.RUnlock()
	return ar.resourceAccess
}
