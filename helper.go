package acl

var accessRegister = AccessRegister{
	actionAccess:   make(map[string]map[string]ActionAccess),
	resourceAccess: make(map[int]ResourceAccess),
}

func AddActionAccess(controllerName, actionName string, actionAccess ActionAccess) {
	accessRegister.AddActionAccess(controllerName, actionName, actionAccess)
}

func AddResourceAccess(resourceType int, resourceAccess ResourceAccess) {
	accessRegister.AddResourceAccess(resourceType, resourceAccess)
}

func HasActionAccess(controllerName, actionName string, rights []int) bool {
	if len(rights) == 0 {
		return false
	}
	if isRA(rights) {
		return true
	}
	actionList := accessRegister.GetActionAccesses()
	if _, ok := actionList[controllerName]; !ok {
		return false
	}
	if _, ok := actionList[controllerName][actionName]; !ok {
		return false
	}
	for resourceType, accessType := range actionList[controllerName][actionName] {
		if HasResourceAccess(resourceType, accessType, rights) {
			return true
		}
	}
	return false
}

func HasResourceAccess(resourceType, accessType int, rights []int) bool {
	resourceTypes := accessRegister.GetResourceAccesses()
	if _, ok := resourceTypes[resourceType]; !ok {
		return false
	}
	if _, ok := resourceTypes[resourceType][accessType]; !ok {
		return false
	}
	return HasRight(resourceTypes[resourceType][accessType], rights)
}

func HasRight(checkRights, rights []int) bool {
	if isRA(rights) {
		return true
	}

	rightsLeft := make(map[int]int)
	rightsRight := make(map[int]int)
	for n, right := range rights {
		rightsLeft[n] = padding(right)
		rightsRight[n] = padding(right+1) - 1
	}
	for _, accessRight := range checkRights {
		ar := padding(accessRight)
		for n := range rights {
			if ar >= rightsLeft[n] && ar <= rightsRight[n] {
				return true
			}
		}
	}

	return false
}

func isRA(rights []int) bool {
	for i := range rights {
		if rights[i] == RSA {
			return true
		}
	}
	return false
}

func padding(c int) int {
	for c != 0 && c <= 100000000 {
		c *= 10
	}
	return c
}
