package acl

type ResourceGuard interface {
	CheckResourceTypeAccess(accessType, resourceType int, context Resource, user User) bool
	CheckResourceAccess(accessType int, resource, context Resource, user User) bool
}

type DefaultResourceGuard struct {
}

func (dr *DefaultResourceGuard) CheckResourceTypeAccess(accessType, resourceType int, context Resource, user User) bool {
	switch accessType {
	case ARead:
		return dr.CanRead(resourceType, context, user)
	case ACreate:
		return dr.CanCreate(resourceType, context, user)
	case AUpdate:
		return dr.CanUpdate(resourceType, context, user)
	case ADelete:
		return dr.CanDelete(resourceType, context, user)
	}
	return false
}

func (dr *DefaultResourceGuard) CheckResourceAccess(accessType int, resource, context Resource, user User) bool {
	switch accessType {
	case ARead:
		return dr.CheckRead(resource, context, user)
	case ACreate:
		return dr.CheckCreate(resource, context, user)
	case AUpdate:
		return dr.CheckUpdate(resource, context, user)
	case ADelete:
		return dr.CheckDelete(resource, context, user)
	}
	return false
}

func (dr *DefaultResourceGuard) CanRead(resourceType int, context Resource, user User) bool {
	if context != nil {
		_ = context.GetResourceType()
	}
	return user.HasResourceAccess(resourceType, ARead)
}

func (dr *DefaultResourceGuard) CanCreate(resourceType int, context Resource, user User) bool {
	if context != nil {
		_ = context.GetResourceType()
	}
	return user.HasResourceAccess(resourceType, ACreate)
}

func (dr *DefaultResourceGuard) CanUpdate(resourceType int, context Resource, user User) bool {
	if context != nil {
		_ = context.GetResourceType()
	}
	return user.HasResourceAccess(resourceType, AUpdate)
}

func (dr *DefaultResourceGuard) CanDelete(resourceType int, context Resource, user User) bool {
	if context != nil {
		_ = context.GetResourceType()
	}
	return user.HasResourceAccess(resourceType, ADelete)
}

func (dr *DefaultResourceGuard) CheckRead(resource Resource, context Resource, user User) bool {
	return dr.CanRead(resource.GetResourceType(), context, user)
}

func (dr *DefaultResourceGuard) CheckCreate(resource Resource, context Resource, user User) bool {
	return dr.CanCreate(resource.GetResourceType(), context, user)
}

func (dr *DefaultResourceGuard) CheckUpdate(resource Resource, context Resource, user User) bool {
	return dr.CanUpdate(resource.GetResourceType(), context, user)
}

func (dr *DefaultResourceGuard) CheckDelete(resource Resource, context Resource, user User) bool {
	return dr.CanDelete(resource.GetResourceType(), context, user)
}
