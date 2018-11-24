package acl

type User interface {
	HasResourceAccess(resourceType, accessType int) bool
}
