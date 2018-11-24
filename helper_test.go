package acl

import "testing"

const (
	TestRight5001    = 5001
	TestRight500101  = 500101
	TestRight5001011 = 5001011
)

func TestHasActionAccess(t *testing.T) {
	t.Parallel()

	AddResourceAccess(ResUserPages, ResourceAccess{ARead: []int{RUser}})
	AddActionAccess("index", "details", ActionAccess{
		ResUserPages: ARead,
	})

	if !HasActionAccess("index", "details", []int{RUser}) {
		t.Error("Expected true")
	}

	if HasActionAccess("index", "details", []int{RGuest}) {
		t.Error("Expected false")
	}
	if HasActionAccess("details", "index", []int{RUser}) {
		t.Error("Expected false")
	}
}

func TestHasResourceAccess(t *testing.T) {
	t.Parallel()

	AddResourceAccess(ResUserPages, ResourceAccess{ARead: []int{RUser}})

	if !HasResourceAccess(ResUserPages, ARead, []int{RUser}) {
		t.Error("Expected true")
	}

	if HasResourceAccess(ResUserPages, AUpdate, []int{RUser}) {
		t.Error("Expected false")
	}
}

func TestHasRight(t *testing.T) {
	t.Parallel()

	if !HasRight([]int{RUser}, []int{RSA}) {
		t.Error("Expected true")
	}

	if HasRight([]int{RUser}, []int{RGuest}) {
		t.Error("Expected false")
	}

	if !HasRight([]int{TestRight500101}, []int{TestRight5001}) {
		t.Error("Expected true")
	}

	if HasRight([]int{TestRight5001011}, []int{RUser}) {
		t.Error("Expected false")
	}
}
