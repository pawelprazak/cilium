// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package identitymanager

import (
	"testing"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type IdentityManagerTestSuite struct{}

var (
	_ = Suite(&IdentityManagerTestSuite{})

	idFooSelectLabels = labels.NewLabelsFromModel([]string{"id=foo"})
	idBarSelectLabels = labels.NewLabelsFromModel([]string{"id=bar"})
	fooIdentity       = identity.NewIdentity(identity.NumericIdentity(12345), idFooSelectLabels)
	barIdentity       = identity.NewIdentity(identity.NumericIdentity(54321), idBarSelectLabels)
)

func (s *IdentityManagerTestSuite) TestIdentityManagerLifecycle(c *C) {
	idm := NewIdentityManager()
	c.Assert(idm.identities, Not(IsNil))

	_, exists := idm.identities[fooIdentity.ID]
	c.Assert(exists, Equals, false)

	idm.Add(fooIdentity)
	c.Assert(idm.identities[fooIdentity.ID].refCount, Equals, uint(1))

	idm.Add(fooIdentity)
	c.Assert(idm.identities[fooIdentity.ID].refCount, Equals, uint(2))

	idm.Add(barIdentity)
	c.Assert(idm.identities[barIdentity.ID].refCount, Equals, uint(1))

	idm.Remove(fooIdentity)
	c.Assert(idm.identities[fooIdentity.ID].refCount, Equals, uint(1))

	idm.Remove(fooIdentity)
	_, exists = idm.identities[fooIdentity.ID]
	c.Assert(exists, Equals, false)

	_, exists = idm.identities[barIdentity.ID]
	c.Assert(exists, Equals, true)

	idm.Remove(barIdentity)
	_, exists = idm.identities[barIdentity.ID]
	c.Assert(exists, Equals, false)

	idm.Add(fooIdentity)
	_, exists = idm.identities[fooIdentity.ID]
	c.Assert(exists, Equals, true)
	idm.RemoveOldAddNew(fooIdentity, barIdentity)
	_, exists = idm.identities[fooIdentity.ID]
	c.Assert(exists, Equals, false)
	_, exists = idm.identities[barIdentity.ID]
	c.Assert(exists, Equals, true)
}

type identityManagerObserver struct {
	removed []identity.NumericIdentity
}

func newIdentityManagerObserver() *identityManagerObserver {
	return &identityManagerObserver{
		removed: make([]identity.NumericIdentity, 0),
	}
}

func (i *identityManagerObserver) LocalEndpointIdentityRemoved(identity *identity.Identity) {
	i.removed = append(i.removed, identity.ID)
}

func (s *IdentityManagerTestSuite) TestIdentityManagerObservers(c *C) {
	idm := NewIdentityManager()
	c.Assert(idm.identities, NotNil)
	observer := newIdentityManagerObserver()
	idm.subscribe(observer)

	// Basic remove
	idm.Add(fooIdentity)
	idm.Remove(fooIdentity)
	expectedObserver := &identityManagerObserver{
		[]identity.NumericIdentity{fooIdentity.ID},
	}
	c.Assert(observer, checker.DeepEquals, expectedObserver)

	idm = NewIdentityManager()
	c.Assert(idm.identities, NotNil)
	observer = newIdentityManagerObserver()
	idm.subscribe(observer)

	// Refcount remove
	idm.Add(fooIdentity)    // foo = 1
	idm.Add(fooIdentity)    // foo = 2
	idm.Add(barIdentity)    // bar = 1
	idm.Remove(fooIdentity) // foo = 1
	expectedObserver = &identityManagerObserver{
		[]identity.NumericIdentity{},
	}
	c.Assert(observer, checker.DeepEquals, expectedObserver)
	idm.Remove(fooIdentity) // foo = 0
	expectedObserver = &identityManagerObserver{
		[]identity.NumericIdentity{fooIdentity.ID},
	}
	c.Assert(observer, checker.DeepEquals, expectedObserver)
	idm.Remove(barIdentity) // bar = 0
	expectedObserver = &identityManagerObserver{
		[]identity.NumericIdentity{fooIdentity.ID, barIdentity.ID},
	}
	c.Assert(observer, checker.DeepEquals, expectedObserver)
}
