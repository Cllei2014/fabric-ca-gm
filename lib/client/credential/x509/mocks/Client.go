/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
// Code generated by mockery v1.0.0

package mocks

import bccsp "github.com/tw-bc-group/fabric-gm/bccsp"
import credential "github.com/tw-bc-group/fabric-ca-gm/lib/client/credential"
import mock "github.com/stretchr/testify/mock"
import x509 "github.com/tw-bc-group/fabric-ca-gm/lib/client/credential/x509"

// Client is an autogenerated mock type for the Client type
type Client struct {
	mock.Mock
}

// GetCSP provides a mock function with given fields:
func (_m *Client) GetCSP() bccsp.BCCSP {
	ret := _m.Called()

	var r0 bccsp.BCCSP
	if rf, ok := ret.Get(0).(func() bccsp.BCCSP); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(bccsp.BCCSP)
		}
	}

	return r0
}

// NewX509Identity provides a mock function with given fields: name, creds
func (_m *Client) NewX509Identity(name string, creds []credential.Credential) x509.Identity {
	ret := _m.Called(name, creds)

	var r0 x509.Identity
	if rf, ok := ret.Get(0).(func(string, []credential.Credential) x509.Identity); ok {
		r0 = rf(name, creds)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(x509.Identity)
		}
	}

	return r0
}
