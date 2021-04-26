package pkix

import (
	"testing"
)

func TestEmailAddress(t *testing.T) {
	name := &Name{
		Country:            []string{"US"},
		Organization:       []string{"Hot Wheels LLC"},
		OrganizationalUnit: []string{"Sweet Rides"},
		Locality:           []string{"San Francisco"},
		Province:           []string{"California"},
		CommonName:         "test.com",
		EmailAddress:       "fella@example.com",
	}

	got := name.String()
	want := "emailAddress=fella@example.com,CN=test.com,OU=Sweet Rides,O=Hot Wheels LLC,L=San Francisco,ST=California,C=US"
	if got != want {
		t.Errorf("name.String() = \"%s\"", got)
		t.Errorf("           want \"%s\"", want)
	}
}
