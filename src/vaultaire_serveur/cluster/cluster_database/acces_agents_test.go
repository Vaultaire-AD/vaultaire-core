package clusterdatabase

import (
	"reflect"
	"testing"
)

func TestAccesPourAgents(t *testing.T) {
	cas := []struct {
		ip, publique string
		port, public int
		attendu      []string
	}{
		{"172.19.0.5", "192.168.56.10", 6666, 6668, []string{"192.168.56.10:6668", "172.19.0.5:6666"}},
		{"10.0.0.2", "", 6666, 0, []string{"10.0.0.2:6666"}},
		{"10.0.0.2", "", 6666, 7000, []string{"10.0.0.2:7000", "10.0.0.2:6666"}},
		{"10.0.0.2", "", 0, 0, nil},
		{"fd00::2", "", 6666, 0, []string{"[fd00::2]:6666"}},
	}
	for _, c := range cas {
		if got := AccesPourAgents(c.ip, c.publique, c.port, c.public); !reflect.DeepEqual(got, c.attendu) {
			t.Errorf("%+v : %q", c, got)
		}
	}
}
