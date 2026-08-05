package check

import (
	"strings"
	"testing"
)

func known(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

func TestComponentValidate(t *testing.T) {
	defined := known("a", "b", "c")

	cases := []struct {
		name string
		c    Component
		want string // substring of the expected error, empty means valid
	}{
		{"any", Component{Name: "email", Checks: []string{"a", "b"}}, ""},
		{"explicit any", Component{Name: "email", Checks: []string{"a"}, DownIf: RollupAny}, ""},
		{"all", Component{Name: "mirrors", Checks: []string{"a", "b"}, DownIf: RollupAll}, ""},
		{"quorum", Component{Name: "dns", Checks: []string{"a", "b", "c"}, DownIf: RollupQuorum, DownAt: 2}, ""},

		{"no name", Component{Checks: []string{"a"}}, "name is required"},
		{"no checks", Component{Name: "email"}, "at least one check"},
		{"duplicate check", Component{Name: "email", Checks: []string{"a", "a"}}, "listed twice"},
		{"unknown check", Component{Name: "email", Checks: []string{"nope"}}, `no check named "nope"`},
		{"bad rollup", Component{Name: "email", Checks: []string{"a"}, DownIf: "most"}, "unknown down_if"},
		{"quorum without down_at", Component{Name: "dns", Checks: []string{"a", "b"}, DownIf: RollupQuorum}, "down_at"},
		// A threshold nothing can reach is a component that can never alert,
		// which is worse than no component at all.
		{"quorum beyond membership", Component{
			Name: "dns", Checks: []string{"a", "b"}, DownIf: RollupQuorum, DownAt: 3,
		}, "down_at"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.c.Validate(defined)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want an error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate() = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// A component defined before its checks exist is still checkable for internal
// consistency; only the cross-reference is skipped.
func TestComponentValidateWithoutKnownChecks(t *testing.T) {
	c := Component{Name: "email", Checks: []string{"anything"}}
	if err := c.Validate(nil); err != nil {
		t.Fatalf("Validate(nil) = %v, want nil", err)
	}
}

func TestRollAny(t *testing.T) {
	c := Component{Name: "email", Checks: []string{"a", "b", "c"}}

	cases := []struct {
		name   string
		status map[string]Status
		want   Status
	}{
		{"all up", map[string]Status{"a": StatusUp, "b": StatusUp, "c": StatusUp}, StatusUp},
		{"one down", map[string]Status{"a": StatusUp, "b": StatusDown, "c": StatusUp}, StatusDown},
		{"all down", map[string]Status{"a": StatusDown, "b": StatusDown, "c": StatusDown}, StatusDown},
		// One failing check satisfies the rule outright, so the others need not
		// have reported for the component to be down.
		{"down beats undecided", map[string]Status{"b": StatusDown}, StatusDown},
		// But nothing may read as up while a member is unaccounted for.
		{"undecided blocks up", map[string]Status{"a": StatusUp, "b": StatusUp}, StatusUnknown},
		{"nothing reported", map[string]Status{}, StatusUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.Roll(tc.status); got != tc.want {
				t.Errorf("Roll() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A pool of equivalent members is degraded when one fails, not down. Reporting
// an outage because a single mirror is unreachable is the false alert this
// whole project exists to remove, moved up a level.
func TestRollAll(t *testing.T) {
	c := Component{Name: "mirrors", Checks: []string{"a", "b", "c"}, DownIf: RollupAll}

	if got := c.Roll(map[string]Status{"a": StatusDown, "b": StatusUp, "c": StatusUp}); got != StatusUp {
		t.Errorf("one member down: Roll() = %q, want up", got)
	}
	if got := c.Roll(map[string]Status{"a": StatusDown, "b": StatusDown, "c": StatusDown}); got != StatusDown {
		t.Errorf("every member down: Roll() = %q, want down", got)
	}
	// Two down and one silent is not "all down" — the silent one may be fine,
	// and claiming an outage on its behalf is exactly the inference the
	// unknown status exists to prevent.
	if got := c.Roll(map[string]Status{"a": StatusDown, "b": StatusDown}); got != StatusUnknown {
		t.Errorf("two down, one silent: Roll() = %q, want unknown", got)
	}
}

func TestRollQuorum(t *testing.T) {
	c := Component{
		Name: "dns", Checks: []string{"a", "b", "c"},
		DownIf: RollupQuorum, DownAt: 2,
	}

	if got := c.Roll(map[string]Status{"a": StatusDown, "b": StatusUp, "c": StatusUp}); got != StatusUp {
		t.Errorf("below threshold: Roll() = %q, want up", got)
	}
	if got := c.Roll(map[string]Status{"a": StatusDown, "b": StatusDown, "c": StatusUp}); got != StatusDown {
		t.Errorf("at threshold: Roll() = %q, want down", got)
	}
	// The threshold is met; the third member's silence cannot un-meet it.
	if got := c.Roll(map[string]Status{"a": StatusDown, "b": StatusDown}); got != StatusDown {
		t.Errorf("threshold met with one silent: Roll() = %q, want down", got)
	}
}

// A check that stops reporting must not leave a component looking healthy.
func TestSilentCheckDoesNotReadAsUp(t *testing.T) {
	c := Component{Name: "email", Checks: []string{"a", "b"}}
	if got := c.Roll(map[string]Status{"a": StatusUp, "b": StatusUnknown}); got != StatusUnknown {
		t.Fatalf("Roll() = %q, want unknown — an undecided check is not a healthy one", got)
	}
}
