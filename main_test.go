package main

import "testing"

func TestValidateReadOnlyCommandAllowsDisplayQueries(t *testing.T) {
	allowed := []string{
		"display version",
		"DISPLAY INTERFACE BRIEF",
		" display current-configuration ",
		"display vlan\ndisplay mac-address",
		"display current-configuration | include sysname",
	}
	for _, command := range allowed {
		if err := validateReadOnlyCommand(command); err != nil {
			t.Errorf("expected %q to be allowed, got %v", command, err)
		}
	}
}

func TestValidateReadOnlyCommandBlocksChanges(t *testing.T) {
	blocked := []string{
		"system-view",
		"save",
		"reboot",
		"reset saved-configuration",
		"delete flash:/config.cfg",
		"undo interface GigabitEthernet1/0/1",
		"display version\nsystem-view",
		"display version; reboot",
		"display version && reboot",
	}
	for _, command := range blocked {
		if err := validateReadOnlyCommand(command); err == nil {
			t.Errorf("expected %q to be blocked", command)
		}
	}
}
