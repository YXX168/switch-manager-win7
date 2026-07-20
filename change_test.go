package main

import "testing"

func TestValidateChangeScriptAllowsControlledChanges(t *testing.T) {
	allowed := []string{"system-view\ninterface GigabitEthernet1/0/1\ndescription Uplink", "system-view\nvlan 120\nname OFFICE", "system-view\ninterface GigabitEthernet1/0/2\nundo shutdown"}
	for _, script := range allowed {
		if err := validateChangeScript(script); err != nil {
			t.Errorf("expected allowed script, got %v", err)
		}
	}
}

func TestValidateChangeScriptBlocksCriticalOperations(t *testing.T) {
	blocked := []string{"reboot", "reset saved-configuration", "format flash:", "delete flash:/vrpcfg.zip", "save force", "system-view\nip address 10.0.0.1 24", "local-user admin password cipher test", "undo stelnet server enable", "display version; reboot"}
	for _, script := range blocked {
		if err := validateChangeScript(script); err == nil {
			t.Errorf("expected %q to be blocked", script)
		}
	}
}
