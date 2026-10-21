package sshd

import "testing"

func TestFakeCommandIsSimulated(t *testing.T) {
	cwd := "/root"
	output, exit := fakeCommand("whoami", &cwd)
	if exit || output != "root\n" {
		t.Fatalf("whoami result = %q, exit=%v", output, exit)
	}
	output, exit = fakeCommand("cat /etc/passwd", &cwd)
	if exit || output == "" || output[0:4] != "root" {
		t.Fatalf("fake passwd output = %q, exit=%v", output, exit)
	}
}
