package audit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCheckKeyMode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mode fs.FileMode
		goos string
		want error
	}{
		{name: "owner only", mode: 0o600, goos: "linux", want: nil},
		{name: "owner read only", mode: 0o400, goos: "linux", want: nil},
		{name: "group readable", mode: 0o640, goos: "linux", want: ErrKeyExposed},
		{name: "world readable", mode: 0o644, goos: "darwin", want: ErrKeyExposed},
		{name: "world writable", mode: 0o602, goos: "linux", want: ErrKeyExposed},
		{name: "windows ignores unix bits", mode: 0o666, goos: "windows", want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkKeyMode(tc.mode, tc.goos)
			if !errors.Is(err, tc.want) {
				t.Fatalf("checkKeyMode(%#o, %s) = %v, want %v", tc.mode, tc.goos, err, tc.want)
			}
		})
	}
}

func TestLoadPrivateKeyRejectsExposedFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits")
	}
	t.Parallel()
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	exposed := filepath.Join(dir, "exposed.pem")
	if err := os.WriteFile(exposed, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(exposed, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(exposed); !errors.Is(err, ErrKeyExposed) {
		t.Fatalf("LoadPrivateKey on 0644 file = %v, want ErrKeyExposed", err)
	}
	private := filepath.Join(dir, "private.pem")
	if err := os.WriteFile(private, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(private); err != nil {
		t.Fatalf("LoadPrivateKey on 0600 file: %v", err)
	}
}
