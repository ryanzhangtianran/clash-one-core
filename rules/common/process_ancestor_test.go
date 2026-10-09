package common

import (
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

const ancestorHelperEnv = "PROCESS_ANCESTOR_HELPER"

// TestProcessAncestorHelper is the child process: it lives until the parent closes its stdin.
func TestProcessAncestorHelper(t *testing.T) {
	if os.Getenv(ancestorHelperEnv) == "" {
		t.Skip("helper process only")
	}
	io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

func TestProcessAncestor(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("ancestor lookup is implemented for darwin and linux")
	}
	self, err := os.Executable()
	require.NoError(t, err)
	self, err = filepath.EvalSymlinks(self)
	require.NoError(t, err)

	// FindProcess reports the pid. Own socket only: macOS hides other processes' sockets from
	// non-root, which is fine in production since TUN mode runs as root.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	src := conn.LocalAddr().(*net.TCPAddr).AddrPort()
	_, pid, _, err := process.FindProcess(process.TCP, src.Addr(), int(src.Port()))
	require.NoError(t, err)
	require.Equal(t, uint32(os.Getpid()), pid)

	// a renamed copy, so the child's own name differs from its parent's
	child := filepath.Join(t.TempDir(), "ancestor-child")
	b, err := os.ReadFile(self)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(child, b, 0o755))
	cmd := exec.Command(child, "-test.run=^TestProcessAncestorHelper$")
	cmd.Env = append(os.Environ(), ancestorHelperEnv+"=1")
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	defer cmd.Wait()
	defer stdin.Close()

	metadata := &C.Metadata{Pid: uint32(cmd.Process.Pid), ProcessPath: child}
	match := func(ruleType C.RuleType, payload string) bool {
		rule, err := NewProcessAncestor(payload, "DIRECT", ruleType)
		require.NoError(t, err)
		ok, _ := rule.Match(metadata, C.RuleMatchHelper{})
		return ok
	}
	require.True(t, match(C.ProcessAncestor, "ancestor-child"), "the process itself")
	require.True(t, match(C.ProcessAncestor, filepath.Base(self)), "parent by name")
	require.True(t, match(C.ProcessAncestorPath, self), "parent by path")
	require.False(t, match(C.ProcessAncestor, "no-such-process"))

	metadata.Pid = 0 // without a pid only the process itself can match
	require.False(t, match(C.ProcessAncestor, filepath.Base(self)))
}
