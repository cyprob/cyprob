package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type scanDebugTestOutput struct {
	Target          string `json:"target"`
	ResolvedTargets []struct {
		Input string `json:"input"`
		IP    string `json:"ip"`
	} `json:"resolved_targets"`
	OpenPorts []struct {
		Target    string `json:"target"`
		OpenPorts []int  `json:"open_ports"`
	} `json:"open_ports"`
	Banners []struct {
		IP     string `json:"ip"`
		Port   int    `json:"port"`
		Banner string `json:"banner"`
		Error  string `json:"error"`
	} `json:"banners"`
	Fingerprints []struct {
		Target  string `json:"target"`
		Port    int    `json:"port"`
		Product string `json:"product"`
	} `json:"fingerprints"`
	TechTags []struct {
		Target string   `json:"target"`
		Port   int      `json:"port"`
		Tags   []string `json:"tags"`
	} `json:"tech_tags"`
	Steps []struct {
		Step     string   `json:"step"`
		Errors   []string `json:"errors"`
		Warnings []string `json:"warnings"`
	} `json:"steps"`
}

func TestScanDebugTargetJSONSmoke(t *testing.T) {
	host, port, cleanup := startBannerTestServer(t)
	defer cleanup()

	cmd := NewCommand()
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs([]string{
		"scan-debug", "target", host,
		"--ports", fmt.Sprintf("%d", port),
		"--timeout", "2s",
		"--format", "json",
	})

	err := cmd.Execute()
	require.NoError(t, err, "stderr: %s", errOut.String())

	var payload scanDebugTestOutput
	require.NoError(t, json.Unmarshal(out.Bytes(), &payload))

	require.Equal(t, host, payload.Target)
	require.NotEmpty(t, payload.ResolvedTargets)
	require.True(t, containsPort(payload.OpenPorts, port), "expected open port %d in output", port)
	require.NotEmpty(t, payload.Banners)
	require.NotEmpty(t, payload.Fingerprints)
	require.NotEmpty(t, payload.TechTags)
	require.True(t, hasTag(payload.TechTags, "ssh"), "expected ssh tag in tech_tags")

	for _, step := range payload.Steps {
		require.Empty(t, step.Errors, "step %s has errors: %v", step.Step, step.Errors)
	}
}

func startBannerTestServer(t *testing.T) (string, int, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Write([]byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"))
				buf := make([]byte, 256)
				_, _ = c.Read(buf)
			}(conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	cleanup := func() {
		_ = ln.Close()
		<-done
	}
	return "127.0.0.1", addr.Port, cleanup
}

func containsPort(results []struct {
	Target    string `json:"target"`
	OpenPorts []int  `json:"open_ports"`
}, port int) bool {
	for _, result := range results {
		for _, p := range result.OpenPorts {
			if p == port {
				return true
			}
		}
	}
	return false
}

func hasTag(results []struct {
	Target string   `json:"target"`
	Port   int      `json:"port"`
	Tags   []string `json:"tags"`
}, tag string) bool {
	for _, result := range results {
		for _, t := range result.Tags {
			if t == tag {
				return true
			}
		}
	}
	return false
}
