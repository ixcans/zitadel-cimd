package publicfetch

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"https://client.example.com/metadata", false},
		{"https://client.example.com:443/metadata", false},
		{"HTTPS://client.example.com/metadata", false},
		{"https://8.8.8.8/metadata", false},
		{"https://[2606:4700:4700::1111]/metadata", false},
		{"https://client.example.com:8443/metadata", true},
		{"https://client.example.com:80/metadata", true},
		{"http://client.example.com/metadata", true},
		{"ftp://client.example.com/metadata", true},
		{"https:///metadata", true},
		{"https://127.0.0.1/metadata", true},
		{"https://[::1]/metadata", true},
		{"https://169.254.169.254/latest/meta-data", true},
		{"https://[fd00::1]/metadata", true},
		{"https://[64:ff9b::a9fe:a9fe]/metadata", true},
		{"https://10.0.0.1:443/metadata", true},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			require.NoError(t, err)
			err = CheckURL(u)
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrDenied)
				return
			}
			assert.NoError(t, err)
		})
	}
	t.Run("nil URL", func(t *testing.T) {
		assert.ErrorIs(t, CheckURL(nil), ErrDenied)
	})
}

// TestTransport_dialTimeCheck pins that the address rule runs on the address a connection is
// actually made to: a hostname that resolves to loopback is refused when it is dialed, before
// anything reaches the server. The test server listens on a random port, so the check under test
// judges the dialed address as if it were on the standard port; the port rule is CheckAddress's own
// table test.
func TestTransport_dialTimeCheck(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	port := strconv.Itoa(server.Listener.Addr().(*net.TCPAddr).Port)
	trustServer := func(tr *transport) {
		tr.base.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	}

	t.Run("a hostname resolving to loopback is refused at dial time", func(t *testing.T) {
		var (
			mu     sync.Mutex
			dialed []netip.AddrPort
		)
		tr := newTransport(func(addr netip.AddrPort) error {
			mu.Lock()
			dialed = append(dialed, addr)
			mu.Unlock()
			return CheckAddress(netip.AddrPortFrom(addr.Addr(), Port))
		})
		trustServer(tr)
		req, err := http.NewRequest(http.MethodGet, "https://localhost:"+port+"/", nil)
		require.NoError(t, err)

		_, err = tr.base.RoundTrip(req)
		assert.ErrorIs(t, err, ErrDenied)
		mu.Lock()
		defer mu.Unlock()
		require.NotEmpty(t, dialed, "the check must see the resolved address")
		for _, addr := range dialed {
			assert.True(t, addr.Addr().Unmap().IsLoopback(), "dialed %s", addr)
		}
		assert.Equal(t, int32(0), hits.Load(), "the request must not reach the server")
	})

	t.Run("the same request passes when the check admits the address", func(t *testing.T) {
		tr := newTransport(func(netip.AddrPort) error { return nil })
		trustServer(tr)
		req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:"+port+"/", nil)
		require.NoError(t, err)

		resp, err := tr.base.RoundTrip(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, int32(1), hits.Load())
	})
}

// TestNewClient_refusesBeforeDialing pins that the production client refuses a URL that is not a
// public https URL on the standard port before any connection is made.
func TestNewClient_refusesBeforeDialing(t *testing.T) {
	client := NewClient()
	for _, raw := range []string{
		"http://client.example.com/metadata",
		"https://client.example.com:8443/metadata",
		"https://127.0.0.1/metadata",
		"https://[fd00::1]/metadata",
	} {
		t.Run(raw, func(t *testing.T) {
			resp, err := client.Get(raw)
			if resp != nil {
				_ = resp.Body.Close()
			}
			assert.ErrorIs(t, err, ErrDenied)
		})
	}
}

func TestNewClient_noProxyNoRedirects(t *testing.T) {
	client := NewClient()
	tr, ok := client.Transport.(*transport)
	require.True(t, ok)
	assert.Nil(t, tr.base.Proxy, "a proxy would make the dial-time check judge the proxy, not the target")
	assert.ErrorIs(t, client.CheckRedirect(nil, nil), http.ErrUseLastResponse)
	assert.Positive(t, client.Timeout)
}
