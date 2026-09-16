package quicx

import (
	"testing"

	"github.com/sagernet/quic-go"
)

func TestFECCapability(t *testing.T) {
	if capability := fecCapability(nil); len(capability) != 0 {
		t.Fatalf("expected no capability byte without FEC options, got %v", capability)
	}
	capability := fecCapability(&FECOptions{})
	if len(capability) != 1 || capability[0] != fecCapabilityAll || parseFECCapability(capability) != fecCapabilityAll {
		t.Fatalf("unexpected capability byte: %v", capability)
	}
	if parseFECCapability(nil) != 0 {
		t.Fatal("expected no FEC support for an empty capability")
	}
	if parseFECCapability([]byte{0x00}) != 0 {
		t.Fatal("expected no FEC support for a zero capability")
	}
	if parseFECCapability([]byte{fecCapabilityEnabled}) != fecCapabilityEnabled {
		t.Fatal("expected block scheme support")
	}
	if parseFECCapability([]byte{fecCapabilityWindow}) != fecCapabilityWindow {
		t.Fatal("expected sliding window scheme support")
	}
	// unknown flags of future versions must not disable the schemes we know
	if parseFECCapability([]byte{fecCapabilityEnabled | 0x80}) != fecCapabilityEnabled {
		t.Fatal("expected block scheme support for a capability with unknown flags")
	}
	// the configuration can restrict what is advertised
	if capability := fecCapability(&FECOptions{Scheme: "block"}); capability[0] != fecCapabilityEnabled {
		t.Fatalf("unexpected capability for the block scheme: %v", capability)
	}
	if capability := fecCapability(&FECOptions{Scheme: "window"}); capability[0] != fecCapabilityWindow {
		t.Fatalf("unexpected capability for the window scheme: %v", capability)
	}
	if capability := fecCapability(&FECOptions{Scheme: "auto"}); capability[0] != fecCapabilityAll {
		t.Fatalf("unexpected capability for the automatic scheme: %v", capability)
	}
}

func TestFECSchemeNegotiation(t *testing.T) {
	for _, test := range []struct {
		client   byte
		server   byte
		expected byte
	}{
		{client: fecCapabilityAll, server: fecCapabilityAll, expected: fecCapabilityWindow},
		{client: fecCapabilityEnabled, server: fecCapabilityAll, expected: fecCapabilityEnabled},
		{client: fecCapabilityWindow, server: fecCapabilityAll, expected: fecCapabilityWindow},
		{client: fecCapabilityAll, server: fecCapabilityEnabled, expected: fecCapabilityEnabled},
		{client: fecCapabilityAll, server: fecCapabilityWindow, expected: fecCapabilityWindow},
		// no scheme in common: FEC stays off on both sides
		{client: fecCapabilityEnabled, server: fecCapabilityWindow, expected: 0},
		{client: fecCapabilityWindow, server: fecCapabilityEnabled, expected: 0},
	} {
		if scheme := fecScheme(test.client, test.server); scheme != test.expected {
			t.Fatalf("expected scheme %#x for client %#x / server %#x, got %#x", test.expected, test.client, test.server, scheme)
		}
	}
}

func TestFECConfigFromOptions(t *testing.T) {
	if config := (*FECOptions)(nil).config(fecCapabilityWindow); config.MaxOverheadPercent != 0 || config.MaxGroupSize != 0 {
		t.Fatalf("unexpected config for nil options: %+v", config)
	}
	options := &FECOptions{MaxOverheadPercent: 25, MaxGroupSize: 8, MaxParityRows: 2}
	config := options.config(fecCapabilityEnabled)
	if config.MaxOverheadPercent != 25 || config.MaxGroupSize != 8 || config.MaxParityRows != 2 {
		t.Fatalf("unexpected config: %+v", config)
	}
	if config.Scheme != quic.FECSchemeBlock {
		t.Fatalf("expected the block scheme, got %v", config.Scheme)
	}
	windowConfig := options.config(fecCapabilityWindow)
	if windowConfig.Scheme != quic.FECSchemeWindow {
		t.Fatalf("expected the window scheme, got %v", windowConfig.Scheme)
	}
	if windowConfig.MaxOverheadPercent != 25 || windowConfig.MaxGroupSize != 8 || windowConfig.MaxParityRows != 2 {
		t.Fatalf("unexpected window config: %+v", windowConfig)
	}
}
