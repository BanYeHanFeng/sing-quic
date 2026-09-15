package quicx

import "testing"

func TestFECCapability(t *testing.T) {
	if capability := fecCapability(nil); len(capability) != 0 {
		t.Fatalf("expected no capability byte without FEC options, got %v", capability)
	}
	capability := fecCapability(&FECOptions{})
	if len(capability) != 1 || !parseFECCapability(capability) {
		t.Fatalf("unexpected capability byte: %v", capability)
	}
	if parseFECCapability(nil) {
		t.Fatal("expected no FEC support for an empty capability")
	}
	if parseFECCapability([]byte{0x00}) {
		t.Fatal("expected no FEC support for a zero capability")
	}
	if !parseFECCapability([]byte{fecCapabilityEnabled}) {
		t.Fatal("expected FEC support")
	}
	// unknown flags of future versions must not disable FEC
	if !parseFECCapability([]byte{0x81}) {
		t.Fatal("expected FEC support for a capability with unknown flags")
	}
}

func TestFECConfigFromOptions(t *testing.T) {
	if config := (*FECOptions)(nil).config(); config.MaxOverheadPercent != 0 || config.MaxGroupSize != 0 {
		t.Fatalf("unexpected config for nil options: %+v", config)
	}
	options := &FECOptions{MaxOverheadPercent: 25, MaxGroupSize: 8, MaxParityRows: 2}
	config := options.config()
	if config.MaxOverheadPercent != 25 || config.MaxGroupSize != 8 || config.MaxParityRows != 2 {
		t.Fatalf("unexpected config: %+v", config)
	}
}
