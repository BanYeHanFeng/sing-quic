package quicx

import (
	"testing"
)

func TestFECCapability(t *testing.T) {
	if capability := fecCapability(nil); len(capability) != 0 {
		t.Fatalf("expected no capability byte without FEC options, got %v", capability)
	}
	capability := fecCapability(&FECOptions{})
	if len(capability) != 1 || capability[0] != fecCapabilityWindow || parseFECCapability(capability) != fecCapabilityWindow {
		t.Fatalf("unexpected capability byte: %v", capability)
	}
	if parseFECCapability(nil) != 0 {
		t.Fatal("expected no FEC support for an empty capability")
	}
	if parseFECCapability([]byte{0x00}) != 0 {
		t.Fatal("expected no FEC support for a zero capability")
	}
	if parseFECCapability([]byte{fecCapabilityWindow}) != fecCapabilityWindow {
		t.Fatal("expected sliding window scheme support")
	}
	// The block scheme flag of older versions is not a scheme this build implements:
	// a peer that only announces it must not be sent window repair frames.
	if parseFECCapability([]byte{0x01}) != 0 {
		t.Fatal("expected no FEC support for a block scheme only capability")
	}
	// A peer that announces both (an older version with the window scheme) is fine:
	// the window flag is the one that matters.
	if parseFECCapability([]byte{0x03}) != fecCapabilityWindow {
		t.Fatal("expected sliding window scheme support for a combined capability")
	}
	// unknown flags of future versions must not disable the scheme we know
	if parseFECCapability([]byte{fecCapabilityWindow | 0x80}) != fecCapabilityWindow {
		t.Fatal("expected sliding window scheme support for a capability with unknown flags")
	}
}

func TestFECConfigFromOptions(t *testing.T) {
	if config := (*FECOptions)(nil).config(); config.MaxOverheadPercent != 0 || config.MaxGroupSize != 0 {
		t.Fatalf("unexpected config for nil options: %+v", config)
	}
	options := &FECOptions{MaxOverheadPercent: 25, MaxGroupSize: 8, MaxParityRows: 2, BaselineRedundancyPercent: 3, RecoveredPacketFeedback: true}
	config := options.config()
	if config.MaxOverheadPercent != 25 || config.MaxGroupSize != 8 || config.MaxParityRows != 2 {
		t.Fatalf("unexpected config: %+v", config)
	}
	if config.BaselineRedundancyPercent != 3 {
		t.Fatalf("baseline redundancy was not passed through: %+v", config)
	}
	if !config.RecoveredPacketFeedback {
		t.Fatalf("recovered packet feedback was not passed through: %+v", config)
	}
}
