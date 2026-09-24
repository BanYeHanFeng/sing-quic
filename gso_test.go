package qtls

import (
	"net"
	"testing"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/bufio"
)

func TestConfigWithGSO(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	wrapped := bufio.NewCounterConn(bufio.NewUDPConnWithoutGSO(udp), nil, nil)
	shared := &quic.Config{EnableDatagrams: true}
	configured := ConfigWithGSO(shared, wrapped)
	if !configured.DisableGSO || !configured.EnableDatagrams {
		t.Fatal("policy or existing config lost")
	}
	if shared.DisableGSO || configured == shared {
		t.Fatal("mutated a shared config")
	}
	if ConfigWithGSO(shared, udp) != shared {
		t.Fatal("changed unrestricted connection config")
	}
	if !ConfigWithGSO(nil, wrapped).DisableGSO {
		t.Fatal("nil config lost policy")
	}
	if ConfigWithGSO(nil, udp) != nil {
		t.Fatal("unrestricted nil config changed")
	}
	ApplyQUICOptions(shared, QUICOptions{DisableGSO: true})
	ApplyQUICOptions(shared, QUICOptions{})
	if !shared.DisableGSO {
		t.Fatal("overrode an existing prohibition")
	}
}
