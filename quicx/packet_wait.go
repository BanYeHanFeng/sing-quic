package quicx

import (
	"io"
	"os"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (c *udpPacketConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readWaitOptions = options
	return options.NeedHeadroom()
}

func (c *udpPacketConn) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	select {
	case message := <-c.data:
		destination = message.destination
		if c.readWaitOptions.NeedHeadroom() {
			buffer = c.readWaitOptions.NewPacketBuffer()
			_, err = buffer.Write(message.data)
			if err != nil {
				buffer.Release()
				return
			}
			c.readWaitOptions.PostReturn(buffer)
		} else {
			// The caller takes the buffer over and releases it. The message is
			// the one thing that holds its payload, so the payload is copied out
			// of it rather than handed over.
			buffer = buf.NewSize(len(message.data))
			_, err = buffer.Write(message.data)
			if err != nil {
				buffer.Release()
				return nil, M.Socksaddr{}, err
			}
		}
		return
	case <-c.ctx.Done():
		return nil, M.Socksaddr{}, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return nil, M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}
