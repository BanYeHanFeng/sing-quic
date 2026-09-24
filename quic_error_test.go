package qtls

import (
	"errors"
	"io"
	"net"
	"testing"

	"github.com/sagernet/quic-go"
	E "github.com/sagernet/sing/common/exceptions"
)

// TestQUICErrorStreamCancel pins how a QUIC stream cancellation is classified.
// A code 0 cancellation carries no error, whether it was initiated locally or
// by the peer: a peer which resets its upload (RESET_STREAM) or stops reading
// (STOP_SENDING) with code 0 closed the request normally. Only a non-zero code
// is a failure.
func TestQUICErrorStreamCancel(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		isClosed bool
		isEOF    bool
	}{
		{
			name:     "remote cancel with code 0 is a normal close",
			err:      &quic.StreamError{StreamID: 4, ErrorCode: 0, Remote: true},
			isClosed: true,
			isEOF:    false,
		},
		{
			name:     "local cancel with code 0 is a normal close",
			err:      &quic.StreamError{StreamID: 4, ErrorCode: 0, Remote: false},
			isClosed: true,
			isEOF:    true,
		},
		{
			name:     "remote cancel with non-zero code is an error",
			err:      &quic.StreamError{StreamID: 4, ErrorCode: 1, Remote: true},
			isClosed: false,
			isEOF:    false,
		},
		{
			name:     "local cancel with non-zero code is an error",
			err:      &quic.StreamError{StreamID: 4, ErrorCode: 1, Remote: false},
			isClosed: false,
			isEOF:    false,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := WrapError(testCase.err)
			if !errors.Is(err, testCase.err) {
				t.Fatal("wrapped error does not unwrap to the original error")
			}
			if isClosed := errors.Is(err, net.ErrClosed); isClosed != testCase.isClosed {
				t.Fatalf("errors.Is(err, net.ErrClosed) = %v, want %v", isClosed, testCase.isClosed)
			}
			if isEOF := errors.Is(err, io.EOF); isEOF != testCase.isEOF {
				t.Fatalf("errors.Is(err, io.EOF) = %v, want %v", isEOF, testCase.isEOF)
			}
			if closedOrCanceled := E.IsClosedOrCanceled(err); closedOrCanceled != testCase.isClosed {
				t.Fatalf("E.IsClosedOrCanceled(err) = %v, want %v", closedOrCanceled, testCase.isClosed)
			}
		})
	}
}

func TestWrapErrorNil(t *testing.T) {
	if err := WrapError(nil); err != nil {
		t.Fatalf("WrapError(nil) = %v, want nil", err)
	}
}
