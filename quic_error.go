package qtls

import (
	"errors"
	"io"
	"net"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
)

type quicError struct {
	err error
}

func WrapError(err error) error {
	if err == nil {
		return nil
	}
	return &quicError{err: err}
}

func (e *quicError) Error() string {
	return e.err.Error()
}

func (e *quicError) Unwrap() error {
	return e.err
}

func (e *quicError) Is(target error) bool {
	if errors.Is(e.err, target) {
		return true
	}
	switch target {
	case net.ErrClosed:
		var streamErr *quic.StreamError
		if errors.As(e.err, &streamErr) {
			// A stream cancellation with error code 0 carries no error, no
			// matter which side cancelled it. A peer which resets its upload
			// (RESET_STREAM) or stops reading (STOP_SENDING) with code 0 closed
			// the request normally, and classifying it as a failure turns every
			// client-side connection abort into an ERROR log line. Non-zero
			// codes stay errors and are still reported.
			return streamErr.ErrorCode == 0
		}
		var transportErr *quic.TransportError
		if errors.As(e.err, &transportErr) {
			return transportErr.ErrorCode == quic.NoError
		}
		var appErr *quic.ApplicationError
		if errors.As(e.err, &appErr) {
			return appErr.Remote && appErr.ErrorCode == 0
		}
		var h3Err *http3.Error
		if errors.As(e.err, &h3Err) {
			return h3Err.ErrorCode == http3.ErrCodeNoError || h3Err.ErrorCode == http3.ErrCodeRequestCanceled
		}
	case io.EOF:
		var streamErr *quic.StreamError
		if errors.As(e.err, &streamErr) {
			return !streamErr.Remote && streamErr.ErrorCode == 0
		}
	}
	return false
}
