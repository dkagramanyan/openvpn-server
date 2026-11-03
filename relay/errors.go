package main

import "errors"

var (
	errAccessDenied      = errors.New("access denied")
	errAuthUnavailable   = errors.New("authorization service unavailable")
	errDestinationDenied = errors.New("destination denied")
	errDNSFailed         = errors.New("DNS resolution failed")
	errInvalidTarget     = errors.New("invalid target")
)
