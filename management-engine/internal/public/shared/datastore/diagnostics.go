// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Datastore diagnostics classify failures without exposing upstream error strings or private values.
package datastore

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"syscall"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// ErrorAttributes reports safe failure categories and status codes for structured logs.
func ErrorAttributes(err error) []any {
	attrs := []any{"error_class", errorClass(err), "error_type", fmt.Sprintf("%T", err)}
	var apiStatus apierrors.APIStatus
	if errors.As(err, &apiStatus) {
		attrs = append(attrs, "storage_status", apiStatus.Status().Code)
	}
	return attrs
}

// errorClass supplies actionable failure categories without logging sensitive error strings.
func errorClass(err error) string {
	_, unknownCA := errors.AsType[x509.UnknownAuthorityError](err)
	_, hostname := errors.AsType[x509.HostnameError](err)
	_, certificate := errors.AsType[x509.CertificateInvalidError](err)
	_, dns := errors.AsType[*net.DNSError](err)
	switch {
	case err == nil:
		return "invalid_storage_response"
	case apierrors.IsNotFound(err):
		return "storage_not_found"
	case apierrors.IsUnauthorized(err):
		return "storage_unauthorized"
	case apierrors.IsForbidden(err):
		return "storage_forbidden"
	case errors.Is(err, context.DeadlineExceeded), apierrors.IsTimeout(err), apierrors.IsServerTimeout(err):
		return "storage_timeout"
	case apierrors.IsInternalError(err):
		return "storage_internal_error"
	case apierrors.IsInvalid(err), apierrors.IsBadRequest(err):
		return "storage_invalid_configuration"
	case unknownCA:
		return "tls_unknown_authority"
	case hostname:
		return "tls_hostname_mismatch"
	case certificate:
		return "tls_invalid_certificate"
	case dns:
		return "dns_lookup_failed"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection_refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection_reset"
	default:
		return "unexpected_failure"
	}
}
