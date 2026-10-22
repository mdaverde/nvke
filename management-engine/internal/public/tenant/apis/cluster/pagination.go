// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Pagination policy bounds tenant lists while the shared codec protects their datastore cursors.
package cluster

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dsx-ai-factory/nvke/management-engine/internal/public/shared/validation"
)

// page validates pagination inputs and restores the original page size when resuming a list.
func (s *Service) page(size int32, token string) (int32, string, error) {
	if size < 0 || size > MaxPageSize {
		return 0, "", validation.FieldViolation("page_size", "must be between 1 and 100, or omitted")
	}
	if token == "" {
		if size == 0 {
			size = defaultPageSize
		}
		return size, "", nil
	}
	cursor, err := s.pages.Decode(token)
	if err != nil || cursor.Size > MaxPageSize || (size != 0 && size != cursor.Size) {
		return 0, "", status.Error(codes.InvalidArgument, "invalid or expired page token, or changed page size; restart listing")
	}
	return cursor.Size, cursor.Continue, nil
}
