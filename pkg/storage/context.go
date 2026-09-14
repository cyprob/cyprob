// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

import "context"

type ctxKey string

const configKey ctxKey = "storage.config"

// WithConfig stores the storage configuration on the provided context.
func WithConfig(ctx context.Context, cfg *Config) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, configKey, cfg)
}

// ConfigFromContext extracts the storage configuration from context.
func ConfigFromContext(ctx context.Context) (*Config, bool) {
	if ctx == nil {
		return nil, false
	}
	val := ctx.Value(configKey)
	if cfg, ok := val.(*Config); ok && cfg != nil {
		return cfg, true
	}
	return nil, false
}
