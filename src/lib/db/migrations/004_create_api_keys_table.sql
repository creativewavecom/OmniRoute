-- Migration: Create API keys table for programmatic user access
-- Created: 2026-06-08
-- Description: Manage user-created API keys with scopes and expiration

CREATE TABLE IF NOT EXISTS api_keys_v2 (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  
  -- Key metadata
  name TEXT,
  key_prefix TEXT NOT NULL,  -- First 12 chars (for display)
  key_hash TEXT UNIQUE NOT NULL,  -- SHA-256 hash (for comparison)
  
  -- Scopes (JSON array)
  scopes TEXT NOT NULL DEFAULT '[]',
  
  -- Lifecycle
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TIMESTAMP NULL,
  expires_at TIMESTAMP NULL,
  revoked_at TIMESTAMP NULL,
  
  -- Constraints
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_api_keys_v2_user_id ON api_keys_v2(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_v2_key_hash ON api_keys_v2(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_v2_active ON api_keys_v2(user_id, revoked_at) WHERE revoked_at IS NULL;
