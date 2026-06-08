-- Migration: Create quotas table for per-user token and request limits
-- Created: 2026-06-08
-- Description: Track and enforce usage limits per user per provider

CREATE TABLE IF NOT EXISTS quotas (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  
  -- Token limits
  monthly_limit_tokens INTEGER NOT NULL DEFAULT 1000000,
  monthly_used_tokens INTEGER NOT NULL DEFAULT 0,
  
  -- Request limits
  monthly_limit_requests INTEGER NOT NULL DEFAULT 100000,
  monthly_used_requests INTEGER NOT NULL DEFAULT 0,
  
  -- Reset timing
  reset_date DATE NOT NULL,
  
  -- Metadata
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  
  -- Constraints
  UNIQUE(user_id, provider),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_quotas_user_id ON quotas(user_id);
CREATE INDEX IF NOT EXISTS idx_quotas_user_provider ON quotas(user_id, provider);
CREATE INDEX IF NOT EXISTS idx_quotas_reset_date ON quotas(reset_date);
