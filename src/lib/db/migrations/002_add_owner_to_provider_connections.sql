-- Migration: Add owner_id to providerConnections for multi-tenant isolation
-- Created: 2026-06-08
-- Description: Enforce strict provider credential ownership per user

-- Add owner_id column (nullable initially for backward compatibility)
ALTER TABLE provider_connections ADD COLUMN owner_id TEXT;

-- Add created_by tracking
ALTER TABLE provider_connections ADD COLUMN created_by TEXT;

-- Update timestamps if not exist
ALTER TABLE provider_connections ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE provider_connections ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- Add foreign key constraint (after migration populates owner_id)
-- This will be added in a post-migration step after data backfill
CREATE INDEX IF NOT EXISTS idx_provider_connections_owner_provider 
  ON provider_connections(owner_id, provider);

CREATE INDEX IF NOT EXISTS idx_provider_connections_owner 
  ON provider_connections(owner_id);
