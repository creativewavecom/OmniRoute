-- Migration: Add user_id tracking to audit_log
-- Created: 2026-06-08
-- Description: Associate audit events with specific users for accountability

-- Add user_id column if not exists
ALTER TABLE audit_log ADD COLUMN user_id TEXT;

-- Add foreign key (cascade delete)
ALTER TABLE audit_log 
  ADD CONSTRAINT fk_audit_log_user_id 
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;

-- Index for user-specific audit queries
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_action ON audit_log(user_id, action);
