-- Auto-approve (per server) + audit flag for auto-approved executions.
-- Existing servers keep the old behaviour ('off'); existing audit rows are not auto-approved.
ALTER TABLE servers ADD COLUMN auto_approve TEXT NOT NULL DEFAULT 'off' CHECK (auto_approve IN ('off', 'safe', 'all'));
ALTER TABLE audit_log ADD COLUMN auto_approved INTEGER NOT NULL DEFAULT 0;
ALTER TABLE audit_log ADD COLUMN auto_level TEXT;
CREATE INDEX IF NOT EXISTS idx_audit_auto ON audit_log (auto_approved, ts DESC);
