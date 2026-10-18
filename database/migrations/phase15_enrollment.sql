-- Phase 15: add lab PCs quickly with an enrollment key (Computers > Add Computers).
-- Run ONCE on an existing mst_database, AFTER phase14 (MySQL Workbench: open this file, then Execute).
-- Safe to run again: it only creates a table that does not exist yet.
USE mst_database;

-- One key enrolls many PCs until it expires, reaches its limit or is revoked. Only a SHA-256 hash of the key is stored.
CREATE TABLE IF NOT EXISTS agent_enrollment_keys (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  key_hash CHAR(64) NOT NULL UNIQUE,
  label VARCHAR(80) NOT NULL,
  max_uses SMALLINT UNSIGNED NOT NULL,
  uses SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  expires_at DATETIME NOT NULL,
  created_by INT UNSIGNED NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at DATETIME NULL,
  revoked_at DATETIME NULL,
  CONSTRAINT fk_enrollment_key_user FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_enrollment_keys_active (revoked_at, expires_at)
);

SELECT 'Phase 15 database update complete' AS result;
