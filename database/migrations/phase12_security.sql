-- Phase 11 (VirusTotal) + Phase 12 (security hardening).
-- Run ONCE on an existing mst_database, AFTER phase11_files.sql (MySQL Workbench: open this file, then Execute).
-- It only adds a table and indexes; existing data is kept.
USE mst_database;

-- Cached VirusTotal results (24 h) so the free API quota (4 lookups/minute) is enough.
CREATE TABLE IF NOT EXISTS hash_reputation (
  sha256 CHAR(64) NOT NULL PRIMARY KEY,
  source VARCHAR(40) NOT NULL DEFAULT 'VirusTotal',
  status ENUM('found','not_found') NOT NULL,
  malicious SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  suspicious SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  harmless SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  undetected SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  total SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  name VARCHAR(160) NULL,
  checked_at DATETIME NOT NULL
);

-- Fast counting of recent failed logins per account and per IP address (login lockout).
ALTER TABLE activity_logs
  ADD INDEX idx_activity_action_user (action, user_id, created_at),
  ADD INDEX idx_activity_action_ip (action, ip_address, created_at);
