-- Phase 13: real file scanner (antivirus engines + VirusTotal), honest risk levels, quarantine, upload scanning.
-- Run ONCE on an existing mst_database, AFTER phase12_security.sql (MySQL Workbench: open this file, then Execute).
-- If it stopped with an error part-way, run phase13_repair.sql instead (safe to run again).
-- It only adds columns, allowed values, a table and settings; existing data is kept (nothing is deleted).
USE mst_database;
-- MySQL Workbench blocks UPDATE statements without a key in safe-update mode (Error 1175); allow them for this script.
SET SQL_SAFE_UPDATES = 0;

-- Scans: lifecycle (scan_state) is separate from the risk result (risk_level), plus the evidence behind it.
ALTER TABLE scans
  MODIFY COLUMN status ENUM('PENDING','SAFE','THREAT','WARNING','UNKNOWN','FAILED') NOT NULL,
  MODIFY COLUMN risk_level ENUM('Unknown','Safe','Low','Medium','High','Critical','Failed') NULL,
  ADD COLUMN source ENUM('Agent','Auto','Upload') NOT NULL DEFAULT 'Agent' AFTER scan_type,
  ADD COLUMN scan_state ENUM('Pending','Scanning','Completed','Failed') NOT NULL DEFAULT 'Pending' AFTER status,
  ADD COLUMN detection VARCHAR(255) NULL,
  ADD COLUMN evidence_strength ENUM('Strong','Moderate','Limited','N/A') NULL,
  ADD COLUMN analysis_coverage ENUM('Full','Partial') NULL,
  ADD COLUMN scanner VARCHAR(255) NULL,
  ADD COLUMN file_size BIGINT UNSIGNED NULL,
  ADD COLUMN file_type VARCHAR(80) NULL,
  ADD COLUMN stored_file VARCHAR(80) NULL,
  ADD COLUMN stored_until DATETIME NULL,
  ADD COLUMN vt_analysis_id VARCHAR(160) NULL,
  ADD COLUMN vt_checked_at DATETIME NULL,
  ADD INDEX idx_scans_state (scan_state),
  ADD INDEX idx_scans_risk (risk_level),
  ADD INDEX idx_scans_created (created_at),
  ADD INDEX idx_scans_hash (file_hash(64));

UPDATE scans SET scan_state = CASE status WHEN 'PENDING' THEN 'Pending' WHEN 'FAILED' THEN 'Failed' ELSE 'Completed' END WHERE scanner IS NULL AND detection IS NULL;
-- Results recorded before Phase 13 came from file-name rules and hash lookups only (no antivirus engine).
UPDATE scans SET detection = 'Recorded before Phase 13 (no antivirus engine result)', evidence_strength = 'N/A' WHERE scan_state = 'Completed' AND detection IS NULL;
-- The two example rows from seed.sql are not real scans. They are labelled, not deleted. To remove them yourself:
--   DELETE FROM scans WHERE file_hash = 'Demo SHA-256';
UPDATE scans SET detection = 'Demo record from seed.sql - not a real scan', evidence_strength = 'N/A', risk_level = 'Unknown', status = 'UNKNOWN' WHERE file_hash = 'Demo SHA-256';

-- File events: modifications and renames, and how the file arrived (download evidence).
ALTER TABLE file_events
  MODIFY COLUMN event_type ENUM('created','modified','renamed','deleted') NOT NULL,
  MODIFY COLUMN risk_level ENUM('Unknown','Safe','Low','Medium','High','Critical','Failed') NOT NULL DEFAULT 'Unknown',
  ADD COLUMN previous_path VARCHAR(1024) NULL AFTER file_path,
  ADD COLUMN origin ENUM('local','browser_download','internet') NULL,
  ADD COLUMN download_url VARCHAR(500) NULL;

-- Threats created by a scan point back to it.
ALTER TABLE threats ADD COLUMN scan_id INT UNSIGNED NULL, ADD CONSTRAINT fk_threat_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL;

-- Files isolated on a lab PC by its agent. pending_action is the job the agent still has to carry out.
CREATE TABLE IF NOT EXISTS quarantine_items (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  computer_id INT UNSIGNED NOT NULL,
  file_event_id BIGINT UNSIGNED NULL,
  scan_id INT UNSIGNED NULL,
  file_name VARCHAR(255) NOT NULL,
  original_path VARCHAR(1024) NOT NULL,
  sha256 CHAR(64) NOT NULL,
  quarantine_name VARCHAR(160) NULL,
  status ENUM('Quarantine Requested','Quarantined','Release Requested','Released','Delete Requested','Deleted','Failed') NOT NULL,
  pending_action ENUM('quarantine','release','delete') NULL,
  action_sent_at DATETIME NULL,
  last_error VARCHAR(255) NULL,
  requested_by INT UNSIGNED NULL,
  release_reason VARCHAR(255) NULL,
  quarantined_at DATETIME NULL,
  released_at DATETIME NULL,
  deleted_at DATETIME NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_quarantine_computer FOREIGN KEY (computer_id) REFERENCES computers(id) ON DELETE CASCADE,
  CONSTRAINT fk_quarantine_file_event FOREIGN KEY (file_event_id) REFERENCES file_events(id) ON DELETE SET NULL,
  CONSTRAINT fk_quarantine_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL,
  CONSTRAINT fk_quarantine_user FOREIGN KEY (requested_by) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_quarantine_jobs (computer_id, pending_action),
  INDEX idx_quarantine_status (status)
);

-- Scanner settings (Admin): scan new files automatically; keep uploaded files for "Scan Again" this long.
INSERT IGNORE INTO settings (category, setting_key, setting_value) VALUES ('scanner', 'autoScan', '1'), ('scanner', 'uploadRetention', '7 days');
SET SQL_SAFE_UPDATES = 1;
