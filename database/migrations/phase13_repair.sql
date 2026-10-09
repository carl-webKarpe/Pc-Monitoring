-- Phase 13 repair: finishes phase13_scanner.sql when it stopped part-way (for example MySQL Workbench
-- "Error Code: 1175 ... safe update mode", or "Duplicate column name" when running it a second time).
-- Safe to run any number of times: it only adds what is missing and never deletes data.
-- MySQL Workbench: File > Open SQL Script > this file > Execute (the lightning icon WITHOUT the cursor).
USE mst_database;
SET SQL_SAFE_UPDATES = 0;

DROP PROCEDURE IF EXISTS mst_add_column;
DROP PROCEDURE IF EXISTS mst_add_index;
DROP PROCEDURE IF EXISTS mst_add_foreign_key;
DELIMITER //
CREATE PROCEDURE mst_add_column(IN table_name_in VARCHAR(64), IN column_name_in VARCHAR(64), IN definition_in TEXT)
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = table_name_in AND COLUMN_NAME = column_name_in) THEN
    SET @mst_sql = CONCAT('ALTER TABLE `', table_name_in, '` ADD COLUMN `', column_name_in, '` ', definition_in);
    PREPARE mst_statement FROM @mst_sql; EXECUTE mst_statement; DEALLOCATE PREPARE mst_statement;
  END IF;
END //
CREATE PROCEDURE mst_add_index(IN table_name_in VARCHAR(64), IN index_name_in VARCHAR(64), IN definition_in TEXT)
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = table_name_in AND INDEX_NAME = index_name_in) THEN
    SET @mst_sql = CONCAT('ALTER TABLE `', table_name_in, '` ADD INDEX `', index_name_in, '` ', definition_in);
    PREPARE mst_statement FROM @mst_sql; EXECUTE mst_statement; DEALLOCATE PREPARE mst_statement;
  END IF;
END //
CREATE PROCEDURE mst_add_foreign_key(IN table_name_in VARCHAR(64), IN constraint_name_in VARCHAR(64), IN definition_in TEXT)
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME = table_name_in AND CONSTRAINT_NAME = constraint_name_in) THEN
    SET @mst_sql = CONCAT('ALTER TABLE `', table_name_in, '` ADD CONSTRAINT `', constraint_name_in, '` ', definition_in);
    PREPARE mst_statement FROM @mst_sql; EXECUTE mst_statement; DEALLOCATE PREPARE mst_statement;
  END IF;
END //
DELIMITER ;

-- Scans
ALTER TABLE scans
  MODIFY COLUMN status ENUM('PENDING','SAFE','THREAT','WARNING','UNKNOWN','FAILED') NOT NULL,
  MODIFY COLUMN risk_level ENUM('Unknown','Safe','Low','Medium','High','Critical','Failed') NULL;
CALL mst_add_column('scans', 'source', "ENUM('Agent','Auto','Upload') NOT NULL DEFAULT 'Agent' AFTER scan_type");
CALL mst_add_column('scans', 'scan_state', "ENUM('Pending','Scanning','Completed','Failed') NOT NULL DEFAULT 'Pending' AFTER status");
CALL mst_add_column('scans', 'detection', 'VARCHAR(255) NULL');
CALL mst_add_column('scans', 'evidence_strength', "ENUM('Strong','Moderate','Limited','N/A') NULL");
CALL mst_add_column('scans', 'analysis_coverage', "ENUM('Full','Partial') NULL");
CALL mst_add_column('scans', 'scanner', 'VARCHAR(255) NULL');
CALL mst_add_column('scans', 'file_size', 'BIGINT UNSIGNED NULL');
CALL mst_add_column('scans', 'file_type', 'VARCHAR(80) NULL');
CALL mst_add_column('scans', 'stored_file', 'VARCHAR(80) NULL');
CALL mst_add_column('scans', 'stored_until', 'DATETIME NULL');
CALL mst_add_column('scans', 'vt_analysis_id', 'VARCHAR(160) NULL');
CALL mst_add_column('scans', 'vt_checked_at', 'DATETIME NULL');
CALL mst_add_index('scans', 'idx_scans_state', '(scan_state)');
CALL mst_add_index('scans', 'idx_scans_risk', '(risk_level)');
CALL mst_add_index('scans', 'idx_scans_created', '(created_at)');
CALL mst_add_index('scans', 'idx_scans_hash', '(file_hash(64))');

-- Only rows recorded before Phase 13 (no scanner recorded yet) are updated.
UPDATE scans SET scan_state = CASE status WHEN 'PENDING' THEN 'Pending' WHEN 'FAILED' THEN 'Failed' ELSE 'Completed' END WHERE scanner IS NULL AND detection IS NULL;
UPDATE scans SET detection = 'Recorded before Phase 13 (no antivirus engine result)', evidence_strength = 'N/A' WHERE scan_state = 'Completed' AND detection IS NULL AND scanner IS NULL;
UPDATE scans SET detection = 'Demo record from seed.sql - not a real scan', evidence_strength = 'N/A', risk_level = 'Unknown', status = 'UNKNOWN' WHERE file_hash = 'Demo SHA-256';

-- File events
ALTER TABLE file_events
  MODIFY COLUMN event_type ENUM('created','modified','renamed','deleted') NOT NULL,
  MODIFY COLUMN risk_level ENUM('Unknown','Safe','Low','Medium','High','Critical','Failed') NOT NULL DEFAULT 'Unknown';
CALL mst_add_column('file_events', 'previous_path', 'VARCHAR(1024) NULL AFTER file_path');
CALL mst_add_column('file_events', 'origin', "ENUM('local','browser_download','internet') NULL");
CALL mst_add_column('file_events', 'download_url', 'VARCHAR(500) NULL');

-- Threats
CALL mst_add_column('threats', 'scan_id', 'INT UNSIGNED NULL');
CALL mst_add_foreign_key('threats', 'fk_threat_scan', 'FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL');

-- Quarantine
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

INSERT IGNORE INTO settings (category, setting_key, setting_value) VALUES ('scanner', 'autoScan', '1'), ('scanner', 'uploadRetention', '7 days');

DROP PROCEDURE IF EXISTS mst_add_column;
DROP PROCEDURE IF EXISTS mst_add_index;
DROP PROCEDURE IF EXISTS mst_add_foreign_key;
SET SQL_SAFE_UPDATES = 1;

SELECT 'Phase 13 database update complete' AS result;
