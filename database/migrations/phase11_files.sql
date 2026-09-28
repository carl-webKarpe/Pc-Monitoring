-- Phase 11: detected-file review, classification and on-PC scanning.
-- Run ONCE on an existing mst_database, AFTER phase9_agent.sql (MySQL Workbench: open this file, then Execute).
-- It only adds columns, allowed values and a table; existing data is kept.
USE mst_database;

ALTER TABLE file_events
  ADD COLUMN risk_level ENUM('Unknown','Safe','Low','Medium','High','Critical') NOT NULL DEFAULT 'Unknown',
  ADD COLUMN suggested_confidential TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN classification ENUM('Normal','Confidential') NULL,
  ADD COLUMN scan_id INT UNSIGNED NULL,
  MODIFY COLUMN status ENUM('New','Reviewed','Scan Requested','Scanned','Scan Failed') NOT NULL DEFAULT 'New';

ALTER TABLE scans
  MODIFY COLUMN status ENUM('PENDING','SAFE','THREAT','WARNING','FAILED') NOT NULL,
  ADD COLUMN file_event_id BIGINT UNSIGNED NULL,
  ADD COLUMN file_path VARCHAR(1024) NULL,
  ADD COLUMN risk_level ENUM('Unknown','Safe','Low','Medium','High','Critical') NULL,
  ADD COLUMN scan_details TEXT NULL;

ALTER TABLE scans ADD CONSTRAINT fk_scan_file_event FOREIGN KEY (file_event_id) REFERENCES file_events(id) ON DELETE SET NULL;
ALTER TABLE file_events ADD CONSTRAINT fk_file_event_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS hash_blocklist (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  sha256 CHAR(64) NOT NULL UNIQUE,
  name VARCHAR(160) NOT NULL,
  severity ENUM('CRITICAL','HIGH','MEDIUM','LOW') NOT NULL DEFAULT 'HIGH',
  source VARCHAR(80) NOT NULL DEFAULT 'Manual',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- The harmless EICAR anti-virus test file, used to demonstrate a THREAT result safely.
INSERT IGNORE INTO hash_blocklist (sha256, name, severity, source) VALUES
('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'EICAR anti-virus test file', 'CRITICAL', 'EICAR');
