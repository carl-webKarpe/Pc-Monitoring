-- Phase 9: Python agent -> PHP API.
-- Run ONCE on an existing mst_database (MySQL Workbench: open this file, then Execute).
-- It only ADDS columns and a table; it does not delete or change existing data.
-- (A fresh install from database/schema.sql already includes these changes.)
USE mst_database;

ALTER TABLE computers
  ADD COLUMN mac_address VARCHAR(17) NULL,
  ADD COLUMN agent_version VARCHAR(20) NULL,
  ADD COLUMN disk_usage TINYINT UNSIGNED NULL,
  ADD COLUMN last_heartbeat_at DATETIME NULL,
  ADD COLUMN agent_token_hash CHAR(64) NULL;

CREATE TABLE IF NOT EXISTS file_events (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  event_uid CHAR(36) NOT NULL UNIQUE,
  computer_id INT UNSIGNED NOT NULL,
  event_type ENUM('created','deleted') NOT NULL,
  file_name VARCHAR(255) NOT NULL,
  file_path VARCHAR(1024) NOT NULL,
  file_size BIGINT UNSIGNED NULL,
  sha256 CHAR(64) NULL,
  status ENUM('New','Reviewed','Scan Requested','Scanned') NOT NULL DEFAULT 'New',
  detected_at DATETIME NOT NULL,
  received_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_file_event_computer FOREIGN KEY (computer_id) REFERENCES computers(id) ON DELETE CASCADE,
  INDEX idx_file_events_computer_detected (computer_id, detected_at),
  INDEX idx_file_events_detected (detected_at)
);
