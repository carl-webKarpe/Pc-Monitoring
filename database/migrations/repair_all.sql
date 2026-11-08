-- REPAIR: brings an MST database of ANY older version up to date in one step (all phases 9-17).
-- Use it when the website says "The database needs an update" and you are not sure which file is missing.
-- Safe to run any number of times: it only ADDS missing tables, columns, allowed values, indexes, links and default
-- settings/permissions. It never deletes or changes your users, computers, files, logs or settings.
-- MySQL Workbench: File > Open SQL Script > this file > Execute (the lightning icon WITHOUT the cursor).
-- The last result ("Still missing") must be empty. Then restart start-server.bat and log in again.
-- (Generated from database/schema.sql.)
USE mst_database;
SET SQL_SAFE_UPDATES = 0;
SET FOREIGN_KEY_CHECKS = 0;

DROP PROCEDURE IF EXISTS mst_add_column;
DROP PROCEDURE IF EXISTS mst_allow_values;
DROP PROCEDURE IF EXISTS mst_add_index;
DROP PROCEDURE IF EXISTS mst_add_foreign_key;
DELIMITER //
CREATE PROCEDURE mst_add_column(IN table_name_in VARCHAR(64), IN column_name_in VARCHAR(64), IN definition_in TEXT)
BEGIN
  DECLARE CONTINUE HANDLER FOR SQLEXCEPTION SELECT CONCAT('Could not add ', table_name_in, '.', column_name_in) AS warning;
  IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = table_name_in AND COLUMN_NAME = column_name_in) THEN
    SET @mst_sql = CONCAT('ALTER TABLE `', table_name_in, '` ADD COLUMN `', column_name_in, '` ', definition_in);
    PREPARE mst_statement FROM @mst_sql; EXECUTE mst_statement; DEALLOCATE PREPARE mst_statement;
  END IF;
END //
CREATE PROCEDURE mst_allow_values(IN table_name_in VARCHAR(64), IN column_name_in VARCHAR(64), IN definition_in TEXT, IN type_in TEXT)
BEGIN
  -- Older databases allow fewer values in a list column (for example file_events.event_type): allow the new ones too.
  DECLARE CONTINUE HANDLER FOR SQLEXCEPTION SELECT CONCAT('Could not update the allowed values of ', table_name_in, '.', column_name_in) AS warning;
  IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = table_name_in AND COLUMN_NAME = column_name_in
             AND LOWER(REPLACE(COLUMN_TYPE, ' ', '')) <> LOWER(REPLACE(type_in, ' ', ''))) THEN
    SET @mst_sql = CONCAT('ALTER TABLE `', table_name_in, '` MODIFY COLUMN `', column_name_in, '` ', definition_in);
    PREPARE mst_statement FROM @mst_sql; EXECUTE mst_statement; DEALLOCATE PREPARE mst_statement;
  END IF;
END //
CREATE PROCEDURE mst_add_index(IN table_name_in VARCHAR(64), IN index_name_in VARCHAR(64), IN definition_in TEXT)
BEGIN
  DECLARE CONTINUE HANDLER FOR SQLEXCEPTION SELECT CONCAT('Could not add index ', index_name_in) AS warning;
  IF NOT EXISTS (SELECT 1 FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = table_name_in AND INDEX_NAME = index_name_in) THEN
    SET @mst_sql = CONCAT('ALTER TABLE `', table_name_in, '` ADD ', definition_in);
    PREPARE mst_statement FROM @mst_sql; EXECUTE mst_statement; DEALLOCATE PREPARE mst_statement;
  END IF;
END //
CREATE PROCEDURE mst_add_foreign_key(IN table_name_in VARCHAR(64), IN constraint_name_in VARCHAR(64), IN definition_in TEXT)
BEGIN
  DECLARE CONTINUE HANDLER FOR SQLEXCEPTION SELECT CONCAT('Could not add link ', constraint_name_in, ' (not needed to log in)') AS warning;
  IF NOT EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME = table_name_in AND CONSTRAINT_NAME = constraint_name_in) THEN
    SET @mst_sql = CONCAT('ALTER TABLE `', table_name_in, '` ADD CONSTRAINT `', constraint_name_in, '` ', definition_in);
    PREPARE mst_statement FROM @mst_sql; EXECUTE mst_statement; DEALLOCATE PREPARE mst_statement;
  END IF;
END //
DELIMITER ;

-- 1. Tables that do not exist yet
CREATE TABLE IF NOT EXISTS users (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, first_name VARCHAR(80) NOT NULL, middle_name VARCHAR(80) NULL, last_name VARCHAR(80) NOT NULL, email VARCHAR(190) NOT NULL UNIQUE, username VARCHAR(40) NOT NULL UNIQUE, password_hash VARCHAR(255) NOT NULL, role ENUM('Super Admin','Admin','Tenant') NOT NULL DEFAULT 'Tenant', status ENUM('Active','Inactive','Suspended') NOT NULL DEFAULT 'Active', created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, last_login TIMESTAMP NULL, INDEX idx_users_role_status (role, status));
CREATE TABLE IF NOT EXISTS computers (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, device_id VARCHAR(40) NOT NULL UNIQUE, hostname VARCHAR(120) NOT NULL, display_name VARCHAR(120) NULL, ip_address VARCHAR(45) NOT NULL, operating_system VARCHAR(80) NOT NULL, status ENUM('online','offline','warning','threat') NOT NULL, threat_level ENUM('safe','unknown','warning','high') NOT NULL, cpu_usage TINYINT UNSIGNED NULL, memory_usage TINYINT UNSIGNED NULL, last_seen VARCHAR(40) NOT NULL, agent_status ENUM('connected','disconnected','outdated') NOT NULL, mac_address VARCHAR(17) NULL, agent_version VARCHAR(20) NULL, disk_usage TINYINT UNSIGNED NULL, last_heartbeat_at DATETIME NULL, agent_token_hash CHAR(64) NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS threats (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, computer_id INT UNSIGNED NULL, threat_name VARCHAR(160) NOT NULL, description TEXT NULL, severity ENUM('CRITICAL','HIGH','MEDIUM','LOW','SAFE') NOT NULL, status ENUM('Detected','Investigating','Quarantined','Resolved','Ignored') NOT NULL DEFAULT 'Detected', source VARCHAR(80) NOT NULL, detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, resolved_at TIMESTAMP NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, scan_id INT UNSIGNED NULL, INDEX idx_threat_status (status), INDEX idx_threat_severity (severity), CONSTRAINT fk_threat_computer FOREIGN KEY (computer_id) REFERENCES computers(id) ON DELETE SET NULL);
CREATE TABLE IF NOT EXISTS scans (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, computer_id INT UNSIGNED NULL, scan_type ENUM('File Scan','Quick Scan','Security Scan','Network Scan') NOT NULL, source ENUM('Agent','Auto','Upload') NOT NULL DEFAULT 'Agent', status ENUM('PENDING','SAFE','THREAT','WARNING','UNKNOWN','FAILED') NOT NULL, scan_state ENUM('Pending','Scanning','Completed','Failed') NOT NULL DEFAULT 'Pending', file_name VARCHAR(255) NULL, file_hash VARCHAR(255) NULL, threat_count SMALLINT UNSIGNED NOT NULL DEFAULT 0, started_at TIMESTAMP NULL, completed_at TIMESTAMP NULL, created_by INT UNSIGNED NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, duration VARCHAR(30) NULL, file_event_id BIGINT UNSIGNED NULL, file_path VARCHAR(1024) NULL, risk_level ENUM('Unknown','Safe','Low','Medium','High','Critical','Failed') NULL, scan_details TEXT NULL, detection VARCHAR(255) NULL, evidence_strength ENUM('Strong','Moderate','Limited','N/A') NULL, analysis_coverage ENUM('Full','Partial') NULL, scanner VARCHAR(255) NULL, file_size BIGINT UNSIGNED NULL, file_type VARCHAR(80) NULL, stored_file VARCHAR(80) NULL, stored_until DATETIME NULL, vt_analysis_id VARCHAR(160) NULL, vt_checked_at DATETIME NULL, CONSTRAINT fk_scan_computer FOREIGN KEY (computer_id) REFERENCES computers(id) ON DELETE SET NULL, CONSTRAINT fk_scan_creator FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL, INDEX idx_scans_status (status), INDEX idx_scans_state (scan_state), INDEX idx_scans_risk (risk_level), INDEX idx_scans_created (created_at), INDEX idx_scans_hash (file_hash(64)));
CREATE TABLE IF NOT EXISTS activity_logs (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, user_id INT UNSIGNED NULL, action VARCHAR(60) NOT NULL, description VARCHAR(255) NULL, target_type VARCHAR(60) NULL, target_id VARCHAR(60) NULL, ip_address VARCHAR(45) NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, CONSTRAINT fk_activity_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL, INDEX idx_activity_created (created_at), INDEX idx_activity_action_user (action, user_id, created_at), INDEX idx_activity_action_ip (action, ip_address, created_at));
CREATE TABLE IF NOT EXISTS permissions (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, role ENUM('Super Admin','Admin') NOT NULL, module VARCHAR(80) NOT NULL, allowed BOOLEAN NOT NULL DEFAULT FALSE, UNIQUE KEY uq_permission_role_module (role, module));
CREATE TABLE IF NOT EXISTS settings (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, category VARCHAR(40) NOT NULL DEFAULT 'system', setting_key VARCHAR(100) NOT NULL UNIQUE, setting_value TEXT NOT NULL, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS file_events (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, event_uid CHAR(36) NOT NULL UNIQUE, computer_id INT UNSIGNED NOT NULL, event_type ENUM('created','modified','renamed','deleted') NOT NULL, delete_mode ENUM('recycle_bin','permanent','recycle_bin_removed') NULL, is_folder TINYINT(1) NOT NULL DEFAULT 0, file_name VARCHAR(255) NOT NULL, file_path VARCHAR(1024) NOT NULL, previous_path VARCHAR(1024) NULL, file_size BIGINT UNSIGNED NULL, sha256 CHAR(64) NULL, status ENUM('New','Reviewed','Scan Requested','Scanned','Scan Failed') NOT NULL DEFAULT 'New', detected_at DATETIME NOT NULL, received_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, risk_level ENUM('Unknown','Safe','Low','Medium','High','Critical','Failed') NOT NULL DEFAULT 'Unknown', suggested_confidential TINYINT(1) NOT NULL DEFAULT 0, classification ENUM('Normal','Confidential') NULL, scan_id INT UNSIGNED NULL, origin ENUM('local','browser_download','internet') NULL, download_url VARCHAR(500) NULL, CONSTRAINT fk_file_event_computer FOREIGN KEY (computer_id) REFERENCES computers(id) ON DELETE CASCADE, INDEX idx_file_events_computer_detected (computer_id, detected_at), INDEX idx_file_events_detected (detected_at));
CREATE TABLE IF NOT EXISTS hash_blocklist (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, sha256 CHAR(64) NOT NULL UNIQUE, name VARCHAR(160) NOT NULL, severity ENUM('CRITICAL','HIGH','MEDIUM','LOW') NOT NULL DEFAULT 'HIGH', source VARCHAR(80) NOT NULL DEFAULT 'Manual', created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS hash_reputation (sha256 CHAR(64) NOT NULL PRIMARY KEY, source VARCHAR(40) NOT NULL DEFAULT 'VirusTotal', status ENUM('found','not_found') NOT NULL, malicious SMALLINT UNSIGNED NOT NULL DEFAULT 0, suspicious SMALLINT UNSIGNED NOT NULL DEFAULT 0, harmless SMALLINT UNSIGNED NOT NULL DEFAULT 0, undetected SMALLINT UNSIGNED NOT NULL DEFAULT 0, total SMALLINT UNSIGNED NOT NULL DEFAULT 0, name VARCHAR(160) NULL, checked_at DATETIME NOT NULL);
CREATE TABLE IF NOT EXISTS quarantine_items (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, computer_id INT UNSIGNED NOT NULL, file_event_id BIGINT UNSIGNED NULL, scan_id INT UNSIGNED NULL, file_name VARCHAR(255) NOT NULL, original_path VARCHAR(1024) NOT NULL, sha256 CHAR(64) NOT NULL, quarantine_name VARCHAR(160) NULL, status ENUM('Quarantine Requested','Quarantined','Release Requested','Released','Delete Requested','Deleted','Failed') NOT NULL, pending_action ENUM('quarantine','release','delete') NULL, action_sent_at DATETIME NULL, last_error VARCHAR(255) NULL, requested_by INT UNSIGNED NULL, release_reason VARCHAR(255) NULL, quarantined_at DATETIME NULL, released_at DATETIME NULL, deleted_at DATETIME NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, CONSTRAINT fk_quarantine_computer FOREIGN KEY (computer_id) REFERENCES computers(id) ON DELETE CASCADE, CONSTRAINT fk_quarantine_file_event FOREIGN KEY (file_event_id) REFERENCES file_events(id) ON DELETE SET NULL, CONSTRAINT fk_quarantine_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL, CONSTRAINT fk_quarantine_user FOREIGN KEY (requested_by) REFERENCES users(id) ON DELETE SET NULL, INDEX idx_quarantine_jobs (computer_id, pending_action), INDEX idx_quarantine_status (status));
CREATE TABLE IF NOT EXISTS trusted_devices (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, user_id INT UNSIGNED NOT NULL, name VARCHAR(80) NOT NULL, key_hash CHAR(64) NOT NULL UNIQUE, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, last_used_at DATETIME NULL, revoked_at DATETIME NULL, CONSTRAINT fk_trusted_device_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, INDEX idx_trusted_devices_user (user_id, revoked_at));
CREATE TABLE IF NOT EXISTS phone_requests (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, purpose ENUM('login','pair') NOT NULL, token_hash CHAR(64) NOT NULL UNIQUE, user_id INT UNSIGNED NOT NULL, status ENUM('pending','approved','denied','used','expired') NOT NULL DEFAULT 'pending', match_number TINYINT UNSIGNED NULL, requester_ip VARCHAR(45) NULL, requester_agent VARCHAR(160) NULL, device_id INT UNSIGNED NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, expires_at DATETIME NOT NULL, decided_at DATETIME NULL, CONSTRAINT fk_phone_request_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, CONSTRAINT fk_phone_request_device FOREIGN KEY (device_id) REFERENCES trusted_devices(id) ON DELETE SET NULL, INDEX idx_phone_requests_user (user_id, status));
CREATE TABLE IF NOT EXISTS agent_enrollment_keys (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, key_hash CHAR(64) NOT NULL UNIQUE, label VARCHAR(80) NOT NULL, max_uses SMALLINT UNSIGNED NOT NULL, uses SMALLINT UNSIGNED NOT NULL DEFAULT 0, expires_at DATETIME NOT NULL, created_by INT UNSIGNED NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, last_used_at DATETIME NULL, revoked_at DATETIME NULL, CONSTRAINT fk_enrollment_key_user FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL, INDEX idx_enrollment_keys_active (revoked_at, expires_at));

-- 2. Columns that are missing in older tables
CALL mst_add_column('users', 'first_name', 'VARCHAR(80) NOT NULL');
CALL mst_add_column('users', 'middle_name', 'VARCHAR(80) NULL');
CALL mst_add_column('users', 'last_name', 'VARCHAR(80) NOT NULL');
CALL mst_add_column('users', 'email', 'VARCHAR(190) NOT NULL');
CALL mst_add_column('users', 'username', 'VARCHAR(40) NOT NULL');
CALL mst_add_column('users', 'password_hash', 'VARCHAR(255) NOT NULL');
CALL mst_add_column('users', 'role', 'ENUM(''Super Admin'',''Admin'',''Tenant'') NOT NULL DEFAULT ''Tenant''');
CALL mst_add_column('users', 'status', 'ENUM(''Active'',''Inactive'',''Suspended'') NOT NULL DEFAULT ''Active''');
CALL mst_add_column('users', 'created_at', 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP');
CALL mst_add_column('users', 'updated_at', 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');
CALL mst_add_column('users', 'last_login', 'TIMESTAMP NULL');
CALL mst_add_column('computers', 'device_id', 'VARCHAR(40) NOT NULL');
CALL mst_add_column('computers', 'hostname', 'VARCHAR(120) NOT NULL');
CALL mst_add_column('computers', 'display_name', 'VARCHAR(120) NULL');
CALL mst_add_column('computers', 'ip_address', 'VARCHAR(45) NOT NULL');
CALL mst_add_column('computers', 'operating_system', 'VARCHAR(80) NOT NULL');
CALL mst_add_column('computers', 'status', 'ENUM(''online'',''offline'',''warning'',''threat'') NOT NULL');
CALL mst_add_column('computers', 'threat_level', 'ENUM(''safe'',''unknown'',''warning'',''high'') NOT NULL');
CALL mst_add_column('computers', 'cpu_usage', 'TINYINT UNSIGNED NULL');
CALL mst_add_column('computers', 'memory_usage', 'TINYINT UNSIGNED NULL');
CALL mst_add_column('computers', 'last_seen', 'VARCHAR(40) NOT NULL');
CALL mst_add_column('computers', 'agent_status', 'ENUM(''connected'',''disconnected'',''outdated'') NOT NULL');
CALL mst_add_column('computers', 'mac_address', 'VARCHAR(17) NULL');
CALL mst_add_column('computers', 'agent_version', 'VARCHAR(20) NULL');
CALL mst_add_column('computers', 'disk_usage', 'TINYINT UNSIGNED NULL');
CALL mst_add_column('computers', 'last_heartbeat_at', 'DATETIME NULL');
CALL mst_add_column('computers', 'agent_token_hash', 'CHAR(64) NULL');
CALL mst_add_column('computers', 'created_at', 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP');
CALL mst_add_column('computers', 'updated_at', 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');
CALL mst_add_column('threats', 'computer_id', 'INT UNSIGNED NULL');
CALL mst_add_column('threats', 'threat_name', 'VARCHAR(160) NOT NULL');
CALL mst_add_column('threats', 'description', 'TEXT NULL');
CALL mst_add_column('threats', 'severity', 'ENUM(''CRITICAL'',''HIGH'',''MEDIUM'',''LOW'',''SAFE'') NOT NULL');
CALL mst_add_column('threats', 'status', 'ENUM(''Detected'',''Investigating'',''Quarantined'',''Resolved'',''Ignored'') NOT NULL DEFAULT ''Detected''');
CALL mst_add_column('threats', 'source', 'VARCHAR(80) NOT NULL');
CALL mst_add_column('threats', 'detected_at', 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP');
CALL mst_add_column('threats', 'resolved_at', 'TIMESTAMP NULL');
CALL mst_add_column('threats', 'created_at', 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP');
CALL mst_add_column('threats', 'updated_at', 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');
CALL mst_add_column('threats', 'scan_id', 'INT UNSIGNED NULL');
CALL mst_add_column('scans', 'computer_id', 'INT UNSIGNED NULL');
CALL mst_add_column('scans', 'scan_type', 'ENUM(''File Scan'',''Quick Scan'',''Security Scan'',''Network Scan'') NOT NULL');
CALL mst_add_column('scans', 'source', 'ENUM(''Agent'',''Auto'',''Upload'') NOT NULL DEFAULT ''Agent''');
CALL mst_add_column('scans', 'status', 'ENUM(''PENDING'',''SAFE'',''THREAT'',''WARNING'',''UNKNOWN'',''FAILED'') NOT NULL');
CALL mst_add_column('scans', 'scan_state', 'ENUM(''Pending'',''Scanning'',''Completed'',''Failed'') NOT NULL DEFAULT ''Pending''');
CALL mst_add_column('scans', 'file_name', 'VARCHAR(255) NULL');
CALL mst_add_column('scans', 'file_hash', 'VARCHAR(255) NULL');
CALL mst_add_column('scans', 'threat_count', 'SMALLINT UNSIGNED NOT NULL DEFAULT 0');
CALL mst_add_column('scans', 'started_at', 'TIMESTAMP NULL');
CALL mst_add_column('scans', 'completed_at', 'TIMESTAMP NULL');
CALL mst_add_column('scans', 'created_by', 'INT UNSIGNED NULL');
CALL mst_add_column('scans', 'created_at', 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP');
CALL mst_add_column('scans', 'duration', 'VARCHAR(30) NULL');
CALL mst_add_column('scans', 'file_event_id', 'BIGINT UNSIGNED NULL');
CALL mst_add_column('scans', 'file_path', 'VARCHAR(1024) NULL');
CALL mst_add_column('scans', 'risk_level', 'ENUM(''Unknown'',''Safe'',''Low'',''Medium'',''High'',''Critical'',''Failed'') NULL');
CALL mst_add_column('scans', 'scan_details', 'TEXT NULL');
CALL mst_add_column('scans', 'detection', 'VARCHAR(255) NULL');
CALL mst_add_column('scans', 'evidence_strength', 'ENUM(''Strong'',''Moderate'',''Limited'',''N/A'') NULL');
CALL mst_add_column('scans', 'analysis_coverage', 'ENUM(''Full'',''Partial'') NULL');
CALL mst_add_column('scans', 'scanner', 'VARCHAR(255) NULL');
CALL mst_add_column('scans', 'file_size', 'BIGINT UNSIGNED NULL');
CALL mst_add_column('scans', 'file_type', 'VARCHAR(80) NULL');
CALL mst_add_column('scans', 'stored_file', 'VARCHAR(80) NULL');
CALL mst_add_column('scans', 'stored_until', 'DATETIME NULL');
CALL mst_add_column('scans', 'vt_analysis_id', 'VARCHAR(160) NULL');
CALL mst_add_column('scans', 'vt_checked_at', 'DATETIME NULL');
CALL mst_add_column('activity_logs', 'user_id', 'INT UNSIGNED NULL');
CALL mst_add_column('activity_logs', 'action', 'VARCHAR(60) NOT NULL');
CALL mst_add_column('activity_logs', 'description', 'VARCHAR(255) NULL');
CALL mst_add_column('activity_logs', 'target_type', 'VARCHAR(60) NULL');
CALL mst_add_column('activity_logs', 'target_id', 'VARCHAR(60) NULL');
CALL mst_add_column('activity_logs', 'ip_address', 'VARCHAR(45) NULL');
CALL mst_add_column('activity_logs', 'created_at', 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP');
CALL mst_add_column('permissions', 'role', 'ENUM(''Super Admin'',''Admin'') NOT NULL');
CALL mst_add_column('permissions', 'module', 'VARCHAR(80) NOT NULL');
CALL mst_add_column('permissions', 'allowed', 'BOOLEAN NOT NULL DEFAULT FALSE');
CALL mst_add_column('settings', 'category', 'VARCHAR(40) NOT NULL DEFAULT ''system''');
CALL mst_add_column('settings', 'setting_key', 'VARCHAR(100) NOT NULL');
CALL mst_add_column('settings', 'setting_value', 'TEXT NOT NULL');
CALL mst_add_column('settings', 'updated_at', 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');
CALL mst_add_column('file_events', 'event_uid', 'CHAR(36) NOT NULL');
CALL mst_add_column('file_events', 'computer_id', 'INT UNSIGNED NOT NULL');
CALL mst_add_column('file_events', 'event_type', 'ENUM(''created'',''modified'',''renamed'',''deleted'') NOT NULL');
CALL mst_add_column('file_events', 'delete_mode', 'ENUM(''recycle_bin'',''permanent'',''recycle_bin_removed'') NULL');
CALL mst_add_column('file_events', 'is_folder', 'TINYINT(1) NOT NULL DEFAULT 0');
CALL mst_add_column('file_events', 'file_name', 'VARCHAR(255) NOT NULL');
CALL mst_add_column('file_events', 'file_path', 'VARCHAR(1024) NOT NULL');
CALL mst_add_column('file_events', 'previous_path', 'VARCHAR(1024) NULL');
CALL mst_add_column('file_events', 'file_size', 'BIGINT UNSIGNED NULL');
CALL mst_add_column('file_events', 'sha256', 'CHAR(64) NULL');
CALL mst_add_column('file_events', 'status', 'ENUM(''New'',''Reviewed'',''Scan Requested'',''Scanned'',''Scan Failed'') NOT NULL DEFAULT ''New''');
CALL mst_add_column('file_events', 'detected_at', 'DATETIME NOT NULL');
CALL mst_add_column('file_events', 'received_at', 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP');
CALL mst_add_column('file_events', 'risk_level', 'ENUM(''Unknown'',''Safe'',''Low'',''Medium'',''High'',''Critical'',''Failed'') NOT NULL DEFAULT ''Unknown''');
CALL mst_add_column('file_events', 'suggested_confidential', 'TINYINT(1) NOT NULL DEFAULT 0');
CALL mst_add_column('file_events', 'classification', 'ENUM(''Normal'',''Confidential'') NULL');
CALL mst_add_column('file_events', 'scan_id', 'INT UNSIGNED NULL');
CALL mst_add_column('file_events', 'origin', 'ENUM(''local'',''browser_download'',''internet'') NULL');
CALL mst_add_column('file_events', 'download_url', 'VARCHAR(500) NULL');
CALL mst_add_column('hash_blocklist', 'sha256', 'CHAR(64) NOT NULL');
CALL mst_add_column('hash_blocklist', 'name', 'VARCHAR(160) NOT NULL');
CALL mst_add_column('hash_blocklist', 'severity', 'ENUM(''CRITICAL'',''HIGH'',''MEDIUM'',''LOW'') NOT NULL DEFAULT ''HIGH''');
CALL mst_add_column('hash_blocklist', 'source', 'VARCHAR(80) NOT NULL DEFAULT ''Manual''');
CALL mst_add_column('hash_blocklist', 'created_at', 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP');
CALL mst_add_column('hash_reputation', 'source', 'VARCHAR(40) NOT NULL DEFAULT ''VirusTotal''');
CALL mst_add_column('hash_reputation', 'status', 'ENUM(''found'',''not_found'') NOT NULL');
CALL mst_add_column('hash_reputation', 'malicious', 'SMALLINT UNSIGNED NOT NULL DEFAULT 0');
CALL mst_add_column('hash_reputation', 'suspicious', 'SMALLINT UNSIGNED NOT NULL DEFAULT 0');
CALL mst_add_column('hash_reputation', 'harmless', 'SMALLINT UNSIGNED NOT NULL DEFAULT 0');
CALL mst_add_column('hash_reputation', 'undetected', 'SMALLINT UNSIGNED NOT NULL DEFAULT 0');
CALL mst_add_column('hash_reputation', 'total', 'SMALLINT UNSIGNED NOT NULL DEFAULT 0');
CALL mst_add_column('hash_reputation', 'name', 'VARCHAR(160) NULL');
CALL mst_add_column('hash_reputation', 'checked_at', 'DATETIME NOT NULL');
CALL mst_add_column('quarantine_items', 'computer_id', 'INT UNSIGNED NOT NULL');
CALL mst_add_column('quarantine_items', 'file_event_id', 'BIGINT UNSIGNED NULL');
CALL mst_add_column('quarantine_items', 'scan_id', 'INT UNSIGNED NULL');
CALL mst_add_column('quarantine_items', 'file_name', 'VARCHAR(255) NOT NULL');
CALL mst_add_column('quarantine_items', 'original_path', 'VARCHAR(1024) NOT NULL');
CALL mst_add_column('quarantine_items', 'sha256', 'CHAR(64) NOT NULL');
CALL mst_add_column('quarantine_items', 'quarantine_name', 'VARCHAR(160) NULL');
CALL mst_add_column('quarantine_items', 'status', 'ENUM(''Quarantine Requested'',''Quarantined'',''Release Requested'',''Released'',''Delete Requested'',''Deleted'',''Failed'') NOT NULL');
CALL mst_add_column('quarantine_items', 'pending_action', 'ENUM(''quarantine'',''release'',''delete'') NULL');
CALL mst_add_column('quarantine_items', 'action_sent_at', 'DATETIME NULL');
CALL mst_add_column('quarantine_items', 'last_error', 'VARCHAR(255) NULL');
CALL mst_add_column('quarantine_items', 'requested_by', 'INT UNSIGNED NULL');
CALL mst_add_column('quarantine_items', 'release_reason', 'VARCHAR(255) NULL');
CALL mst_add_column('quarantine_items', 'quarantined_at', 'DATETIME NULL');
CALL mst_add_column('quarantine_items', 'released_at', 'DATETIME NULL');
CALL mst_add_column('quarantine_items', 'deleted_at', 'DATETIME NULL');
CALL mst_add_column('quarantine_items', 'created_at', 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP');
CALL mst_add_column('quarantine_items', 'updated_at', 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');
CALL mst_add_column('trusted_devices', 'user_id', 'INT UNSIGNED NOT NULL');
CALL mst_add_column('trusted_devices', 'name', 'VARCHAR(80) NOT NULL');
CALL mst_add_column('trusted_devices', 'key_hash', 'CHAR(64) NOT NULL');
CALL mst_add_column('trusted_devices', 'created_at', 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP');
CALL mst_add_column('trusted_devices', 'last_used_at', 'DATETIME NULL');
CALL mst_add_column('trusted_devices', 'revoked_at', 'DATETIME NULL');
CALL mst_add_column('phone_requests', 'purpose', 'ENUM(''login'',''pair'') NOT NULL');
CALL mst_add_column('phone_requests', 'token_hash', 'CHAR(64) NOT NULL');
CALL mst_add_column('phone_requests', 'user_id', 'INT UNSIGNED NOT NULL');
CALL mst_add_column('phone_requests', 'status', 'ENUM(''pending'',''approved'',''denied'',''used'',''expired'') NOT NULL DEFAULT ''pending''');
CALL mst_add_column('phone_requests', 'match_number', 'TINYINT UNSIGNED NULL');
CALL mst_add_column('phone_requests', 'requester_ip', 'VARCHAR(45) NULL');
CALL mst_add_column('phone_requests', 'requester_agent', 'VARCHAR(160) NULL');
CALL mst_add_column('phone_requests', 'device_id', 'INT UNSIGNED NULL');
CALL mst_add_column('phone_requests', 'created_at', 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP');
CALL mst_add_column('phone_requests', 'expires_at', 'DATETIME NOT NULL');
CALL mst_add_column('phone_requests', 'decided_at', 'DATETIME NULL');
CALL mst_add_column('agent_enrollment_keys', 'key_hash', 'CHAR(64) NOT NULL');
CALL mst_add_column('agent_enrollment_keys', 'label', 'VARCHAR(80) NOT NULL');
CALL mst_add_column('agent_enrollment_keys', 'max_uses', 'SMALLINT UNSIGNED NOT NULL');
CALL mst_add_column('agent_enrollment_keys', 'uses', 'SMALLINT UNSIGNED NOT NULL DEFAULT 0');
CALL mst_add_column('agent_enrollment_keys', 'expires_at', 'DATETIME NOT NULL');
CALL mst_add_column('agent_enrollment_keys', 'created_by', 'INT UNSIGNED NULL');
CALL mst_add_column('agent_enrollment_keys', 'created_at', 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP');
CALL mst_add_column('agent_enrollment_keys', 'last_used_at', 'DATETIME NULL');
CALL mst_add_column('agent_enrollment_keys', 'revoked_at', 'DATETIME NULL');

-- 3. New allowed values in list (ENUM) columns
CALL mst_allow_values('users', 'role', 'ENUM(''Super Admin'',''Admin'',''Tenant'') NOT NULL DEFAULT ''Tenant''', 'ENUM(''Super Admin'',''Admin'',''Tenant'')');
CALL mst_allow_values('users', 'status', 'ENUM(''Active'',''Inactive'',''Suspended'') NOT NULL DEFAULT ''Active''', 'ENUM(''Active'',''Inactive'',''Suspended'')');
CALL mst_allow_values('computers', 'status', 'ENUM(''online'',''offline'',''warning'',''threat'') NOT NULL', 'ENUM(''online'',''offline'',''warning'',''threat'')');
CALL mst_allow_values('computers', 'threat_level', 'ENUM(''safe'',''unknown'',''warning'',''high'') NOT NULL', 'ENUM(''safe'',''unknown'',''warning'',''high'')');
CALL mst_allow_values('computers', 'agent_status', 'ENUM(''connected'',''disconnected'',''outdated'') NOT NULL', 'ENUM(''connected'',''disconnected'',''outdated'')');
CALL mst_allow_values('threats', 'severity', 'ENUM(''CRITICAL'',''HIGH'',''MEDIUM'',''LOW'',''SAFE'') NOT NULL', 'ENUM(''CRITICAL'',''HIGH'',''MEDIUM'',''LOW'',''SAFE'')');
CALL mst_allow_values('threats', 'status', 'ENUM(''Detected'',''Investigating'',''Quarantined'',''Resolved'',''Ignored'') NOT NULL DEFAULT ''Detected''', 'ENUM(''Detected'',''Investigating'',''Quarantined'',''Resolved'',''Ignored'')');
CALL mst_allow_values('scans', 'scan_type', 'ENUM(''File Scan'',''Quick Scan'',''Security Scan'',''Network Scan'') NOT NULL', 'ENUM(''File Scan'',''Quick Scan'',''Security Scan'',''Network Scan'')');
CALL mst_allow_values('scans', 'source', 'ENUM(''Agent'',''Auto'',''Upload'') NOT NULL DEFAULT ''Agent''', 'ENUM(''Agent'',''Auto'',''Upload'')');
CALL mst_allow_values('scans', 'status', 'ENUM(''PENDING'',''SAFE'',''THREAT'',''WARNING'',''UNKNOWN'',''FAILED'') NOT NULL', 'ENUM(''PENDING'',''SAFE'',''THREAT'',''WARNING'',''UNKNOWN'',''FAILED'')');
CALL mst_allow_values('scans', 'scan_state', 'ENUM(''Pending'',''Scanning'',''Completed'',''Failed'') NOT NULL DEFAULT ''Pending''', 'ENUM(''Pending'',''Scanning'',''Completed'',''Failed'')');
CALL mst_allow_values('scans', 'risk_level', 'ENUM(''Unknown'',''Safe'',''Low'',''Medium'',''High'',''Critical'',''Failed'') NULL', 'ENUM(''Unknown'',''Safe'',''Low'',''Medium'',''High'',''Critical'',''Failed'')');
CALL mst_allow_values('scans', 'evidence_strength', 'ENUM(''Strong'',''Moderate'',''Limited'',''N/A'') NULL', 'ENUM(''Strong'',''Moderate'',''Limited'',''N/A'')');
CALL mst_allow_values('scans', 'analysis_coverage', 'ENUM(''Full'',''Partial'') NULL', 'ENUM(''Full'',''Partial'')');
CALL mst_allow_values('permissions', 'role', 'ENUM(''Super Admin'',''Admin'') NOT NULL', 'ENUM(''Super Admin'',''Admin'')');
CALL mst_allow_values('file_events', 'event_type', 'ENUM(''created'',''modified'',''renamed'',''deleted'') NOT NULL', 'ENUM(''created'',''modified'',''renamed'',''deleted'')');
CALL mst_allow_values('file_events', 'delete_mode', 'ENUM(''recycle_bin'',''permanent'',''recycle_bin_removed'') NULL', 'ENUM(''recycle_bin'',''permanent'',''recycle_bin_removed'')');
CALL mst_allow_values('file_events', 'status', 'ENUM(''New'',''Reviewed'',''Scan Requested'',''Scanned'',''Scan Failed'') NOT NULL DEFAULT ''New''', 'ENUM(''New'',''Reviewed'',''Scan Requested'',''Scanned'',''Scan Failed'')');
CALL mst_allow_values('file_events', 'risk_level', 'ENUM(''Unknown'',''Safe'',''Low'',''Medium'',''High'',''Critical'',''Failed'') NOT NULL DEFAULT ''Unknown''', 'ENUM(''Unknown'',''Safe'',''Low'',''Medium'',''High'',''Critical'',''Failed'')');
CALL mst_allow_values('file_events', 'classification', 'ENUM(''Normal'',''Confidential'') NULL', 'ENUM(''Normal'',''Confidential'')');
CALL mst_allow_values('file_events', 'origin', 'ENUM(''local'',''browser_download'',''internet'') NULL', 'ENUM(''local'',''browser_download'',''internet'')');
CALL mst_allow_values('hash_blocklist', 'severity', 'ENUM(''CRITICAL'',''HIGH'',''MEDIUM'',''LOW'') NOT NULL DEFAULT ''HIGH''', 'ENUM(''CRITICAL'',''HIGH'',''MEDIUM'',''LOW'')');
CALL mst_allow_values('hash_reputation', 'status', 'ENUM(''found'',''not_found'') NOT NULL', 'ENUM(''found'',''not_found'')');
CALL mst_allow_values('quarantine_items', 'status', 'ENUM(''Quarantine Requested'',''Quarantined'',''Release Requested'',''Released'',''Delete Requested'',''Deleted'',''Failed'') NOT NULL', 'ENUM(''Quarantine Requested'',''Quarantined'',''Release Requested'',''Released'',''Delete Requested'',''Deleted'',''Failed'')');
CALL mst_allow_values('quarantine_items', 'pending_action', 'ENUM(''quarantine'',''release'',''delete'') NULL', 'ENUM(''quarantine'',''release'',''delete'')');
CALL mst_allow_values('phone_requests', 'purpose', 'ENUM(''login'',''pair'') NOT NULL', 'ENUM(''login'',''pair'')');
CALL mst_allow_values('phone_requests', 'status', 'ENUM(''pending'',''approved'',''denied'',''used'',''expired'') NOT NULL DEFAULT ''pending''', 'ENUM(''pending'',''approved'',''denied'',''used'',''expired'')');

-- 4. Indexes (speed) and links between tables
CALL mst_add_index('users', 'idx_users_role_status', 'INDEX idx_users_role_status (role, status)');
CALL mst_add_index('threats', 'idx_threat_status', 'INDEX idx_threat_status (status)');
CALL mst_add_index('threats', 'idx_threat_severity', 'INDEX idx_threat_severity (severity)');
CALL mst_add_index('scans', 'idx_scans_status', 'INDEX idx_scans_status (status)');
CALL mst_add_index('scans', 'idx_scans_state', 'INDEX idx_scans_state (scan_state)');
CALL mst_add_index('scans', 'idx_scans_risk', 'INDEX idx_scans_risk (risk_level)');
CALL mst_add_index('scans', 'idx_scans_created', 'INDEX idx_scans_created (created_at)');
CALL mst_add_index('scans', 'idx_scans_hash', 'INDEX idx_scans_hash (file_hash(64))');
CALL mst_add_index('activity_logs', 'idx_activity_created', 'INDEX idx_activity_created (created_at)');
CALL mst_add_index('activity_logs', 'idx_activity_action_user', 'INDEX idx_activity_action_user (action, user_id, created_at)');
CALL mst_add_index('activity_logs', 'idx_activity_action_ip', 'INDEX idx_activity_action_ip (action, ip_address, created_at)');
CALL mst_add_index('permissions', 'uq_permission_role_module', 'UNIQUE KEY uq_permission_role_module (role, module)');
CALL mst_add_index('file_events', 'idx_file_events_computer_detected', 'INDEX idx_file_events_computer_detected (computer_id, detected_at)');
CALL mst_add_index('file_events', 'idx_file_events_detected', 'INDEX idx_file_events_detected (detected_at)');
CALL mst_add_index('quarantine_items', 'idx_quarantine_jobs', 'INDEX idx_quarantine_jobs (computer_id, pending_action)');
CALL mst_add_index('quarantine_items', 'idx_quarantine_status', 'INDEX idx_quarantine_status (status)');
CALL mst_add_index('trusted_devices', 'idx_trusted_devices_user', 'INDEX idx_trusted_devices_user (user_id, revoked_at)');
CALL mst_add_index('phone_requests', 'idx_phone_requests_user', 'INDEX idx_phone_requests_user (user_id, status)');
CALL mst_add_index('agent_enrollment_keys', 'idx_enrollment_keys_active', 'INDEX idx_enrollment_keys_active (revoked_at, expires_at)');
CALL mst_add_foreign_key('threats', 'fk_threat_computer', 'FOREIGN KEY (computer_id) REFERENCES computers(id) ON DELETE SET NULL');
CALL mst_add_foreign_key('scans', 'fk_scan_computer', 'FOREIGN KEY (computer_id) REFERENCES computers(id) ON DELETE SET NULL');
CALL mst_add_foreign_key('scans', 'fk_scan_creator', 'FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL');
CALL mst_add_foreign_key('activity_logs', 'fk_activity_user', 'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL');
CALL mst_add_foreign_key('file_events', 'fk_file_event_computer', 'FOREIGN KEY (computer_id) REFERENCES computers(id) ON DELETE CASCADE');
CALL mst_add_foreign_key('scans', 'fk_scan_file_event', 'FOREIGN KEY (file_event_id) REFERENCES file_events(id) ON DELETE SET NULL');
CALL mst_add_foreign_key('file_events', 'fk_file_event_scan', 'FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL');
CALL mst_add_foreign_key('threats', 'fk_threat_scan', 'FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL');
CALL mst_add_foreign_key('quarantine_items', 'fk_quarantine_computer', 'FOREIGN KEY (computer_id) REFERENCES computers(id) ON DELETE CASCADE');
CALL mst_add_foreign_key('quarantine_items', 'fk_quarantine_file_event', 'FOREIGN KEY (file_event_id) REFERENCES file_events(id) ON DELETE SET NULL');
CALL mst_add_foreign_key('quarantine_items', 'fk_quarantine_scan', 'FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL');
CALL mst_add_foreign_key('quarantine_items', 'fk_quarantine_user', 'FOREIGN KEY (requested_by) REFERENCES users(id) ON DELETE SET NULL');
CALL mst_add_foreign_key('trusted_devices', 'fk_trusted_device_user', 'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE');
CALL mst_add_foreign_key('phone_requests', 'fk_phone_request_user', 'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE');
CALL mst_add_foreign_key('phone_requests', 'fk_phone_request_device', 'FOREIGN KEY (device_id) REFERENCES trusted_devices(id) ON DELETE SET NULL');
CALL mst_add_foreign_key('agent_enrollment_keys', 'fk_enrollment_key_user', 'FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL');

-- 5. Default settings and permissions that are missing (existing ones are kept as they are)
INSERT IGNORE INTO permissions (role, module, allowed) VALUES
('Super Admin','dashboard',1),('Super Admin','computer_monitoring',1),('Super Admin','network',1),('Super Admin','threats',1),('Super Admin','file_scanner',0),('Super Admin','scan_history',1),('Super Admin','reports',1),('Super Admin','activity_logs',1),('Super Admin','user_management',1),('Super Admin','admin_management',1),('Super Admin','permissions',1),('Super Admin','settings',1),
('Admin','dashboard',1),('Admin','computer_monitoring',1),('Admin','network',1),('Admin','threats',1),('Admin','file_scanner',1),('Admin','scan_history',1),('Admin','reports',1),('Admin','activity_logs',1),('Admin','user_management',0),('Admin','admin_management',0),('Admin','permissions',0),('Admin','settings',1);
INSERT IGNORE INTO settings (category, setting_key, setting_value) VALUES ('system','systemName','Monitoring System Threat'),('system','monitoringStatus','1'),('system','refreshInterval','10 seconds'),('scanner','autoScan','1'),('scanner','uploadRetention','7 days');
INSERT IGNORE INTO hash_blocklist (sha256, name, severity, source) VALUES ('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'EICAR anti-virus test file', 'CRITICAL', 'EICAR');
INSERT IGNORE INTO settings (category, setting_key, setting_value) VALUES ('scanner', 'autoScan', '1'), ('scanner', 'uploadRetention', '7 days');

DROP PROCEDURE IF EXISTS mst_add_column;
DROP PROCEDURE IF EXISTS mst_allow_values;
DROP PROCEDURE IF EXISTS mst_add_index;
DROP PROCEDURE IF EXISTS mst_add_foreign_key;
SET FOREIGN_KEY_CHECKS = 1;
SET SQL_SAFE_UPDATES = 1;

-- 6. Check: this list must be EMPTY.
SELECT CONCAT(e.t, '.', e.c) AS `Still missing` FROM (
  SELECT 'users' AS t, 'first_name' AS c
  UNION ALL SELECT 'users' AS t, 'middle_name' AS c
  UNION ALL SELECT 'users' AS t, 'last_name' AS c
  UNION ALL SELECT 'users' AS t, 'email' AS c
  UNION ALL SELECT 'users' AS t, 'username' AS c
  UNION ALL SELECT 'users' AS t, 'password_hash' AS c
  UNION ALL SELECT 'users' AS t, 'role' AS c
  UNION ALL SELECT 'users' AS t, 'status' AS c
  UNION ALL SELECT 'users' AS t, 'created_at' AS c
  UNION ALL SELECT 'users' AS t, 'updated_at' AS c
  UNION ALL SELECT 'users' AS t, 'last_login' AS c
  UNION ALL SELECT 'computers' AS t, 'device_id' AS c
  UNION ALL SELECT 'computers' AS t, 'hostname' AS c
  UNION ALL SELECT 'computers' AS t, 'display_name' AS c
  UNION ALL SELECT 'computers' AS t, 'ip_address' AS c
  UNION ALL SELECT 'computers' AS t, 'operating_system' AS c
  UNION ALL SELECT 'computers' AS t, 'status' AS c
  UNION ALL SELECT 'computers' AS t, 'threat_level' AS c
  UNION ALL SELECT 'computers' AS t, 'cpu_usage' AS c
  UNION ALL SELECT 'computers' AS t, 'memory_usage' AS c
  UNION ALL SELECT 'computers' AS t, 'last_seen' AS c
  UNION ALL SELECT 'computers' AS t, 'agent_status' AS c
  UNION ALL SELECT 'computers' AS t, 'mac_address' AS c
  UNION ALL SELECT 'computers' AS t, 'agent_version' AS c
  UNION ALL SELECT 'computers' AS t, 'disk_usage' AS c
  UNION ALL SELECT 'computers' AS t, 'last_heartbeat_at' AS c
  UNION ALL SELECT 'computers' AS t, 'agent_token_hash' AS c
  UNION ALL SELECT 'computers' AS t, 'created_at' AS c
  UNION ALL SELECT 'computers' AS t, 'updated_at' AS c
  UNION ALL SELECT 'threats' AS t, 'computer_id' AS c
  UNION ALL SELECT 'threats' AS t, 'threat_name' AS c
  UNION ALL SELECT 'threats' AS t, 'description' AS c
  UNION ALL SELECT 'threats' AS t, 'severity' AS c
  UNION ALL SELECT 'threats' AS t, 'status' AS c
  UNION ALL SELECT 'threats' AS t, 'source' AS c
  UNION ALL SELECT 'threats' AS t, 'detected_at' AS c
  UNION ALL SELECT 'threats' AS t, 'resolved_at' AS c
  UNION ALL SELECT 'threats' AS t, 'created_at' AS c
  UNION ALL SELECT 'threats' AS t, 'updated_at' AS c
  UNION ALL SELECT 'threats' AS t, 'scan_id' AS c
  UNION ALL SELECT 'scans' AS t, 'computer_id' AS c
  UNION ALL SELECT 'scans' AS t, 'scan_type' AS c
  UNION ALL SELECT 'scans' AS t, 'source' AS c
  UNION ALL SELECT 'scans' AS t, 'status' AS c
  UNION ALL SELECT 'scans' AS t, 'scan_state' AS c
  UNION ALL SELECT 'scans' AS t, 'file_name' AS c
  UNION ALL SELECT 'scans' AS t, 'file_hash' AS c
  UNION ALL SELECT 'scans' AS t, 'threat_count' AS c
  UNION ALL SELECT 'scans' AS t, 'started_at' AS c
  UNION ALL SELECT 'scans' AS t, 'completed_at' AS c
  UNION ALL SELECT 'scans' AS t, 'created_by' AS c
  UNION ALL SELECT 'scans' AS t, 'created_at' AS c
  UNION ALL SELECT 'scans' AS t, 'duration' AS c
  UNION ALL SELECT 'scans' AS t, 'file_event_id' AS c
  UNION ALL SELECT 'scans' AS t, 'file_path' AS c
  UNION ALL SELECT 'scans' AS t, 'risk_level' AS c
  UNION ALL SELECT 'scans' AS t, 'scan_details' AS c
  UNION ALL SELECT 'scans' AS t, 'detection' AS c
  UNION ALL SELECT 'scans' AS t, 'evidence_strength' AS c
  UNION ALL SELECT 'scans' AS t, 'analysis_coverage' AS c
  UNION ALL SELECT 'scans' AS t, 'scanner' AS c
  UNION ALL SELECT 'scans' AS t, 'file_size' AS c
  UNION ALL SELECT 'scans' AS t, 'file_type' AS c
  UNION ALL SELECT 'scans' AS t, 'stored_file' AS c
  UNION ALL SELECT 'scans' AS t, 'stored_until' AS c
  UNION ALL SELECT 'scans' AS t, 'vt_analysis_id' AS c
  UNION ALL SELECT 'scans' AS t, 'vt_checked_at' AS c
  UNION ALL SELECT 'activity_logs' AS t, 'user_id' AS c
  UNION ALL SELECT 'activity_logs' AS t, 'action' AS c
  UNION ALL SELECT 'activity_logs' AS t, 'description' AS c
  UNION ALL SELECT 'activity_logs' AS t, 'target_type' AS c
  UNION ALL SELECT 'activity_logs' AS t, 'target_id' AS c
  UNION ALL SELECT 'activity_logs' AS t, 'ip_address' AS c
  UNION ALL SELECT 'activity_logs' AS t, 'created_at' AS c
  UNION ALL SELECT 'permissions' AS t, 'role' AS c
  UNION ALL SELECT 'permissions' AS t, 'module' AS c
  UNION ALL SELECT 'permissions' AS t, 'allowed' AS c
  UNION ALL SELECT 'settings' AS t, 'category' AS c
  UNION ALL SELECT 'settings' AS t, 'setting_key' AS c
  UNION ALL SELECT 'settings' AS t, 'setting_value' AS c
  UNION ALL SELECT 'settings' AS t, 'updated_at' AS c
  UNION ALL SELECT 'file_events' AS t, 'event_uid' AS c
  UNION ALL SELECT 'file_events' AS t, 'computer_id' AS c
  UNION ALL SELECT 'file_events' AS t, 'event_type' AS c
  UNION ALL SELECT 'file_events' AS t, 'delete_mode' AS c
  UNION ALL SELECT 'file_events' AS t, 'is_folder' AS c
  UNION ALL SELECT 'file_events' AS t, 'file_name' AS c
  UNION ALL SELECT 'file_events' AS t, 'file_path' AS c
  UNION ALL SELECT 'file_events' AS t, 'previous_path' AS c
  UNION ALL SELECT 'file_events' AS t, 'file_size' AS c
  UNION ALL SELECT 'file_events' AS t, 'sha256' AS c
  UNION ALL SELECT 'file_events' AS t, 'status' AS c
  UNION ALL SELECT 'file_events' AS t, 'detected_at' AS c
  UNION ALL SELECT 'file_events' AS t, 'received_at' AS c
  UNION ALL SELECT 'file_events' AS t, 'risk_level' AS c
  UNION ALL SELECT 'file_events' AS t, 'suggested_confidential' AS c
  UNION ALL SELECT 'file_events' AS t, 'classification' AS c
  UNION ALL SELECT 'file_events' AS t, 'scan_id' AS c
  UNION ALL SELECT 'file_events' AS t, 'origin' AS c
  UNION ALL SELECT 'file_events' AS t, 'download_url' AS c
  UNION ALL SELECT 'hash_blocklist' AS t, 'sha256' AS c
  UNION ALL SELECT 'hash_blocklist' AS t, 'name' AS c
  UNION ALL SELECT 'hash_blocklist' AS t, 'severity' AS c
  UNION ALL SELECT 'hash_blocklist' AS t, 'source' AS c
  UNION ALL SELECT 'hash_blocklist' AS t, 'created_at' AS c
  UNION ALL SELECT 'hash_reputation' AS t, 'source' AS c
  UNION ALL SELECT 'hash_reputation' AS t, 'status' AS c
  UNION ALL SELECT 'hash_reputation' AS t, 'malicious' AS c
  UNION ALL SELECT 'hash_reputation' AS t, 'suspicious' AS c
  UNION ALL SELECT 'hash_reputation' AS t, 'harmless' AS c
  UNION ALL SELECT 'hash_reputation' AS t, 'undetected' AS c
  UNION ALL SELECT 'hash_reputation' AS t, 'total' AS c
  UNION ALL SELECT 'hash_reputation' AS t, 'name' AS c
  UNION ALL SELECT 'hash_reputation' AS t, 'checked_at' AS c
  UNION ALL SELECT 'quarantine_items' AS t, 'computer_id' AS c
  UNION ALL SELECT 'quarantine_items' AS t, 'file_event_id' AS c
  UNION ALL SELECT 'quarantine_items' AS t, 'scan_id' AS c
  UNION ALL SELECT 'quarantine_items' AS t, 'file_name' AS c
  UNION ALL SELECT 'quarantine_items' AS t, 'original_path' AS c
  UNION ALL SELECT 'quarantine_items' AS t, 'sha256' AS c
  UNION ALL SELECT 'quarantine_items' AS t, 'quarantine_name' AS c
  UNION ALL SELECT 'quarantine_items' AS t, 'status' AS c
  UNION ALL SELECT 'quarantine_items' AS t, 'pending_action' AS c
  UNION ALL SELECT 'quarantine_items' AS t, 'action_sent_at' AS c
  UNION ALL SELECT 'quarantine_items' AS t, 'last_error' AS c
  UNION ALL SELECT 'quarantine_items' AS t, 'requested_by' AS c
  UNION ALL SELECT 'quarantine_items' AS t, 'release_reason' AS c
  UNION ALL SELECT 'quarantine_items' AS t, 'quarantined_at' AS c
  UNION ALL SELECT 'quarantine_items' AS t, 'released_at' AS c
  UNION ALL SELECT 'quarantine_items' AS t, 'deleted_at' AS c
  UNION ALL SELECT 'quarantine_items' AS t, 'created_at' AS c
  UNION ALL SELECT 'quarantine_items' AS t, 'updated_at' AS c
  UNION ALL SELECT 'trusted_devices' AS t, 'user_id' AS c
  UNION ALL SELECT 'trusted_devices' AS t, 'name' AS c
  UNION ALL SELECT 'trusted_devices' AS t, 'key_hash' AS c
  UNION ALL SELECT 'trusted_devices' AS t, 'created_at' AS c
  UNION ALL SELECT 'trusted_devices' AS t, 'last_used_at' AS c
  UNION ALL SELECT 'trusted_devices' AS t, 'revoked_at' AS c
  UNION ALL SELECT 'phone_requests' AS t, 'purpose' AS c
  UNION ALL SELECT 'phone_requests' AS t, 'token_hash' AS c
  UNION ALL SELECT 'phone_requests' AS t, 'user_id' AS c
  UNION ALL SELECT 'phone_requests' AS t, 'status' AS c
  UNION ALL SELECT 'phone_requests' AS t, 'match_number' AS c
  UNION ALL SELECT 'phone_requests' AS t, 'requester_ip' AS c
  UNION ALL SELECT 'phone_requests' AS t, 'requester_agent' AS c
  UNION ALL SELECT 'phone_requests' AS t, 'device_id' AS c
  UNION ALL SELECT 'phone_requests' AS t, 'created_at' AS c
  UNION ALL SELECT 'phone_requests' AS t, 'expires_at' AS c
  UNION ALL SELECT 'phone_requests' AS t, 'decided_at' AS c
  UNION ALL SELECT 'agent_enrollment_keys' AS t, 'key_hash' AS c
  UNION ALL SELECT 'agent_enrollment_keys' AS t, 'label' AS c
  UNION ALL SELECT 'agent_enrollment_keys' AS t, 'max_uses' AS c
  UNION ALL SELECT 'agent_enrollment_keys' AS t, 'uses' AS c
  UNION ALL SELECT 'agent_enrollment_keys' AS t, 'expires_at' AS c
  UNION ALL SELECT 'agent_enrollment_keys' AS t, 'created_by' AS c
  UNION ALL SELECT 'agent_enrollment_keys' AS t, 'created_at' AS c
  UNION ALL SELECT 'agent_enrollment_keys' AS t, 'last_used_at' AS c
  UNION ALL SELECT 'agent_enrollment_keys' AS t, 'revoked_at' AS c
) e
LEFT JOIN information_schema.COLUMNS i ON i.TABLE_SCHEMA = DATABASE() AND i.TABLE_NAME = e.t AND i.COLUMN_NAME = e.c
WHERE i.COLUMN_NAME IS NULL;

SELECT 'MST database repair complete' AS result;
