-- MOVE MST TO ITS OWN DATABASE "mst_monitoring".
-- Use it when another project uses the same database name "mst_database" (for example its users table replaced MST's:
-- "Unknown column 'username'" or "Field 'full_name' doesn't have a default value").
-- It creates the database mst_monitoring and COPIES the MST data out of mst_database (computers, detected files, scans,
-- threats, quarantine, Activity Logs, enrollment keys, settings). It only READS mst_database: the other project's
-- tables and data stay exactly as they are. Safe to run again (a table that already has data is not copied twice).
-- Not copied: accounts that are not MST accounts, paired phones (pair again in Settings).
-- MySQL Workbench: File > Open SQL Script > this file > Execute (the lightning icon WITHOUT the cursor).
-- Afterwards: set DB_DATABASE=mst_monitoring in .env, restart start-server.bat and run
--   php backend/tools/set-password.php admin        (answer y to create the account if it is missing)
--   php backend/tools/set-password.php superadmin
-- (Generated from database/schema.sql.)
CREATE DATABASE IF NOT EXISTS mst_monitoring CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE mst_monitoring;
SET FOREIGN_KEY_CHECKS = 0;
SET SQL_SAFE_UPDATES = 0;

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

DROP PROCEDURE IF EXISTS mst_add_foreign_key;
DROP PROCEDURE IF EXISTS mst_copy;
DROP PROCEDURE IF EXISTS mst_unlink_missing_user;
DELIMITER //
CREATE PROCEDURE mst_add_foreign_key(IN table_name_in VARCHAR(64), IN constraint_name_in VARCHAR(64), IN definition_in TEXT)
BEGIN
  DECLARE CONTINUE HANDLER FOR SQLEXCEPTION SELECT CONCAT('Could not add link ', constraint_name_in) AS warning;
  IF NOT EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = 'mst_monitoring' AND TABLE_NAME = table_name_in AND CONSTRAINT_NAME = constraint_name_in) THEN
    SET @mst_sql = CONCAT('ALTER TABLE mst_monitoring.`', table_name_in, '` ADD CONSTRAINT `', constraint_name_in, '` ', definition_in);
    PREPARE mst_statement FROM @mst_sql; EXECUTE mst_statement; DEALLOCATE PREPARE mst_statement;
  END IF;
END //
CREATE PROCEDURE mst_copy(IN table_name_in VARCHAR(64), IN mst_column_in VARCHAR(64), IN condition_in TEXT)
BEGIN
  -- Copies the rows of mst_database.<table> that are MST rows (their MST column is filled), using the columns both
  -- tables have. Skipped when mst_database has no such table or column, or when mst_monitoring.<table> has data.
  DECLARE CONTINUE HANDLER FOR SQLEXCEPTION SELECT CONCAT('Could not copy ', table_name_in, ' (skipped)') AS warning;
  IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'mst_database' AND TABLE_NAME = table_name_in AND COLUMN_NAME = mst_column_in) THEN
    SET @mst_sql = CONCAT('SELECT COUNT(*) INTO @mst_rows FROM mst_monitoring.`', table_name_in, '`');
    PREPARE mst_statement FROM @mst_sql; EXECUTE mst_statement; DEALLOCATE PREPARE mst_statement;
    IF @mst_rows = 0 THEN
      SELECT GROUP_CONCAT(CONCAT('`', t.COLUMN_NAME, '`') ORDER BY t.ORDINAL_POSITION) INTO @mst_columns
        FROM information_schema.COLUMNS t JOIN information_schema.COLUMNS s
          ON s.TABLE_SCHEMA = 'mst_database' AND s.TABLE_NAME = t.TABLE_NAME AND s.COLUMN_NAME = t.COLUMN_NAME
        WHERE t.TABLE_SCHEMA = 'mst_monitoring' AND t.TABLE_NAME = table_name_in;
      SET @mst_sql = CONCAT('INSERT IGNORE INTO mst_monitoring.`', table_name_in, '` (', @mst_columns, ') SELECT ', @mst_columns,
        ' FROM mst_database.`', table_name_in, '` WHERE `', mst_column_in, '` IS NOT NULL AND `', mst_column_in, '` <> \'\'',
        IF(condition_in = '', '', CONCAT(' AND ', condition_in)));
      PREPARE mst_statement FROM @mst_sql; EXECUTE mst_statement; SET @mst_copied = ROW_COUNT(); DEALLOCATE PREPARE mst_statement;
      SELECT CONCAT(table_name_in, ': ', @mst_copied, ' row(s) copied') AS copied;
    END IF;
  END IF;
END //
CREATE PROCEDURE mst_unlink_missing_user(IN table_name_in VARCHAR(64), IN column_in VARCHAR(64))
BEGIN
  -- A row that points to an account that was not copied keeps the row, without the account.
  SET @mst_sql = CONCAT('UPDATE mst_monitoring.`', table_name_in, '` t LEFT JOIN mst_monitoring.users u ON u.id = t.`', column_in,
    '` SET t.`', column_in, '` = NULL WHERE t.`', column_in, '` IS NOT NULL AND u.id IS NULL');
  PREPARE mst_statement FROM @mst_sql; EXECUTE mst_statement; DEALLOCATE PREPARE mst_statement;
END //
DELIMITER ;

CALL mst_add_foreign_key('scans', 'fk_scan_file_event', 'FOREIGN KEY (file_event_id) REFERENCES file_events(id) ON DELETE SET NULL');
CALL mst_add_foreign_key('file_events', 'fk_file_event_scan', 'FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL');
CALL mst_add_foreign_key('threats', 'fk_threat_scan', 'FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL');

-- Copy the MST data out of mst_database (read only there)
CALL mst_copy('users', 'username', 'BINARY role IN (''Super Admin'',''Admin'',''Tenant'')');
CALL mst_copy('computers', 'device_id', '');
CALL mst_copy('threats', 'threat_name', '');
CALL mst_copy('scans', 'scan_type', '');
CALL mst_copy('activity_logs', 'action', 'action REGEXP BINARY ''^[A-Z][A-Z_]*$''');
CALL mst_copy('permissions', 'module', 'BINARY role IN (''Super Admin'',''Admin'')');
CALL mst_copy('settings', 'setting_key', '');
CALL mst_copy('file_events', 'event_uid', '');
CALL mst_copy('hash_blocklist', 'sha256', '');
CALL mst_copy('hash_reputation', 'sha256', '');
CALL mst_copy('quarantine_items', 'original_path', '');
CALL mst_copy('agent_enrollment_keys', 'key_hash', '');
CALL mst_unlink_missing_user('scans', 'created_by');
CALL mst_unlink_missing_user('activity_logs', 'user_id');
CALL mst_unlink_missing_user('quarantine_items', 'requested_by');
CALL mst_unlink_missing_user('agent_enrollment_keys', 'created_by');

-- Default settings, permissions and the EICAR test hash that are still missing
INSERT IGNORE INTO permissions (role, module, allowed) VALUES
('Super Admin','dashboard',1),('Super Admin','computer_monitoring',1),('Super Admin','network',1),('Super Admin','threats',1),('Super Admin','file_scanner',0),('Super Admin','scan_history',1),('Super Admin','reports',1),('Super Admin','activity_logs',1),('Super Admin','user_management',1),('Super Admin','admin_management',1),('Super Admin','permissions',1),('Super Admin','settings',1),
('Admin','dashboard',1),('Admin','computer_monitoring',1),('Admin','network',1),('Admin','threats',1),('Admin','file_scanner',1),('Admin','scan_history',1),('Admin','reports',1),('Admin','activity_logs',1),('Admin','user_management',0),('Admin','admin_management',0),('Admin','permissions',0),('Admin','settings',1);
INSERT IGNORE INTO settings (category, setting_key, setting_value) VALUES ('system','systemName','Monitoring System Threat'),('system','monitoringStatus','1'),('system','refreshInterval','10 seconds'),('scanner','autoScan','1'),('scanner','uploadRetention','7 days');
INSERT IGNORE INTO hash_blocklist (sha256, name, severity, source) VALUES ('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'EICAR anti-virus test file', 'CRITICAL', 'EICAR');
INSERT IGNORE INTO settings (category, setting_key, setting_value) VALUES ('scanner', 'autoScan', '1'), ('scanner', 'uploadRetention', '7 days');

DROP PROCEDURE IF EXISTS mst_add_foreign_key;
DROP PROCEDURE IF EXISTS mst_copy;
DROP PROCEDURE IF EXISTS mst_unlink_missing_user;
SET FOREIGN_KEY_CHECKS = 1;
SET SQL_SAFE_UPDATES = 1;
SELECT (SELECT COUNT(*) FROM mst_monitoring.computers) AS computers, (SELECT COUNT(*) FROM mst_monitoring.file_events) AS detected_files,
       (SELECT COUNT(*) FROM mst_monitoring.users) AS accounts;
SELECT 'MST now has its own database mst_monitoring: set DB_DATABASE=mst_monitoring in .env' AS result;
