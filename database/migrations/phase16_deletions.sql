-- Phase 16: how a file was deleted (Recycle Bin / permanently / removed from the Recycle Bin) and folder deletes.
-- Run ONCE after phase15_rename.sql (MySQL Workbench: open this file, then Execute). Safe to run again.
-- Until it has run, updated agents keep their events in their queue and send them afterwards (nothing is lost).
USE mst_database;

SET @mst_missing = (SELECT COUNT(*) = 0 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'file_events' AND COLUMN_NAME = 'delete_mode');
SET @mst_sql = IF(@mst_missing, "ALTER TABLE file_events ADD COLUMN delete_mode ENUM('recycle_bin','permanent','recycle_bin_removed') NULL AFTER event_type", 'SELECT 1');
PREPARE mst_statement FROM @mst_sql; EXECUTE mst_statement; DEALLOCATE PREPARE mst_statement;

SET @mst_missing = (SELECT COUNT(*) = 0 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'file_events' AND COLUMN_NAME = 'is_folder');
SET @mst_sql = IF(@mst_missing, 'ALTER TABLE file_events ADD COLUMN is_folder TINYINT(1) NOT NULL DEFAULT 0 AFTER delete_mode', 'SELECT 1');
PREPARE mst_statement FROM @mst_sql; EXECUTE mst_statement; DEALLOCATE PREPARE mst_statement;

SELECT 'Phase 16 database update complete' AS result;
