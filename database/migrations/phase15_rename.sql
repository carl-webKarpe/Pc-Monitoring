-- Phase 15 (rename): your own name for each computer (Computers > Rename). The agent keeps reporting the real Windows
-- computer name in "hostname"; "display_name" is what the Computers page shows when it is set.
-- Run ONCE after phase15_enrollment.sql (MySQL Workbench: open this file, then Execute). Safe to run again.
USE mst_database;

SET @mst_has_column = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'computers' AND COLUMN_NAME = 'display_name');
SET @mst_sql = IF(@mst_has_column = 0, 'ALTER TABLE computers ADD COLUMN display_name VARCHAR(120) NULL AFTER hostname', 'SELECT 1');
PREPARE mst_statement FROM @mst_sql; EXECUTE mst_statement; DEALLOCATE PREPARE mst_statement;

SELECT 'Phase 15 rename update complete' AS result;
