# Regenerates database/migrations/move_to_mst_monitoring.sql from database/schema.sql and seed.sql:
#   python database/tools/make_move_database.py . > database/migrations/move_to_mst_monitoring.sql
import re, sys

root = sys.argv[1]
schema = open(f"{root}/database/schema.sql").read()
seed = open(f"{root}/database/seed.sql").read()
q = lambda s: "'" + s.replace("\\", "\\\\").replace("'", "''") + "'"

# Table -> (MST-only column that must be filled in a real MST row, extra condition). Tables not listed are not copied
# (phone pairings and sign-in requests are made again).
COPY = {
    "users": ("username", "BINARY role IN ('Super Admin','Admin','Tenant')"),
    "computers": ("device_id", ""),
    "threats": ("threat_name", ""),
    "scans": ("scan_type", ""),
    "activity_logs": ("action", "action REGEXP BINARY '^[A-Z][A-Z_]*$'"),
    "permissions": ("module", "BINARY role IN ('Super Admin','Admin')"),
    "settings": ("setting_key", ""),
    "file_events": ("event_uid", ""),
    "hash_blocklist": ("sha256", ""),
    "hash_reputation": ("sha256", ""),
    "quarantine_items": ("original_path", ""),
    "agent_enrollment_keys": ("key_hash", ""),
}
USER_LINKS = [("scans", "created_by"), ("activity_logs", "user_id"), ("quarantine_items", "requested_by"), ("agent_enrollment_keys", "created_by")]

tables = [line.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1) for line in schema.splitlines() if line.startswith("CREATE TABLE ")]
foreign_keys = re.findall(r"^ALTER TABLE (\w+) ADD CONSTRAINT (\w+) (FOREIGN KEY .*);$", schema, re.M)
order = [re.match(r"CREATE TABLE IF NOT EXISTS (\w+)", t).group(1) for t in tables]

out = ["""-- MOVE MST TO ITS OWN DATABASE "mst_monitoring".
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
"""]
out += tables
out.append("""
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
        ' FROM mst_database.`', table_name_in, '` WHERE `', mst_column_in, '` IS NOT NULL AND `', mst_column_in, '` <> \\'\\'',
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
""")
out += [f"CALL mst_add_foreign_key({q(t)}, {q(n)}, {q(d)});" for t, n, d in foreign_keys]
out.append("\n-- Copy the MST data out of mst_database (read only there)")
out += [f"CALL mst_copy({q(t)}, {q(COPY[t][0])}, {q(COPY[t][1])});" for t in order if t in COPY]
out += [f"CALL mst_unlink_missing_user({q(t)}, {q(c)});" for t, c in USER_LINKS]
out.append("\n-- Default settings, permissions and the EICAR test hash that are still missing")
for statement in re.findall(r"^INSERT INTO (?:settings|permissions|hash_blocklist) .*?;$", seed, re.M | re.S):
    out.append(statement.replace("INSERT INTO", "INSERT IGNORE INTO", 1))
out.append("INSERT IGNORE INTO settings (category, setting_key, setting_value) VALUES ('scanner', 'autoScan', '1'), ('scanner', 'uploadRetention', '7 days');")
out.append("""
DROP PROCEDURE IF EXISTS mst_add_foreign_key;
DROP PROCEDURE IF EXISTS mst_copy;
DROP PROCEDURE IF EXISTS mst_unlink_missing_user;
SET FOREIGN_KEY_CHECKS = 1;
SET SQL_SAFE_UPDATES = 1;
SELECT (SELECT COUNT(*) FROM mst_monitoring.computers) AS computers, (SELECT COUNT(*) FROM mst_monitoring.file_events) AS detected_files,
       (SELECT COUNT(*) FROM mst_monitoring.users) AS accounts;
SELECT 'MST now has its own database mst_monitoring: set DB_DATABASE=mst_monitoring in .env' AS result;""")
print("\n".join(out))
