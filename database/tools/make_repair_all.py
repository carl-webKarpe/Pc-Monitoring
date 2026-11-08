# Regenerates database/migrations/repair_all.sql from database/schema.sql and seed.sql (run after a schema change):
#   python database/tools/make_repair_all.py . > database/migrations/repair_all.sql
import re, sys
root = sys.argv[1]
schema = open(f"{root}/database/schema.sql").read()
seed = open(f"{root}/database/seed.sql").read()

def split_top(body):
    parts, depth, cur, quote = [], 0, "", False
    for ch in body:
        if ch == "'": quote = not quote
        if not quote:
            if ch == "(": depth += 1
            elif ch == ")": depth -= 1
            elif ch == "," and depth == 0:
                parts.append(cur.strip()); cur = ""; continue
        cur += ch
    parts.append(cur.strip())
    return parts

tables, columns, enums, indexes, fks = [], [], [], [], []
for line in schema.splitlines():
    m = re.match(r"CREATE TABLE (\w+) \((.*)\);$", line)
    if m:
        name, body = m.groups()
        tables.append(line.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
        for item in split_top(body):
            word = item.split()[0]
            upper = word.upper()
            if upper in ("PRIMARY",):
                continue
            if upper == "CONSTRAINT":
                cm = re.match(r"CONSTRAINT (\w+) (FOREIGN KEY .*)", item)
                fks.append((name, cm.group(1), cm.group(2)))
            elif upper in ("INDEX", "KEY"):
                im = re.match(r"(?:INDEX|KEY) (\w+) (\(.*\))", item)
                indexes.append((name, im.group(1), im.group(2), False))
            elif upper == "UNIQUE":
                um = re.match(r"UNIQUE KEY (\w+) (\(.*\))", item)
                indexes.append((name, um.group(1), um.group(2), True))
            else:
                definition = item[len(word):].strip()
                if "PRIMARY KEY" in definition:
                    continue
                # A column added to an existing table cannot be UNIQUE (its existing rows would all be equal).
                columns.append((name, word, re.sub(r"\s+UNIQUE\b", "", definition)))
                em = re.match(r"(ENUM\(.*?\))", definition)
                if em:
                    enums.append((name, word, definition, em.group(1)))
    m = re.match(r"ALTER TABLE (\w+) ADD CONSTRAINT (\w+) (FOREIGN KEY .*);$", line)
    if m:
        fks.append(m.groups())

q = lambda s: "'" + s.replace("\\", "\\\\").replace("'", "''") + "'"
out = []
w = out.append
w("""-- REPAIR: brings an MST database of ANY older version up to date in one step (all phases 9-17).
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
""")
w("-- 1. Tables that do not exist yet")
out.extend(tables)
w("\n-- 2. Columns that are missing in older tables")
out.extend(f"CALL mst_add_column({q(t)}, {q(c)}, {q(d)});" for t, c, d in columns)
w("\n-- 3. New allowed values in list (ENUM) columns")
out.extend(f"CALL mst_allow_values({q(t)}, {q(c)}, {q(d)}, {q(e)});" for t, c, d, e in enums)
w("\n-- 4. Indexes (speed) and links between tables")
out.extend(f"CALL mst_add_index({q(t)}, {q(i)}, {q(('UNIQUE KEY ' if u else 'INDEX ') + i + ' ' + cols)});" for t, i, cols, u in indexes)
out.extend(f"CALL mst_add_foreign_key({q(t)}, {q(n)}, {q(d)});" for t, n, d in fks)
w("\n-- 5. Default settings and permissions that are missing (existing ones are kept as they are)")
for statement in re.findall(r"^INSERT INTO (?:settings|permissions|hash_blocklist) .*?;$", seed, re.M | re.S):
    w(statement.replace("INSERT INTO", "INSERT IGNORE INTO", 1))
w("INSERT IGNORE INTO settings (category, setting_key, setting_value) VALUES ('scanner', 'autoScan', '1'), ('scanner', 'uploadRetention', '7 days');")
w("""
DROP PROCEDURE IF EXISTS mst_add_column;
DROP PROCEDURE IF EXISTS mst_allow_values;
DROP PROCEDURE IF EXISTS mst_add_index;
DROP PROCEDURE IF EXISTS mst_add_foreign_key;
SET FOREIGN_KEY_CHECKS = 1;
SET SQL_SAFE_UPDATES = 1;

-- 6. Check: this list must be EMPTY.""")
union = "\n  UNION ALL ".join(f"SELECT {q(t)} AS t, {q(c)} AS c" for t, c, _ in columns)
w(f"SELECT CONCAT(e.t, '.', e.c) AS `Still missing` FROM (\n  {union}\n) e\nLEFT JOIN information_schema.COLUMNS i ON i.TABLE_SCHEMA = DATABASE() AND i.TABLE_NAME = e.t AND i.COLUMN_NAME = e.c\nWHERE i.COLUMN_NAME IS NULL;")
w("\nSELECT 'MST database repair complete' AS result;")
print("\n".join(out))
