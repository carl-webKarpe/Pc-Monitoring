-- Phase 14: Super Admin sign-in approved by scanning a QR code with a paired phone.
-- Run ONCE on an existing mst_database, AFTER phase13 (MySQL Workbench: open this file, then Execute).
-- Safe to run again: it only creates tables that do not exist yet.
USE mst_database;

-- Phones paired with an account. Only a SHA-256 hash of each phone's secret key is stored.
CREATE TABLE IF NOT EXISTS trusted_devices (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  name VARCHAR(80) NOT NULL,
  key_hash CHAR(64) NOT NULL UNIQUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at DATETIME NULL,
  revoked_at DATETIME NULL,
  CONSTRAINT fk_trusted_device_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_trusted_devices_user (user_id, revoked_at)
);

-- One-time QR requests: "login" (approve a sign-in) and "pair" (add a phone). Only token hashes are stored.
CREATE TABLE IF NOT EXISTS phone_requests (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  purpose ENUM('login','pair') NOT NULL,
  token_hash CHAR(64) NOT NULL UNIQUE,
  user_id INT UNSIGNED NOT NULL,
  status ENUM('pending','approved','denied','used','expired') NOT NULL DEFAULT 'pending',
  match_number TINYINT UNSIGNED NULL,
  requester_ip VARCHAR(45) NULL,
  requester_agent VARCHAR(160) NULL,
  device_id INT UNSIGNED NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  decided_at DATETIME NULL,
  CONSTRAINT fk_phone_request_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_phone_request_device FOREIGN KEY (device_id) REFERENCES trusted_devices(id) ON DELETE SET NULL,
  INDEX idx_phone_requests_user (user_id, status)
);
