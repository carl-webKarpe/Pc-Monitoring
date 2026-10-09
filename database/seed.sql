USE mst_database;

INSERT INTO users (id, first_name, last_name, email, username, password_hash, role, status) VALUES
(1, 'System', 'Administrator', 'superadmin@mst.local', 'superadmin', '$2y$10$xL.8ZVTyfavI1NqmFNG/L.6RUiUvwk6b4ZO8NjOgKTUWJ/X5R45gi', 'Super Admin', 'Active'),
(2, 'System', 'Administrator', 'admin@mst.local', 'admin', '$2y$10$C/zatTtcoEkyHfHa7eScNeGBoHJCzOq3Fg7L2upQ8PdseDKWAvAvS', 'Admin', 'Active'),
(3, 'Juan', 'Dela Cruz', 'juan@example.com', 'tenant01', '$2y$12$pxc/eFT/wIzWv4a0HSRE3elaG0qoZilG7yu6qbIbE.Y0CzTGVSXVO', 'Tenant', 'Active');

INSERT INTO computers (id, device_id, hostname, ip_address, operating_system, status, threat_level, cpu_usage, memory_usage, last_seen, agent_status) VALUES
(1, 'MST-PC-001', 'LAB-PC-01', '192.168.1.20', 'Windows', 'online', 'safe', 24, 42, '5 sec ago', 'connected'),
(2, 'MST-PC-002', 'LAB-PC-02', '192.168.1.21', 'Windows', 'warning', 'warning', 58, 61, '10 sec ago', 'connected'),
(3, 'MST-PC-003', 'LAB-PC-03', '192.168.1.22', 'Windows', 'offline', 'unknown', NULL, NULL, '12 min ago', 'disconnected'),
(4, 'MST-PC-004', 'LAB-PC-04', '192.168.1.23', 'Windows', 'threat', 'high', 78, 83, '3 sec ago', 'connected');

INSERT INTO threats (id, computer_id, threat_name, description, severity, status, source, detected_at) VALUES
(1, 4, 'Suspicious File', 'Potentially harmful file detected', 'HIGH', 'Investigating', 'File Scanner', '2026-09-15 22:42:00'),
(2, 2, 'Suspicious Script', 'Potentially unwanted script detected', 'MEDIUM', 'Detected', 'Agent', '2026-09-15 22:35:00');

-- No example scans: every scan record comes from a real scan (agent, automatic or File Scanner upload).

INSERT INTO permissions (role, module, allowed) VALUES
('Super Admin','dashboard',1),('Super Admin','computer_monitoring',1),('Super Admin','network',1),('Super Admin','threats',1),('Super Admin','file_scanner',0),('Super Admin','scan_history',1),('Super Admin','reports',1),('Super Admin','activity_logs',1),('Super Admin','user_management',1),('Super Admin','admin_management',1),('Super Admin','permissions',1),('Super Admin','settings',1),
('Admin','dashboard',1),('Admin','computer_monitoring',1),('Admin','network',1),('Admin','threats',1),('Admin','file_scanner',1),('Admin','scan_history',1),('Admin','reports',1),('Admin','activity_logs',1),('Admin','user_management',0),('Admin','admin_management',0),('Admin','permissions',0),('Admin','settings',1);

INSERT INTO settings (category, setting_key, setting_value) VALUES ('system','systemName','Monitoring System Threat'),('system','monitoringStatus','1'),('system','refreshInterval','10 seconds'),('scanner','autoScan','1'),('scanner','uploadRetention','7 days');

-- Harmless EICAR anti-virus test file hash, used to demonstrate a THREAT scan result safely.
INSERT INTO hash_blocklist (sha256, name, severity, source) VALUES ('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'EICAR anti-virus test file', 'CRITICAL', 'EICAR');
