-- =========================================
-- IDS Honeypot schema for MySQL 8+
-- =========================================

-- =========================================
-- users
-- =========================================
CREATE TABLE IF NOT EXISTS users (
  user_id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  email VARCHAR(100) NOT NULL UNIQUE,
  role ENUM('admin','analyst','user') NOT NULL DEFAULT 'user',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================
-- attack_types
-- =========================================
CREATE TABLE IF NOT EXISTS attack_types (
  attack_id INT AUTO_INCREMENT PRIMARY KEY,
  attack_name VARCHAR(100) NOT NULL UNIQUE,
  category VARCHAR(50) NOT NULL DEFAULT 'General',
  description TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================
-- events
-- =========================================
CREATE TABLE IF NOT EXISTS events (
  event_id INT AUTO_INCREMENT PRIMARY KEY,
  timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  source_ip VARCHAR(45) NOT NULL,
  destination_ip VARCHAR(45) NOT NULL,
  attack_id INT NOT NULL,
  severity ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
  description TEXT,
  detected_by ENUM('AI','Signature','Manual') NOT NULL DEFAULT 'AI',
  status ENUM('new','investigating','resolved') NOT NULL DEFAULT 'new',
  CONSTRAINT fk_events_attack FOREIGN KEY (attack_id)
    REFERENCES attack_types(attack_id)
    ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================
-- honeypot_data
-- =========================================
CREATE TABLE IF NOT EXISTS honeypot_data (
  honeypot_id INT AUTO_INCREMENT PRIMARY KEY,
  timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  attacker_ip VARCHAR(45) NOT NULL,
  attack_id INT NOT NULL,
  payload TEXT,
  captured_file VARCHAR(255),
  severity ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
  CONSTRAINT fk_honeypot_attack FOREIGN KEY (attack_id)
    REFERENCES attack_types(attack_id)
    ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================
-- ai_analysis
-- =========================================
CREATE TABLE IF NOT EXISTS ai_analysis (
  analysis_id INT AUTO_INCREMENT PRIMARY KEY,
  event_id INT NOT NULL,
  model_used VARCHAR(100) NOT NULL,
  prediction ENUM('Malicious','Benign','Suspicious') NOT NULL,
  confidence DECIMAL(5,2) NOT NULL,
  analysis_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_analysis_event FOREIGN KEY (event_id)
    REFERENCES events(event_id)
    ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================
-- alerts
-- =========================================
CREATE TABLE IF NOT EXISTS alerts (
  alert_id INT AUTO_INCREMENT PRIMARY KEY,
  event_id INT NOT NULL,
  alert_message TEXT NOT NULL,
  alert_level ENUM('info','warning','critical') NOT NULL DEFAULT 'info',
  sent_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  is_sent BOOLEAN NOT NULL DEFAULT FALSE,
  CONSTRAINT fk_alerts_event FOREIGN KEY (event_id)
    REFERENCES events(event_id)
    ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================
-- incident_reports
-- =========================================
CREATE TABLE IF NOT EXISTS incident_reports (
  report_id INT AUTO_INCREMENT PRIMARY KEY,
  event_id INT NOT NULL,
  report_details TEXT NOT NULL,
  reported_by INT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_reports_event FOREIGN KEY (event_id)
    REFERENCES events(event_id)
    ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT fk_reports_user FOREIGN KEY (reported_by)
    REFERENCES users(user_id)
    ON UPDATE CASCADE ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================
-- ip_blocked (đã hợp nhất & tự động gỡ chặn)
-- =========================================
CREATE TABLE IF NOT EXISTS ip_blocked (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    reason VARCHAR(255),
    blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME GENERATED ALWAYS AS (DATE_ADD(blocked_at, INTERVAL 15 MINUTE)) STORED,
    status ENUM('blocked','unblocked') NOT NULL DEFAULT 'blocked'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX idx_ip_blocked_status ON ip_blocked (status, expires_at);

-- =========================================
-- Thủ tục: Block IP (gọi khi phát hiện tấn công)
-- =========================================
DELIMITER //

CREATE PROCEDURE block_attacker_ip(
    IN p_ip VARCHAR(45),
    IN p_reason VARCHAR(255)
)
BEGIN
    INSERT INTO ip_blocked (ip_address, reason, blocked_at, status)
    VALUES (p_ip, p_reason, NOW(), 'blocked')
    ON DUPLICATE KEY UPDATE
        reason = VALUES(reason),
        blocked_at = NOW(),
        status = 'blocked';
END;
//

DELIMITER ;

-- =========================================
-- Sự kiện tự động kiểm tra và gỡ chặn IP hết hạn (mỗi phút)
-- =========================================
SET GLOBAL event_scheduler = ON;

DELIMITER //

CREATE EVENT IF NOT EXISTS auto_unblock_expired_ips
ON SCHEDULE EVERY 1 MINUTE
DO
BEGIN
    UPDATE ip_blocked
    SET status = 'unblocked'
    WHERE status = 'blocked'
      AND expires_at <= NOW();
END;
//

DELIMITER ;

-- =========================================
-- ✅ Hướng dẫn sử dụng
-- =========================================
-- 1️⃣ Gọi thủ tục để block IP (15 phút tự động):
-- CALL block_attacker_ip('192.168.1.100', 'Brute-force attack detected');
--
-- 2️⃣ MySQL Event tự động chạy mỗi phút và gỡ IP hết hạn.
--
-- 3️⃣ Kiểm tra IP bị chặn hiện tại:
-- SELECT * FROM ip_blocked WHERE status='blocked';
