CREATE TABLE roles (
                       id BIGINT AUTO_INCREMENT PRIMARY KEY,
                       name VARCHAR(100),
                       tenant_id VARCHAR(100)
);

CREATE TABLE permissions (
                             id BIGINT AUTO_INCREMENT PRIMARY KEY,
                             name VARCHAR(200),
                             tenant_id VARCHAR(100)
);

CREATE TABLE users (
                       id BIGINT AUTO_INCREMENT PRIMARY KEY,
                       email VARCHAR(200) NOT NULL UNIQUE,
                       password_hash VARCHAR(255) NOT NULL,
                       enabled BOOLEAN DEFAULT FALSE,
                       email_verified BOOLEAN DEFAULT FALSE,
                       tenant_id VARCHAR(100),
                       created_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP(3)
);

CREATE TABLE user_roles (
                            user_id BIGINT NOT NULL,
                            role_id BIGINT NOT NULL,
                            PRIMARY KEY (user_id, role_id)
);

CREATE TABLE refresh_tokens (
                                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                                token_hash VARCHAR(512) NOT NULL,
                                user_id BIGINT NOT NULL,
                                device VARCHAR(255),
                                ip VARCHAR(100),
                                created_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP(3),
                                expires_at TIMESTAMP(3),
                                revoked BOOLEAN DEFAULT FALSE
);

CREATE TABLE processed_events (
                                  id BIGINT AUTO_INCREMENT PRIMARY KEY,
                                  event_id VARCHAR(255) NOT NULL UNIQUE,
                                  topic VARCHAR(255),
                                  processed_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP(3)
);
