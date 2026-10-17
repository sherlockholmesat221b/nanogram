
-- Registered user identities.
CREATE TABLE users (
    id BINARY(16) NOT NULL,
    username VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Temporary username reservations during registration.
CREATE TABLE username_reservations (
    username VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    PRIMARY KEY (username),
    KEY idx_username_reservations_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- OPAQUE registration records and their key-stretching version.
CREATE TABLE opaque_records (
    user_id BINARY(16) NOT NULL,
    record VARBINARY(1024) NOT NULL,
    ksf_version SMALLINT NOT NULL,
    PRIMARY KEY (user_id),
    CONSTRAINT fk_opaque_records_user
        FOREIGN KEY (user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Versioned encrypted key blobs.
CREATE TABLE key_blobs (
    user_id BINARY(16) NOT NULL,
    kind ENUM('kek', 'mek', 'identity', 'recovery') NOT NULL,
    version INT NOT NULL,
    prev_hash BINARY(32) NOT NULL,
    blob VARBINARY(4096) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, kind, version),
    CONSTRAINT fk_key_blobs_user
        FOREIGN KEY (user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Authenticated sessions with hashed lookup identifiers.
CREATE TABLE sessions (
    session_id_hash BINARY(32) NOT NULL,
    user_id BINARY(16) NOT NULL,
    session_key VARBINARY(64) NOT NULL,
    last_counter BIGINT UNSIGNED NOT NULL DEFAULT 0,
    expires_at TIMESTAMP NOT NULL,
    PRIMARY KEY (session_id_hash),
    KEY idx_sessions_expires_at (expires_at),
    CONSTRAINT fk_sessions_user
        FOREIGN KEY (user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
