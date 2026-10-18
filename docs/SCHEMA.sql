-- MariaDB 10.6+, InnoDB, utf8mb4. All DATETIME values are UTC.
-- Registered user identities.
CREATE TABLE users (
    id BINARY(16) NOT NULL,
    username VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Temporary username reservations during registration.
CREATE TABLE username_reservations (
    username VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    user_id BINARY(16) NOT NULL,
    expires_at DATETIME NOT NULL,
    PRIMARY KEY (username),
    KEY idx_username_reservations_expires_at (expires_at),
    CONSTRAINT fk_username_reservations_user
        FOREIGN KEY (user_id) REFERENCES users (id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- OPAQUE records separated by credential kind and pending status.
CREATE TABLE opaque_records (
    user_id BINARY(16) NOT NULL,
    kind ENUM('password', 'recovery') NOT NULL,
    pending TINYINT(1) NOT NULL DEFAULT 0,
    record VARBINARY(1024) NOT NULL,
    ksf_version SMALLINT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, kind, pending),
    CONSTRAINT fk_opaque_records_user
        FOREIGN KEY (user_id) REFERENCES users (id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Versioned encrypted key blobs; the first version's prev_hash is 32 zero bytes.
CREATE TABLE key_blobs (
    user_id BINARY(16) NOT NULL,
    kind ENUM('kek', 'mek', 'identity', 'recovery') NOT NULL,
    version BIGINT UNSIGNED NOT NULL,
    prev_hash BINARY(32) NOT NULL,
    blob VARBINARY(4096) NOT NULL,
    pending TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, kind, version),
    CONSTRAINT fk_key_blobs_user
        FOREIGN KEY (user_id) REFERENCES users (id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Versioned public keys used for encapsulation and signing.
CREATE TABLE public_keys (
    user_id BINARY(16) NOT NULL,
    kind ENUM('mlkem', 'sign') NOT NULL,
    version INT UNSIGNED NOT NULL,
    public_key VARBINARY(2048) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, kind, version),
    CONSTRAINT fk_public_keys_user
        FOREIGN KEY (user_id) REFERENCES users (id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Temporary login states; usernames may refer to users not yet registered.
CREATE TABLE login_states (
    id_hash BINARY(32) NOT NULL,
    username VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    kind ENUM('password', 'recovery') NOT NULL,
    state VARBINARY(1024) NOT NULL,
    expires_at DATETIME NOT NULL,
    PRIMARY KEY (id_hash),
    KEY idx_login_states_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Authenticated sessions with hashed lookup identifiers.
CREATE TABLE sessions (
    session_id_hash BINARY(32) NOT NULL,
    user_id BINARY(16) NOT NULL,
    session_key VARBINARY(64) NOT NULL,
    last_counter BIGINT UNSIGNED NOT NULL DEFAULT 0,
    expires_at DATETIME NOT NULL,
    PRIMARY KEY (session_id_hash),
    KEY idx_sessions_expires_at (expires_at),
    CONSTRAINT fk_sessions_user
        FOREIGN KEY (user_id) REFERENCES users (id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;