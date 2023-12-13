CREATE TABLE IF NOT EXISTS `basic_auth` (
    `id`          INTEGER PRIMARY KEY AUTOINCREMENT,
    `username`    TEXT    NOT NULL,
    `password`    TEXT    NOT NULL,
    `client_name` TEXT    NOT NULL,
    `client_id`   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS `certificates` (
    `id`               INTEGER PRIMARY KEY AUTOINCREMENT,
    `order`            INTEGER NOT NULL,
    `certificate_data` BLOB
);

CREATE TABLE IF NOT EXISTS `config` (
    `id`            INTEGER PRIMARY KEY AUTOINCREMENT,
    `access_token`  TEXT,
    `refresh_token` TEXT,
    `credential_id` TEXT,
    `cert_status`   TEXT,
    `cert_algo`     TEXT,
    `cert_len`      TEXT
);

CREATE TABLE IF NOT EXISTS `signature` (
    `id`                INTEGER PRIMARY KEY AUTOINCREMENT,
    `contact_info`      TEXT,
    `location_info`     TEXT,
    `reason`            TEXT,
    `time_stamp_server` TEXT,
    `enable_ltv`        INTEGER,
    `signature_x`       REAL,
    `signature_y`       REAL,
    `signature_width`   REAL,
    `signature_height`  REAL,
    `signature_image`   BLOB
);

CREATE TABLE IF NOT EXISTS `db_version` (
    `id`         INTEGER PRIMARY KEY,
    `created_at` TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
