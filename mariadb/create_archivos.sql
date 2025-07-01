CREATE TABLE IF NOT EXISTS archivos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    path VARCHAR(500) NOT NULL,
    size INT,
    upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_modification DATETIME,
    user_that_uploaded VARCHAR(100),
    encryption BOOLEAN DEFAULT FALSE
);
