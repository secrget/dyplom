-- Створення таблиці користувачів
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL
);

-- Створення таблиці конференцій
CREATE TABLE conferences (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Додавання початкових даних (опціонально)
INSERT INTO users (email, username, password_hash) VALUES ('test@example.com', 'testuser', 'hashed_password');
INSERT INTO conferences (title, description, user_id) VALUES ('Test Conference', 'This is a test conference.', 1);
