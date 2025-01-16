-- cipta database users --  
CREATE DATABASE IF NOT EXISTS nodejs_jwt;

-- guna database users --
USE nodejs_jwt;

-- cipta table users --
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
);
