# aes-python

AES-128 implementation in pure Python. 
Currently only supports ECB mode of operation.


Database Setup:

CREATE DATABASE project;
use project;

CREATE TABLE Users (
	id INT NOT NULL AUTO_INCREMENT,
    EMAIL VARCHAR(40) NOT NULL,
    password VARCHAR(60) NOT NULL,
    salt VARCHAR(60) NOT NULL,
    first_name VARCHAR(20) NOT NULL,
    last_name VARCHAR(20) NOT NULL,
    PRIMARY KEY(id)
);

Add user hierarchy

ALTER TABLE Users
ADD COLUMN admin TINYINT(1) NOT NULL;

TINYINT in MySQL uses 0 as FALSE, 1 as TRUE 
