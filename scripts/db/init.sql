-- Clarity-AI Database Initialization Script
-- This script sets up the basic database structure for development

-- Create the main database if it doesn't exist
-- Note: This is mainly for Docker PostgreSQL initialization

-- Grant necessary permissions
GRANT ALL PRIVILEGES ON DATABASE clarity_ai TO clarity_user;

-- Create extensions if needed (PostgreSQL only)
-- CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
-- CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Basic setup is complete
-- The actual schema will be created by Alembic migrations