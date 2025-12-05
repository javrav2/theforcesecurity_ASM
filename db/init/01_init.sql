-- The Force Security ASM - Database Initialization Script
-- This script runs automatically when the PostgreSQL container starts for the first time

-- Enable UUID extension (useful for future enhancements)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Grant necessary permissions to the application user
GRANT ALL PRIVILEGES ON DATABASE asm_db TO asm_user;

-- Log initialization
DO $$
BEGIN
    RAISE NOTICE 'The Force Security ASM database initialized successfully!';
END $$;



