-- Migration: Add port verification fields for nmap deep inspection
-- Run this on the database to add verification tracking columns

-- Add verification columns to port_services table
ALTER TABLE port_services 
ADD COLUMN IF NOT EXISTS verified BOOLEAN DEFAULT FALSE;

ALTER TABLE port_services 
ADD COLUMN IF NOT EXISTS verified_at TIMESTAMP;

ALTER TABLE port_services 
ADD COLUMN IF NOT EXISTS verified_state VARCHAR(50);

ALTER TABLE port_services 
ADD COLUMN IF NOT EXISTS verification_scanner VARCHAR(50);

-- Add index for faster queries on verified ports
CREATE INDEX IF NOT EXISTS idx_port_services_verified 
ON port_services (verified);

-- Add index for verified_state to filter by nmap result
CREATE INDEX IF NOT EXISTS idx_port_services_verified_state 
ON port_services (verified_state);

-- Log completion
DO $$
BEGIN
    RAISE NOTICE 'Port verification fields added successfully!';
END $$;
