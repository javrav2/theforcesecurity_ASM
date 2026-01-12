"""
Migration script to add acquisitions table for M&A tracking.

Run this script inside the backend container:
    docker exec asm_backend python scripts/migrate_add_acquisitions_table.py
"""

import sys
sys.path.insert(0, '/app')

from sqlalchemy import text
from app.db.database import SessionLocal, engine

def run_migration():
    """Add the acquisitions table."""
    
    # SQL to create the acquisitions table
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS acquisitions (
        id SERIAL PRIMARY KEY,
        organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        
        -- Target company info
        target_name VARCHAR(255) NOT NULL,
        target_domain VARCHAR(255),
        target_domains JSONB DEFAULT '[]',
        target_description TEXT,
        target_industry VARCHAR(255),
        target_country VARCHAR(100),
        target_city VARCHAR(100),
        target_founded_year INTEGER,
        target_employees INTEGER,
        
        -- Acquisition details
        acquisition_type VARCHAR(50) DEFAULT 'acquisition',
        status VARCHAR(50) DEFAULT 'completed',
        announced_date TIMESTAMP,
        closed_date TIMESTAMP,
        deal_value FLOAT,
        deal_currency VARCHAR(10) DEFAULT 'USD',
        
        -- Integration status
        is_integrated BOOLEAN DEFAULT FALSE,
        integration_notes TEXT,
        
        -- Domain tracking
        domains_discovered INTEGER DEFAULT 0,
        domains_in_scope INTEGER DEFAULT 0,
        
        -- External IDs
        tracxn_id VARCHAR(100) UNIQUE,
        crunchbase_id VARCHAR(100),
        linkedin_url VARCHAR(500),
        website_url VARCHAR(500),
        
        -- Source tracking
        source VARCHAR(50) DEFAULT 'manual',
        metadata_ JSONB DEFAULT '{}',
        
        -- Timestamps
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Create indexes
    CREATE INDEX IF NOT EXISTS idx_acquisitions_organization_id ON acquisitions(organization_id);
    CREATE INDEX IF NOT EXISTS idx_acquisitions_target_name ON acquisitions(target_name);
    CREATE INDEX IF NOT EXISTS idx_acquisitions_status ON acquisitions(status);
    """
    
    db = SessionLocal()
    try:
        # Check if table already exists
        result = db.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'acquisitions'
            );
        """))
        exists = result.scalar()
        
        if exists:
            print("✓ acquisitions table already exists")
        else:
            print("Creating acquisitions table...")
            db.execute(text(create_table_sql))
            db.commit()
            print("✓ Created acquisitions table successfully")
        
        # Verify table structure
        result = db.execute(text("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'acquisitions'
            ORDER BY ordinal_position;
        """))
        columns = result.fetchall()
        
        print(f"\nAcquisitions table has {len(columns)} columns:")
        for col in columns:
            print(f"  - {col[0]}: {col[1]}")
        
        print("\n✓ Migration complete!")
        
    except Exception as e:
        db.rollback()
        print(f"✗ Migration failed: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    run_migration()
