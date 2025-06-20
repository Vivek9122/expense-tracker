#!/usr/bin/env python3
"""
Simple script to run database migration on Render
This will create the necessary tables for groups functionality
"""

import os
import sys

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the migration
try:
    from migrate_groups import run_migration
    print("🔄 Starting database migration...")
    run_migration()
    print("✅ Migration completed successfully!")
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Running migration directly...")
    
    # Run migration directly if import fails
    from sqlalchemy import create_engine, text, inspect
    
    DATABASE_URL = os.environ.get('DATABASE_URL')
    if not DATABASE_URL:
        print("ERROR: DATABASE_URL environment variable not set")
        sys.exit(1)
    
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    
    engine = create_engine(DATABASE_URL)
    
    with engine.connect() as conn:
        trans = conn.begin()
        try:
            # Create Group table
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS "group" (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    description VARCHAR(500),
                    created_by INTEGER NOT NULL REFERENCES "user"(id),
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
            
            # Create GroupMember table  
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS group_member (
                    id SERIAL PRIMARY KEY,
                    group_id INTEGER NOT NULL REFERENCES "group"(id),
                    user_id INTEGER NOT NULL REFERENCES "user"(id),
                    joined_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    is_admin BOOLEAN DEFAULT FALSE,
                    UNIQUE(group_id, user_id)
                )
            """))
            
            # Check if group_id column exists in expense table
            inspector = inspect(engine)
            columns = [col['name'] for col in inspector.get_columns('expense')]
            
            if 'group_id' not in columns:
                # Add group_id column
                conn.execute(text("ALTER TABLE expense ADD COLUMN group_id INTEGER"))
                
                # Create a default group if there are existing expenses
                result = conn.execute(text("SELECT COUNT(*) as count FROM expense")).fetchone()
                if result and result.count > 0:
                    # Get first user
                    first_user = conn.execute(text("SELECT id FROM \"user\" ORDER BY id LIMIT 1")).fetchone()
                    if first_user:
                        # Create default group
                        conn.execute(text("""
                            INSERT INTO "group" (name, description, created_by)
                            VALUES ('Default Group', 'Auto-created for existing expenses', :user_id)
                        """), {"user_id": first_user.id})
                        
                        # Get default group ID
                        default_group = conn.execute(text("""
                            SELECT id FROM "group" WHERE name = 'Default Group' AND created_by = :user_id
                        """), {"user_id": first_user.id}).fetchone()
                        
                        if default_group:
                            # Add all users to default group
                            conn.execute(text("""
                                INSERT INTO group_member (group_id, user_id, is_admin)
                                SELECT :group_id, id, TRUE FROM "user"
                            """), {"group_id": default_group.id})
                            
                            # Update existing expenses
                            conn.execute(text("""
                                UPDATE expense SET group_id = :group_id WHERE group_id IS NULL
                            """), {"group_id": default_group.id})
                
                # Make group_id NOT NULL
                conn.execute(text("ALTER TABLE expense ALTER COLUMN group_id SET NOT NULL"))
                conn.execute(text("""
                    ALTER TABLE expense ADD CONSTRAINT fk_expense_group 
                    FOREIGN KEY (group_id) REFERENCES "group"(id)
                """))
            
            # Check if paid_by column exists
            if 'paid_by' not in columns:
                conn.execute(text("ALTER TABLE expense ADD COLUMN paid_by INTEGER REFERENCES \"user\"(id)"))
                conn.execute(text("UPDATE expense SET paid_by = user_id WHERE paid_by IS NULL"))
            
            trans.commit()
            print("✅ Migration completed successfully!")
            
        except Exception as e:
            trans.rollback()
            print(f"❌ Migration failed: {e}")
            raise

except Exception as e:
    print(f"❌ Migration error: {e}")
    sys.exit(1) 