#!/usr/bin/env python3
"""
Migration script to add Groups functionality to existing database
This script safely adds the new tables: Group, GroupMember
And updates the Expense table to include group_id
"""

import os
import sys
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.exc import OperationalError

# Get database URL from environment
DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    print("ERROR: DATABASE_URL environment variable not set")
    sys.exit(1)

# Handle SQLite database URL for production
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

print(f"Connecting to database...")
engine = create_engine(DATABASE_URL)

def check_table_exists(engine, table_name):
    """Check if a table exists in the database"""
    inspector = inspect(engine)
    return table_name in inspector.get_table_names()

def check_column_exists(engine, table_name, column_name):
    """Check if a column exists in a table"""
    inspector = inspect(engine)
    if not check_table_exists(engine, table_name):
        return False
    columns = [col['name'] for col in inspector.get_columns(table_name)]
    return column_name in columns

def run_migration():
    """Run the migration to add groups functionality"""
    try:
        with engine.connect() as conn:
            # Start transaction
            trans = conn.begin()
            
            try:
                print("Starting migration...")
                
                # 1. Create Group table if it doesn't exist
                if not check_table_exists(engine, 'group'):
                    print("Creating 'group' table...")
                    conn.execute(text("""
                        CREATE TABLE "group" (
                            id SERIAL PRIMARY KEY,
                            name VARCHAR(100) NOT NULL,
                            description VARCHAR(500),
                            created_by INTEGER NOT NULL REFERENCES "user"(id),
                            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                        )
                    """))
                    print("✓ Group table created")
                else:
                    print("✓ Group table already exists")
                
                # 2. Create GroupMember table if it doesn't exist
                if not check_table_exists(engine, 'group_member'):
                    print("Creating 'group_member' table...")
                    conn.execute(text("""
                        CREATE TABLE group_member (
                            id SERIAL PRIMARY KEY,
                            group_id INTEGER NOT NULL REFERENCES "group"(id),
                            user_id INTEGER NOT NULL REFERENCES "user"(id),
                            joined_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            is_admin BOOLEAN DEFAULT FALSE,
                            UNIQUE(group_id, user_id)
                        )
                    """))
                    print("✓ GroupMember table created")
                else:
                    print("✓ GroupMember table already exists")
                
                # 3. Add group_id column to expense table if it doesn't exist
                if not check_column_exists(engine, 'expense', 'group_id'):
                    print("Adding group_id column to expense table...")
                    
                    # First, create a default group for existing expenses
                    result = conn.execute(text("SELECT COUNT(*) as count FROM expense")).fetchone()
                    if result and result.count > 0:
                        print("Found existing expenses. Creating default group...")
                        
                        # Get the first user to be the creator of default group
                        first_user = conn.execute(text("SELECT id FROM \"user\" ORDER BY id LIMIT 1")).fetchone()
                        if first_user:
                            # Create default group
                            conn.execute(text("""
                                INSERT INTO "group" (name, description, created_by)
                                VALUES ('Default Group', 'Auto-created group for existing expenses', :user_id)
                            """), {"user_id": first_user.id})
                            
                            # Get the default group ID
                            default_group = conn.execute(text("""
                                SELECT id FROM "group" WHERE name = 'Default Group' AND created_by = :user_id
                            """), {"user_id": first_user.id}).fetchone()
                            
                            if default_group:
                                print(f"✓ Default group created with ID: {default_group.id}")
                                
                                # Add all existing users to the default group
                                conn.execute(text("""
                                    INSERT INTO group_member (group_id, user_id, is_admin)
                                    SELECT :group_id, id, TRUE FROM "user"
                                """), {"group_id": default_group.id})
                                
                                # Add group_id column with default value
                                conn.execute(text("ALTER TABLE expense ADD COLUMN group_id INTEGER"))
                                
                                # Update existing expenses to use default group
                                conn.execute(text("""
                                    UPDATE expense SET group_id = :group_id WHERE group_id IS NULL
                                """), {"group_id": default_group.id})
                                
                                # Make group_id NOT NULL
                                conn.execute(text("ALTER TABLE expense ALTER COLUMN group_id SET NOT NULL"))
                                
                                # Add foreign key constraint
                                conn.execute(text("""
                                    ALTER TABLE expense ADD CONSTRAINT fk_expense_group 
                                    FOREIGN KEY (group_id) REFERENCES "group"(id)
                                """))
                                
                                print("✓ group_id column added to expense table")
                    else:
                        # No existing expenses, just add the column
                        conn.execute(text("""
                            ALTER TABLE expense ADD COLUMN group_id INTEGER NOT NULL 
                            REFERENCES "group"(id)
                        """))
                        print("✓ group_id column added to expense table")
                else:
                    print("✓ group_id column already exists in expense table")
                
                # 4. Add paid_by column to expense table if it doesn't exist
                if not check_column_exists(engine, 'expense', 'paid_by'):
                    print("Adding paid_by column to expense table...")
                    conn.execute(text("ALTER TABLE expense ADD COLUMN paid_by INTEGER REFERENCES \"user\"(id)"))
                    
                    # Update existing expenses to set paid_by = user_id
                    conn.execute(text("UPDATE expense SET paid_by = user_id WHERE paid_by IS NULL"))
                    
                    print("✓ paid_by column added to expense table")
                else:
                    print("✓ paid_by column already exists in expense table")
                
                # Commit transaction
                trans.commit()
                print("✅ Migration completed successfully!")
                
            except Exception as e:
                trans.rollback()
                print(f"❌ Migration failed: {e}")
                raise
                
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        raise

if __name__ == "__main__":
    print("🔄 Starting Groups Migration...")
    run_migration()
    print("🎉 Migration complete!") 