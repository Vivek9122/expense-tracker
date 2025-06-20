#!/usr/bin/env python3
"""
Fix local SQLite database by adding the missing group tables
"""

import sqlite3
import os

# Path to local SQLite database
DB_PATH = 'instance/expenses.db'

def fix_local_database():
    """Add groups tables to local SQLite database"""
    
    if not os.path.exists(DB_PATH):
        print(f"❌ Database file not found: {DB_PATH}")
        return
    
    print(f"🔄 Fixing local database: {DB_PATH}")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if group table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='group'")
        if not cursor.fetchone():
            print("Creating 'group' table...")
            cursor.execute("""
                CREATE TABLE "group" (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(100) NOT NULL,
                    description VARCHAR(500),
                    created_by INTEGER NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (created_by) REFERENCES user(id)
                )
            """)
            print("✅ Group table created")
        else:
            print("✅ Group table already exists")
        
        # Check if group_member table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='group_member'")
        if not cursor.fetchone():
            print("Creating 'group_member' table...")
            cursor.execute("""
                CREATE TABLE group_member (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    joined_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    is_admin BOOLEAN DEFAULT 0,
                    FOREIGN KEY (group_id) REFERENCES "group"(id),
                    FOREIGN KEY (user_id) REFERENCES user(id),
                    UNIQUE(group_id, user_id)
                )
            """)
            print("✅ GroupMember table created")
        else:
            print("✅ GroupMember table already exists")
        
        # Check if group_id column exists in expense table
        cursor.execute("PRAGMA table_info(expense)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'group_id' not in columns:
            print("Adding group_id column to expense table...")
            
            # Check if there are existing expenses
            cursor.execute("SELECT COUNT(*) FROM expense")
            expense_count = cursor.fetchone()[0]
            
            if expense_count > 0:
                print(f"Found {expense_count} existing expenses. Creating default group...")
                
                # Get first user
                cursor.execute("SELECT id FROM user ORDER BY id LIMIT 1")
                first_user = cursor.fetchone()
                
                if first_user:
                    user_id = first_user[0]
                    
                    # Create default group
                    cursor.execute("""
                        INSERT INTO "group" (name, description, created_by)
                        VALUES ('Default Group', 'Auto-created for existing expenses', ?)
                    """, (user_id,))
                    
                    group_id = cursor.lastrowid
                    print(f"✅ Default group created with ID: {group_id}")
                    
                    # Add all users to default group
                    cursor.execute("""
                        INSERT INTO group_member (group_id, user_id, is_admin)
                        SELECT ?, id, 1 FROM user
                    """, (group_id,))
                    
                    # Add group_id column
                    cursor.execute("ALTER TABLE expense ADD COLUMN group_id INTEGER")
                    
                    # Update existing expenses to use default group
                    cursor.execute("UPDATE expense SET group_id = ? WHERE group_id IS NULL", (group_id,))
                    
                    print("✅ Updated existing expenses with default group")
            else:
                # No existing expenses, just add the column
                cursor.execute("ALTER TABLE expense ADD COLUMN group_id INTEGER")
                print("✅ Added group_id column to expense table")
        else:
            print("✅ group_id column already exists in expense table")
        
        # Check if paid_by column exists
        if 'paid_by' not in columns:
            print("Adding paid_by column to expense table...")
            cursor.execute("ALTER TABLE expense ADD COLUMN paid_by INTEGER")
            
            # Update existing expenses to set paid_by = user_id
            cursor.execute("UPDATE expense SET paid_by = user_id WHERE paid_by IS NULL")
            print("✅ Added paid_by column to expense table")
        else:
            print("✅ paid_by column already exists in expense table")
        
        conn.commit()
        conn.close()
        
        print("🎉 Local database fixed successfully!")
        
    except Exception as e:
        print(f"❌ Error fixing database: {e}")
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    fix_local_database() 