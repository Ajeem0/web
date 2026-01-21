# Neon Database Setup - Permission Issue Solution

## Problem
You're getting `ERROR: permission denied for schema public` when trying to create tables with the `neondb_owner` user on Neon.

## Root Cause
Neon restricts the default `public` schema to superuser access only. The `neondb_owner` role you created lacks the `CREATE` privilege on the public schema.

## Solution: Two Approaches

### ✅ **RECOMMENDED: Use Neon SQL Editor**

The easiest solution is to use Neon's built-in SQL Editor as the postgres superuser:

1. **Go to Your Neon Project**
   - Visit: https://console.neon.tech
   - Select your project "neondb"

2. **Open SQL Editor**
   - Click "SQL Editor" in the sidebar
   - You'll be logged in as the `postgres` superuser (has all permissions)

3. **Grant Privileges to neondb_owner**
   - Copy and paste these commands in the SQL Editor:
   ```sql
   -- Grant neondb_owner the ability to create objects in public schema
   GRANT CREATE ON SCHEMA public TO neondb_owner;
   GRANT USAGE ON SCHEMA public TO neondb_owner;
   ```
   - Click "Run"

4. **Now Run Your Schema**
   - Back in your terminal:
   ```bash
   cd /Users/ajeem/Downloads/web/database
   psql -U neondb_owner -d neondb -f schema.sql
   ```
   - This should now work!

---

### Alternative: Create Custom Schema

If GRANT doesn't work, use a custom schema:

1. **In Neon SQL Editor, run:**
```sql
CREATE SCHEMA IF NOT EXISTS app;
GRANT ALL ON SCHEMA app TO neondb_owner;
ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT ALL ON TABLES TO neondb_owner;
ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT ALL ON SEQUENCES TO neondb_owner;
```

2. **Then modify your schema.sql:**
   - Add this at the top:
   ```sql
   SET search_path TO app, public;
   ```

3. **Update your Node.js connection:**
   - Edit `src/config/database.js`:
   ```javascript
   pool.on('connect', (client) => {
     client.query('SET search_path TO app, public;');
   });
   ```

---

## Quick Checklist

- [ ] Go to https://console.neon.tech
- [ ] Select your project
- [ ] Click "SQL Editor"
- [ ] Run the GRANT commands (paste above)
- [ ] Run: `psql -U neondb_owner -d neondb -f database/schema.sql`
- [ ] Check for errors
- [ ] Start server: `node server.js`
- [ ] Test API at http://localhost:3000

## If Still Failing

**Option 1: Check Current Privileges**
```sql
-- In Neon SQL Editor, check what neondb_owner can do:
SELECT * FROM information_schema.role_table_grants 
WHERE grantee='neondb_owner' AND table_schema='public';
```

**Option 2: Use Local PostgreSQL Instead**
```bash
# Install PostgreSQL locally (macOS)
brew install postgresql@15
brew services start postgresql@15

# Create local database
createdb classroom_scheduler

# Run schema
psql classroom_scheduler < database/schema.sql

# Update .env to use local database
DB_URL=postgresql://localhost/classroom_scheduler
```

**Option 3: Create New Neon Project**
- Delete current project
- Create new project
- Check if it has a different default configuration

## Testing After Setup

Once schema is created:

```bash
# Test connection
node -e "
const pool = require('./src/config/database.js');
pool.query('SELECT * FROM users LIMIT 1').then(r => {
  console.log('✅ Connected! Tables exist');
  process.exit(0);
}).catch(e => {
  console.log('❌ Error:', e.message);
  process.exit(1);
});
"
```

---

**Next Steps**: Follow the "RECOMMENDED" approach above, then let me know once tables are created!
