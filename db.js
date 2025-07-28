
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://neondb_owner:npg_ea6cFMGCDSB4@ep-royal-mode-a1vtitee-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require'
});


module.exports = { pool };