// auth/authModel.js
const bcrypt = require('bcrypt');
const { pool } = require('../db');

const findUserByEmail = async (email) => {
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  return result.rows[0];
};

const createLandlord = async (userData) => {
  const hashedPassword = await bcrypt.hash(userData.password, 10);
  const result = await pool.query(
    `INSERT INTO users (name, email, phone, password, role, address, postal_code, city)
     VALUES ($1, $2, $3, $4, 'landlord', $5, $6, $7)
     RETURNING id, name, email, phone, address, postal_code AS "postalCode", city, role`,
    [
      userData.name,
      userData.email,
      userData.phone,
      hashedPassword,
      userData.address,
      userData.postalCode,
      userData.city
    ]
  );
  return result.rows[0];
};

const createTenant = async (userData) => {
  const hashedPassword = await bcrypt.hash(userData.password, 10);
  const tenancyId = `TID-${Date.now().toString(36).toUpperCase()}`;
  
  const result = await pool.query(
    `INSERT INTO users (name, email, phone, password, role, tenancy_id)
     VALUES ($1, $2, $3, $4, 'tenant', $5)
     RETURNING id, name, email, phone, role, tenancy_id AS "tenancyId"`,
    [userData.name, userData.email, userData.phone, hashedPassword, tenancyId]
  );
  return result.rows[0];
};

const verifyCredentials = async (email, password) => {
  const user = await findUserByEmail(email);
  if (!user) return null;

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return null;

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    ...(user.role === 'tenant' && { tenancyId: user.tenancy_id })
  };
};

module.exports = {
  findUserByEmail,
  createLandlord,
  createTenant,
  verifyCredentials
};