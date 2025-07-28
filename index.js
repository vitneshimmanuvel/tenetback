require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(bodyParser.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://neondb_owner:npg_ea6cFMGCDSB4@ep-royal-mode-a1vtitee-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require'
});

// Database connection test
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection failed:', err);
  } else {
    console.log(`Database connected successfully at ${res.rows[0].now}`);
  }
});

// Enhanced nodemailer configuration
const createTransporter = () => {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.error('EMAIL_USER or EMAIL_PASS not configured in environment variables');
    return null;
  }

  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
    tls: {
      rejectUnauthorized: false
    }
  });
};

const transporter = createTransporter();
const otpStore = new Map();

// Helper function to send emails
const sendEmail = async (mailOptions) => {
  if (!transporter) {
    throw new Error('Email service not configured');
  }
  
  try {
    const result = await transporter.sendMail(mailOptions);
    console.log('Email sent successfully:', result.messageId);
    return result;
  } catch (error) {
    console.error('Failed to send email:', error);
    throw error;
  }
};

// Helper to find user in all tables
const findUser = async (email) => {
  try {
    const emailLower = email.toLowerCase();
    
    // Check admins first
    const adminResult = await pool.query(
      'SELECT * FROM admins WHERE LOWER(email) = $1',
      [emailLower]
    );
    
    if (adminResult.rows.length > 0) {
      return { ...adminResult.rows[0], role: 'admin' };
    }

    const landlordResult = await pool.query(
      'SELECT * FROM landlords WHERE LOWER(email) = $1',
      [emailLower]
    );
    
    if (landlordResult.rows.length > 0) {
      return { ...landlordResult.rows[0], role: 'landlord' };
    }

    const tenantResult = await pool.query(
      'SELECT * FROM tenants WHERE LOWER(email) = $1',
      [emailLower]
    );
    
    if (tenantResult.rows.length > 0) {
      return { ...tenantResult.rows[0], role: 'tenant' };
    }

    return null;
  } catch (err) {
    console.error('Error finding user:', err);
    return null;
  }
};

// ===================== ADMIN ENDPOINTS =====================

// Admin registration
app.post('/api/admin/register', async (req, res) => {
  const { name, email, password } = req.body;
  
  try {
    const emailLower = email.toLowerCase();
    
    if (!emailLower.includes('alfa')) {
      return res.status(400).json({ error: 'Invalid admin email' });
    }

    if (await findUser(emailLower)) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000;
    otpStore.set(emailLower, { 
      otp, 
      expiresAt, 
      purpose: 'admin_register', 
      userData: { name, email: emailLower, hashedPassword } 
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Admin Registration OTP',
      text: `Your admin registration OTP is: ${otp}\nExpires in 5 minutes.`
    };

    await sendEmail(mailOptions);
    
    res.status(200).json({ 
      success: true,
      message: 'OTP sent to your email'
    });
  } catch (err) {
    console.error('Admin registration error:', err);
    res.status(500).json({ error: 'Registration failed. Please check email configuration.' });
  }
});

// Admin login
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const user = await findUser(email.toLowerCase());
    if (!user || user.role !== 'admin') {
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }

    const adminData = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role
    };

    console.log(`Admin login successful: ${email}`);
    res.json({ 
      message: 'Admin login successful',
      admin: adminData
    });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get admin dashboard stats
app.get('/api/admin/dashboard-stats', async (req, res) => {
  try {
    const tenantsResult = await pool.query('SELECT COUNT(*) FROM tenants');
    const landlordsResult = await pool.query(
      'SELECT COUNT(*) FROM landlords WHERE verified = true AND admin_approved = true'
    );
    const propertiesResult = await pool.query(
      'SELECT COUNT(*) FROM properties WHERE approved = true'
    );
    
    res.json({
      totalTenants: parseInt(tenantsResult.rows[0].count) || 0,
      totalLandlords: parseInt(landlordsResult.rows[0].count) || 0,
      totalProperties: parseInt(propertiesResult.rows[0].count) || 0
    });
  } catch (err) {
    console.error('Get admin stats error:', err);
    res.status(500).json({ 
      error: 'Failed to get stats',
      totalTenants: 0,
      totalLandlords: 0,
      totalProperties: 0
    });
  }
});

// Get pending property approvals for admin
app.get('/api/admin/pending-properties', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        p.id, 
        p.address, 
        p.street,
        p.city, 
        p.postal_code, 
        p.property_type,
        p.created_at,
        l.name as landlord_name,
        l.email as landlord_email,
        l.phone as landlord_phone
      FROM properties p 
      JOIN landlords l ON p.landlord_id = l.id 
      WHERE p.approved = false AND l.admin_approved = true
      ORDER BY p.created_at DESC
    `);
    
    console.log(`Found ${result.rows.length} pending property requests`);
    res.json({ properties: result.rows });
  } catch (err) {
    console.error('Get pending properties error:', err);
    res.status(500).json({ error: 'Failed to get pending properties', properties: [] });
  }
});

// Approve/reject property by admin
app.post('/api/admin/approve-property/:id', async (req, res) => {
  const { id } = req.params;
  const { approve } = req.body;
  
  try {
    if (approve) {
      await pool.query('UPDATE properties SET approved = true WHERE id = $1', [id]);
      
      const propertyResult = await pool.query(`
        SELECT p.address, p.city, l.email, l.name 
        FROM properties p 
        JOIN landlords l ON p.landlord_id = l.id 
        WHERE p.id = $1
      `, [id]);
      
      if (propertyResult.rows.length > 0) {
        const property = propertyResult.rows[0];
        
        try {
          const mailOptions = {
            from: process.env.EMAIL_USER,
            to: property.email,
            subject: 'Property Request Approved!',
            text: `Dear ${property.name},\n\nGreat news! Your property request has been approved.\n\nProperty Details:\nAddress: ${property.address}\nCity: ${property.city}\n\nYour property is now active on our platform and visible to potential tenants.\n\nBest regards,\nTenancy App Team`
          };
          
          await sendEmail(mailOptions);
          console.log(`Property approval email sent to ${property.email}`);
        } catch (emailError) {
          console.error('Failed to send property approval email:', emailError);
        }
      }
      
      console.log(`Property ${id} approved successfully`);
    } else {
      await pool.query('DELETE FROM properties WHERE id = $1', [id]);
      console.log(`Property ${id} rejected and deleted`);
    }
    
    res.json({ success: true, message: approve ? 'Property approved' : 'Property rejected' });
  } catch (err) {
    console.error('Approve property error:', err);
    res.status(500).json({ error: 'Failed to process property approval' });
  }
});

// ===================== LANDLORD ENDPOINTS =====================

// Landlord registration
app.post('/api/landlord/register', async (req, res) => {
  const { name, email, phone, password, address, postalCode, city } = req.body;
  
  try {
    const emailLower = email.toLowerCase();
    
    if (await findUser(emailLower)) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    await pool.query(
      `INSERT INTO landlords (name, email, phone, password_hash, address, city, postal_code, verified, admin_approved)
       VALUES ($1, $2, $3, $4, $5, $6, $7, false, false)`,
      [name, emailLower, phone, hashedPassword, address, city, postalCode]
    );

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000;
    otpStore.set(emailLower, { otp, expiresAt, purpose: 'register' });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify Your Registration - Tenancy App',
      text: `Welcome to Tenancy App!\n\nYour registration OTP is: ${otp}\n\nThis code expires in 5 minutes.\n\nAfter verification, your account will be sent for admin approval.\n\nBest regards,\nTenancy App Team`
    };

    try {
      await sendEmail(mailOptions);
      console.log(`Registration OTP sent to ${emailLower}`);
      res.status(201).json({ 
        success: true,
        message: 'Registration successful! OTP sent to your email for verification.'
      });
    } catch (emailError) {
      console.error('Failed to send registration OTP:', emailError);
      res.status(500).json({ error: 'Registration successful but failed to send OTP. Please contact support.' });
    }
  } catch (err) {
    console.error('Landlord registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Get landlord profile
app.get('/api/landlord/profile/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    const result = await pool.query('SELECT * FROM landlords WHERE id = $1', [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Landlord not found' });
    }

    const landlord = result.rows[0];
    const profileData = {
      id: landlord.id,
      name: landlord.name,
      email: landlord.email,
      phone: landlord.phone,
      address: landlord.address,
      city: landlord.city,
      postalCode: landlord.postal_code
    };

    res.json({ profile: profileData });
  } catch (err) {
    console.error('Get landlord profile error:', err);
    res.status(500).json({ error: 'Failed to get profile' });
  }
});

// Update landlord profile
app.put('/api/landlord/profile/:id', async (req, res) => {
  const { id } = req.params;
  const { name, phone, address } = req.body; // Note: email cannot be changed
  
  try {
    const result = await pool.query(
      'UPDATE landlords SET name = $1, phone = $2, address = $3 WHERE id = $4 RETURNING *',
      [name, phone, address, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Landlord not found' });
    }

    const updatedLandlord = result.rows[0];
    const profileData = {
      id: updatedLandlord.id,
      name: updatedLandlord.name,
      email: updatedLandlord.email,
      phone: updatedLandlord.phone,
      address: updatedLandlord.address,
      city: updatedLandlord.city,
      postalCode: updatedLandlord.postal_code
    };

    console.log(`Landlord profile updated: ${id}`);
    res.json({ success: true, profile: profileData, message: 'Profile updated successfully' });
  } catch (err) {
    console.error('Update landlord profile error:', err);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Add property request
app.post('/api/landlord/add-property', async (req, res) => {
  const { landlordId, address, street, city, postalCode } = req.body;
  
  try {
    const result = await pool.query(
      `INSERT INTO properties (landlord_id, address, street, city, postal_code, approved, status)
       VALUES ($1, $2, $3, $4, $5, false, 'pending')
       RETURNING id`,
      [landlordId, address, street || '', city, postalCode]
    );
    
    console.log(`Property request submitted by landlord ${landlordId}: ${address}`);
    res.status(201).json({ 
      success: true,
      message: 'Property request submitted for admin approval',
      propertyId: result.rows[0].id
    });
  } catch (err) {
    console.error('Add property request error:', err);
    res.status(500).json({ error: 'Failed to submit property request' });
  }
});

// Get landlord's properties
app.get('/api/landlord/properties/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    const result = await pool.query(`
      SELECT 
        p.*,
        COALESCE(COUNT(tr.id), 0) as total_ratings,
        COALESCE(AVG(tr.overall_rating), 0) as average_rating,
        pth.tenant_id as current_tenant_id,
        t.name as current_tenant_name,
        t.tenancy_id as current_tenant_tenancy_id
      FROM properties p
      LEFT JOIN tenant_ratings tr ON p.id = tr.property_id
      LEFT JOIN property_tenant_history pth ON p.id = pth.property_id AND pth.is_current = true
      LEFT JOIN tenants t ON pth.tenant_id = t.id
      WHERE p.landlord_id = $1
      GROUP BY p.id, pth.tenant_id, t.name, t.tenancy_id
      ORDER BY p.created_at DESC
    `, [id]);
    
    res.json({ properties: result.rows });
  } catch (err) {
    console.error('Get landlord properties error:', err);
    res.status(500).json({ error: 'Failed to get properties', properties: [] });
  }
});

// Get property history
app.get('/api/landlord/property-history/:propertyId', async (req, res) => {
  const { propertyId } = req.params;
  
  try {
    const result = await pool.query(`
      SELECT 
        tr.*,
        t.name as tenant_name,
        t.tenancy_id as tenant_tenancy_id,
        pth.start_date,
        pth.end_date,
        pth.is_current
      FROM tenant_ratings tr
      JOIN tenants t ON tr.tenant_id = t.id
      LEFT JOIN property_tenant_history pth ON tr.tenant_id = pth.tenant_id AND tr.property_id = pth.property_id
      WHERE tr.property_id = $1
      ORDER BY tr.created_at DESC
    `, [propertyId]);
    
    res.json({ history: result.rows });
  } catch (err) {
    console.error('Get property history error:', err);
    res.status(500).json({ error: 'Failed to get property history', history: [] });
  }
});

// Search tenant by ID or name
app.get('/api/landlord/search-tenant', async (req, res) => {
  const { query, landlordId } = req.query;
  
  try {
    const searchResult = await pool.query(`
      SELECT 
        t.id,
        t.name,
        t.email,
        t.phone,
        t.tenancy_id,
        COALESCE(COUNT(tr.id), 0) as total_ratings,
        COALESCE(AVG(tr.overall_rating), 0) as average_rating
      FROM tenants t
      LEFT JOIN tenant_ratings tr ON t.id = tr.tenant_id
      WHERE 
        t.tenancy_id ILIKE $1 OR 
        t.name ILIKE $1 OR 
        t.email ILIKE $1
      GROUP BY t.id, t.name, t.email, t.phone, t.tenancy_id
      ORDER BY t.name
      LIMIT 10
    `, [`%${query}%`]);

    // Record search history
    if (searchResult.rows.length > 0 && landlordId) {
      for (const tenant of searchResult.rows) {
        await pool.query(
          'INSERT INTO tenant_search_history (landlord_id, tenant_id, search_type) VALUES ($1, $2, $3)',
          [landlordId, tenant.id, 'search']
        );
      }
    }
    
    res.json({ tenants: searchResult.rows });
  } catch (err) {
    console.error('Search tenant error:', err);
    res.status(500).json({ error: 'Failed to search tenants', tenants: [] });
  }
});

// Get all tenants (simplified list)
app.get('/api/landlord/all-tenants/:landlordId', async (req, res) => {
  const { landlordId } = req.params;
  
  try {
    const result = await pool.query(`
      SELECT 
        t.id,
        t.name,
        t.email,
        t.tenancy_id,
        COALESCE(AVG(tr.overall_rating), 0) as average_rating
      FROM tenants t
      LEFT JOIN tenant_ratings tr ON t.id = tr.tenant_id
      GROUP BY t.id, t.name, t.email, t.tenancy_id
      ORDER BY t.name
      LIMIT 20
    `);

    // Record that landlord viewed tenant list
    if (result.rows.length > 0) {
      for (const tenant of result.rows.slice(0, 5)) { // Record only first 5 to avoid spam
        await pool.query(
          'INSERT INTO tenant_search_history (landlord_id, tenant_id, search_type) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
          [landlordId, tenant.id, 'list_view']
        );
      }
    }
    
    res.json({ tenants: result.rows });
  } catch (err) {
    console.error('Get all tenants error:', err);
    res.status(500).json({ error: 'Failed to get tenants', tenants: [] });
  }
});

// Get landlord's search history
app.get('/api/landlord/search-history/:landlordId', async (req, res) => {
  const { landlordId } = req.params;
  
  try {
    const result = await pool.query(`
      SELECT DISTINCT
        t.id,
        t.name,
        t.email,
        t.tenancy_id,
        tsh.searched_at,
        COALESCE(AVG(tr.overall_rating), 0) as average_rating
      FROM tenant_search_history tsh
      JOIN tenants t ON tsh.tenant_id = t.id
      LEFT JOIN tenant_ratings tr ON t.id = tr.tenant_id
      WHERE tsh.landlord_id = $1
      GROUP BY t.id, t.name, t.email, t.tenancy_id, tsh.searched_at
      ORDER BY tsh.searched_at DESC
      LIMIT 10
    `, [landlordId]);
    
    res.json({ searchHistory: result.rows });
  } catch (err) {
    console.error('Get search history error:', err);
    res.status(500).json({ error: 'Failed to get search history', searchHistory: [] });
  }
});

// Rate a tenant
app.post('/api/landlord/rate-tenant', async (req, res) => {
  const { 
    tenantId, 
    landlordId, 
    propertyId, 
    rentPayment, 
    communication, 
    propertyCare, 
    utilities, 
    respectOthers, 
    propertyHandover, 
    comments,
    stayPeriodStart,
    stayPeriodEnd 
  } = req.body;
  
  try {
    // Calculate overall rating
    const scores = [rentPayment, communication, propertyCare, utilities, propertyHandover];
    const overallRating = scores.reduce((sum, score) => sum + score, 0) / scores.length;

    const result = await pool.query(`
      INSERT INTO tenant_ratings 
      (tenant_id, landlord_id, property_id, rent_payment, communication, property_care, 
       utilities, respect_others, property_handover, overall_rating, comments, 
       stay_period_start, stay_period_end)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING id
    `, [
      tenantId, landlordId, propertyId, rentPayment, communication, propertyCare,
      utilities, respectOthers, propertyHandover, overallRating, comments,
      stayPeriodStart, stayPeriodEnd
    ]);

    // Update property tenant history if not exists
    await pool.query(`
      INSERT INTO property_tenant_history (property_id, tenant_id, landlord_id, start_date, end_date, is_current)
      VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT DO NOTHING
    `, [propertyId, tenantId, landlordId, stayPeriodStart, stayPeriodEnd, !stayPeriodEnd]);

    console.log(`Tenant rating submitted: Tenant ${tenantId} rated by Landlord ${landlordId}`);
    res.json({ 
      success: true, 
      message: 'Tenant rating submitted successfully',
      ratingId: result.rows[0].id 
    });
  } catch (err) {
    console.error('Rate tenant error:', err);
    res.status(500).json({ error: 'Failed to submit tenant rating' });
  }
});

// ===================== TENANT ENDPOINTS =====================

// Tenant registration
app.post('/api/tenant/register', async (req, res) => {
  const { name, email, phone, password } = req.body;
  const tenancyId = `TNE-${Date.now().toString(36).toUpperCase()}`;
  
  try {
    const emailLower = email.toLowerCase();
    
    if (await findUser(emailLower)) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO tenants (name, email, phone, password_hash, tenancy_id, verified)
       VALUES ($1, $2, $3, $4, $5, true)
       RETURNING id, name, email, phone, tenancy_id AS "tenancyId"`,
      [name, emailLower, phone, hashedPassword, tenancyId]
    );

    console.log(`Tenant registered: ${emailLower} | Tenancy ID: ${tenancyId}`);
    res.status(201).json({ 
      message: 'Tenant registration successful', 
      user: { ...result.rows[0], role: 'tenant' }
    });
  } catch (err) {
    console.error('Tenant registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ===================== GENERAL ENDPOINTS =====================

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const user = await findUser(email.toLowerCase());
    if (!user) {
      console.log(`Login failed: User not found (${email})`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      console.log(`Login failed: Incorrect password (${email})`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if landlord needs admin approval or verification
    if (user.role === 'landlord') {
      if (!user.verified) {
        return res.status(403).json({
          error: 'Please verify your email first',
          requiresVerification: true,
          isVerified: false,
          message: 'Check your email for OTP verification'
        });
      }
      if (!user.admin_approved) {
        return res.status(403).json({
          error: 'Account pending admin approval',
          requiresApproval: true,
          isVerified: true,
          message: 'Your account is waiting for admin approval'
        });
      }
    }

    // Update last login
    if (user.role === 'landlord') {
      await pool.query('UPDATE landlords SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);
    } else if (user.role === 'tenant') {
      await pool.query('UPDATE tenants SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);
    }

    const userData = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      phone: user.phone,
      ...(user.role === 'tenant' && { 
        tenancyId: user.tenancy_id,
        verified: user.verified 
      }),
      ...(user.role === 'landlord' && { 
        address: user.address,
        postalCode: user.postal_code,
        city: user.city,
        verified: user.verified,
        adminApproved: user.admin_approved
      })
    };

    console.log(`Login successful: ${email} (${user.role})`);
    res.json({ 
      success: true,
      message: 'Login successful',
      user: userData
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Send OTP endpoint
app.post('/api/auth/send-otp', async (req, res) => {
  const { email, purpose } = req.body;
  
  try {
    const emailLower = email.toLowerCase();
    
    // Check if user exists (except for admin registration)
    if (purpose !== 'admin_register') {
      const user = await findUser(emailLower);
      if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000;
    
    // Store OTP
    otpStore.set(emailLower, { otp, expiresAt, purpose });

    // Send email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP Code - Tenancy App',
      text: `Your OTP for ${purpose === 'reset' ? 'password reset' : purpose === 'admin_register' ? 'admin registration' : 'verification'} is: ${otp}\n\nThis code expires in 5 minutes.\n\nIf you didn't request this, please ignore this email.\n\nBest regards,\nTenancy App Team`
    };

    await sendEmail(mailOptions);
    
    console.log(`OTP sent to ${emailLower} for ${purpose}`);
    res.json({ success: true, message: 'OTP sent successfully' });
  } catch (err) {
    console.error('Send OTP error:', err);
    res.status(500).json({ success: false, message: 'Failed to send OTP. Please check email configuration.' });
  }
});

// Verify OTP endpoint
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    let { email, otp, purpose } = req.body;

    const emailNormalized = email.toLowerCase();
    const storedOtp = otpStore.get(emailNormalized);

    console.log(`Verifying OTP for ${emailNormalized} with purpose ${purpose}`);

    if (!storedOtp || storedOtp.purpose !== purpose) {
      return res.status(400).json({ success: false, message: 'Invalid OTP request' });
    }

    if (Date.now() > storedOtp.expiresAt) {
      otpStore.delete(emailNormalized);
      return res.status(400).json({ success: false, message: 'OTP expired' });
    }

    if (storedOtp.otp !== otp.trim()) {
      return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }

    // OTP is valid, handle different purposes
    if (purpose === 'admin_register') {
      const { name, email: adminEmail, hashedPassword } = storedOtp.userData;

      const result = await pool.query(
        `INSERT INTO admins (name, email, password_hash, verified)
         VALUES ($1, $2, $3, true)
         RETURNING id, name, email`,
        [name, adminEmail, hashedPassword]
      );

      otpStore.delete(emailNormalized);

      return res.json({
        success: true,
        admin: { ...result.rows[0], role: 'admin' },
        message: 'Admin registration successful',
      });
    }

    if (purpose === 'register') {
      const landlordUpdate = await pool.query(
        'UPDATE landlords SET verified = true WHERE LOWER(email) = $1 RETURNING *',
        [emailNormalized]
      );

      if (landlordUpdate.rowCount === 0) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }

      const user = landlordUpdate.rows[0];
      const userData = {
        id: user.id,
        name: user.name,
        email: user.email,
        role: 'landlord',
        verified: true,
        phone: user.phone,
        address: user.address,
        postalCode: user.postal_code,
        city: user.city,
        adminApproved: user.admin_approved,
      };

      otpStore.delete(emailNormalized);

      return res.json({
        success: true,
        user: userData,
        message: 'Email verified successfully! Your account is now pending admin approval.',
      });
    }

    if (purpose === 'reset') {
      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetExpires = Date.now() + 15 * 60 * 1000;

      otpStore.set(emailNormalized, { resetToken, resetExpires, purpose: 'reset' });

      return res.json({
        success: true,
        resetToken,
        message: 'OTP verified successfully',
      });
    }

    return res.json({ success: true, message: 'OTP verified successfully' });
  } catch (err) {
    console.error('Verify OTP error:', err);
    res.status(500).json({ success: false, message: 'OTP verification failed' });
  }
});

// Reset password endpoint
app.post('/api/auth/reset-password', async (req, res) => {
  const { email, resetToken, newPassword } = req.body;
  
  try {
    const emailLower = email.toLowerCase();
    const storedReset = otpStore.get(emailLower);
    
    if (!storedReset || storedReset.purpose !== 'reset') {
      return res.status(400).json({ success: false, message: 'Invalid reset request' });
    }
    
    if (Date.now() > storedReset.resetExpires) {
      otpStore.delete(emailLower);
      return res.status(400).json({ success: false, message: 'Reset token expired' });
    }
    
    if (storedReset.resetToken !== resetToken) {
      return res.status(400).json({ success: false, message: 'Invalid reset token' });
    }
    
    // Token is valid - reset password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    // Update password in all tables
    const landlordUpdate = await pool.query(
      'UPDATE landlords SET password_hash = $1 WHERE LOWER(email) = $2',
      [hashedPassword, emailLower]
    );
    
    const tenantUpdate = await pool.query(
      'UPDATE tenants SET password_hash = $1 WHERE LOWER(email) = $2',
      [hashedPassword, emailLower]
    );
    
    const adminUpdate = await pool.query(
      'UPDATE admins SET password_hash = $1 WHERE LOWER(email) = $2',
      [hashedPassword, emailLower]
    );
    
    if (landlordUpdate.rowCount === 0 && tenantUpdate.rowCount === 0 && adminUpdate.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    otpStore.delete(emailLower);
    res.json({ success: true, message: 'Password reset successful' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ success: false, message: 'Password reset failed' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    message: 'Server is running'
  });
});

// Test database tables
app.get('/api/test/tables', async (req, res) => {
  try {
    const tables = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
      ORDER BY table_name
    `);
    
    const counts = {};
    for (const table of tables.rows) {
      try {
        const countResult = await pool.query(`SELECT COUNT(*) FROM ${table.table_name}`);
        counts[table.table_name] = parseInt(countResult.rows[0].count);
      } catch (err) {
        counts[table.table_name] = 'Error: ' + err.message;
      }
    }
    
    res.json({
      tables: tables.rows.map(row => row.table_name),
      counts: counts
    });
  } catch (err) {
    console.error('Test tables error:', err);
    res.status(500).json({ error: 'Failed to get table info' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  console.log(`404 - Route not found: ${req.method} ${req.path}`);
  res.status(404).json({ error: `Route not found: ${req.method} ${req.path}` });
});

console.log('Starting server...');
app.listen(PORT, () => {
  console.log(`✓ Server running on port ${PORT}`);
  console.log(`✓ Health check: http://localhost:${PORT}/api/health`);
  console.log(`✓ Test tables: http://localhost:${PORT}/api/test/tables`);
  
  console.log('\n=== API ENDPOINTS ===');
  console.log('🔐 AUTH ENDPOINTS:');
  console.log('POST /api/auth/login - User login');
  console.log('POST /api/auth/send-otp - Send OTP');
  console.log('POST /api/auth/verify-otp - Verify OTP');
  console.log('POST /api/auth/reset-password - Reset password');
  
  console.log('\n👨‍💼 ADMIN ENDPOINTS:');
  console.log('POST /api/admin/register - Admin registration');
  console.log('POST /api/admin/login - Admin login');
  console.log('GET /api/admin/dashboard-stats - Get dashboard stats');
  console.log('GET /api/admin/pending-properties - Get pending properties');
  console.log('POST /api/admin/approve-property/:id - Approve/reject property');
  
  console.log('\n🏠 LANDLORD ENDPOINTS:');
  console.log('POST /api/landlord/register - Landlord registration');
  console.log('GET /api/landlord/profile/:id - Get profile');
  console.log('PUT /api/landlord/profile/:id - Update profile');
  console.log('POST /api/landlord/add-property - Add property request');
  console.log('GET /api/landlord/properties/:id - Get properties');
  console.log('GET /api/landlord/property-history/:propertyId - Get property history');
  console.log('GET /api/landlord/search-tenant - Search tenant');
  console.log('GET /api/landlord/all-tenants/:landlordId - Get all tenants');
  console.log('GET /api/landlord/search-history/:landlordId - Get search history');
  console.log('POST /api/landlord/rate-tenant - Rate tenant');
  
  console.log('\n🏘️ TENANT ENDPOINTS:');
  console.log('POST /api/tenant/register - Tenant registration');
});