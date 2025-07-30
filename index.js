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
// Tenant registration
// Tenant registration - CORRECTED VERSION
app.post('/api/tenant/register', async (req, res) => {
  const { name, email, phone, password } = req.body;
  
  try {
    const emailLower = email.toLowerCase();
    
    // Validate required fields
    if (!name || !email || !phone || !password) {
      return res.status(400).json({
        success: false,
        message: 'Please fill all required fields'
      });
    }
    
    // Validate email format
    const emailRegex = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/;
    if (!emailRegex.test(emailLower)) {
      return res.status(400).json({
        success: false,
        message: 'Please enter a valid email address'
      });
    }
    
    // Validate phone number
    if (phone.length < 10) {
      return res.status(400).json({
        success: false,
        message: 'Please enter a valid phone number'
      });
    }
    
    // Validate password
    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters'
      });
    }
    
    // Check if tenant already exists - CRITICAL CHECK
    const existingUser = await findUser(emailLower);
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'Email already registered. Please use a different email or login instead.'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Generate unique 8-digit tenant ID
    const tenancyId = Math.floor(10000000 + Math.random() * 90000000).toString();
    
    // Insert new tenant
    const insertResult = await pool.query(
      `INSERT INTO tenants (name, email, phone, password_hash, tenancy_id, verified)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id`,
      [name, emailLower, phone, hashedPassword, tenancyId, false]
    );

    if (insertResult.rowCount === 0) {
      return res.status(500).json({
        success: false,
        message: 'Failed to create account. Please try again.'
      });
    }

    // Generate and store OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
    otpStore.set(emailLower, { otp, expiresAt, purpose: 'tenant_register' });

    // Send OTP email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify Your Tenant Account - Tenancy App',
      text: `Welcome to Tenancy App!

Your tenant registration OTP is: ${otp}

This code expires in 5 minutes.

After verification, you'll receive your unique Tenancy ID

Best regards,
Tenancy App Team`
    };

    try {
      await sendEmail(mailOptions);
      
      console.log(`✅ Tenant registration successful: ${emailLower} | Tenancy ID: ${tenancyId}`);
      
      // ✅ FIXED: Return 201 status with success response
      return res.status(201).json({ 
        success: true,
        message: 'Registration successful! Please check your email for OTP verification.',
        tenantId: tenancyId
      });
      
    } catch (emailError) {
      console.error('❌ Failed to send OTP email:', emailError);
      
      // Delete the created user since email failed
      await pool.query('DELETE FROM tenants WHERE email = $1', [emailLower]);
      
      return res.status(500).json({
        success: false,
        message: 'Account created but failed to send verification email. Please try again.'
      });
    }
    
  } catch (err) {
    console.error('💥 Tenant registration error:', err);
    
    // Handle specific database errors
    if (err.code === '23505') { // PostgreSQL unique violation
      if (err.constraint && err.constraint.includes('email')) {
        return res.status(409).json({
          success: false,
          message: 'Email already registered. Please use a different email or login instead.'
        });
      }
    }
    
    return res.status(500).json({ 
      success: false, 
      message: 'Registration failed. Please try again.' 
    });
  }
});
// Updated sendOtp function - removed HTML for Flutter app
async function sendOtp(email, purpose) {
  try {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Save OTP to database
    await OtpVerification.findOneAndUpdate(
      { email, purpose },
      { email, otp, purpose, expiresAt, createdAt: new Date() },
      { upsert: true }
    );

    // Get email content based on purpose - SIMPLIFIED FOR FLUTTER
    let subject, textContent;
    
    if (purpose === 'tenant_register') {
      subject = 'Verify Your Tenant Account - Tenancy App';
      textContent = `Welcome to Tenancy App!\n\nYour OTP code is: ${otp}\n\nThis code will expire in 10 minutes.\n\nAfter verification, you'll receive your unique Tenancy ID.`;
    } else {
      subject = 'Your OTP Code';
      textContent = `Your OTP code is: ${otp}`;
    }

    // Send email - USING TEXT INSTEAD OF HTML
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: subject,
      text: textContent  // Changed from html to text
    };

    await transporter.sendMail(mailOptions);
    
    return { success: true, message: 'OTP sent successfully' };
  } catch (error) {
    console.error('Send OTP error:', error);
    return { success: false, message: 'Failed to send OTP' };
  }
}

// Updated sendOtp function - removed HTML for Flutter app
async function sendOtp(email, purpose) {
  try {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Save OTP to database
    await OtpVerification.findOneAndUpdate(
      { email, purpose },
      { email, otp, purpose, expiresAt, createdAt: new Date() },
      { upsert: true }
    );

    // Get email content based on purpose - SIMPLIFIED FOR FLUTTER
    let subject, textContent;
    
    if (purpose === 'tenant_register') {
      subject = 'Verify Your Tenant Account - Tenancy App';
      textContent = `Welcome to Tenancy App!\n\nYour OTP code is: ${otp}\n\nThis code will expire in 10 minutes.\n\nAfter verification, you'll receive your unique Tenancy ID.`;
    } else {
      subject = 'Your OTP Code';
      textContent = `Your OTP code is: ${otp}`;
    }

    // Send email - USING TEXT INSTEAD OF HTML
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: subject,
      text: textContent  // Changed from html to text
    };

    await transporter.sendMail(mailOptions);
    
    return { success: true, message: 'OTP sent successfully' };
  } catch (error) {
    console.error('Send OTP error:', error);
    return { success: false, message: 'Failed to send OTP' };
  }
}

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

// ===================== UPDATED LANDLORD ROUTES =====================

// Get landlord's properties (REMOVED property rating averages)
app.get('/api/landlord/properties/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    const result = await pool.query(`
      SELECT 
        p.*,
        -- Current tenant info
        pth.tenant_id as current_tenant_id,
        t.name as current_tenant_name,
        t.tenancy_id as current_tenant_tenancy_id,
        t.email as current_tenant_email,
        pth.start_date as current_stay_start,
        -- Count of tenants who have stayed in this property
        COALESCE(COUNT(DISTINCT pth_all.tenant_id), 0) as total_tenants_stayed
      FROM properties p
      LEFT JOIN property_tenant_history pth ON p.id = pth.property_id AND pth.is_current = true
      LEFT JOIN tenants t ON pth.tenant_id = t.id
      LEFT JOIN property_tenant_history pth_all ON p.id = pth_all.property_id
      WHERE p.landlord_id = $1
      GROUP BY p.id, pth.tenant_id, t.name, t.tenancy_id, t.email, pth.start_date
      ORDER BY p.created_at DESC
    `, [id]);
    
    res.json({ properties: result.rows });
  } catch (err) {
    console.error('Get landlord properties error:', err);
    res.status(500).json({ error: 'Failed to get properties', properties: [] });
  }
});

// Get property history with tenant ratings
app.get('/api/landlord/property-history/:propertyId', async (req, res) => {
  const { propertyId } = req.params;
  
  try {
    console.log(`🏠 Getting property history for property: ${propertyId}`);
    
    const result = await pool.query(`
      SELECT 
        pth.*,
        t.name as tenant_name,
        t.email as tenant_email,
        t.tenancy_id as tenant_tenancy_id,
        t.phone as tenant_phone,
        -- Get tenant's rating for this specific property
        tr.rent_payment,
        tr.communication,
        tr.property_care,
        tr.utilities,
        tr.respect_others,
        tr.property_handover,
        tr.overall_rating,
        tr.comments,
        tr.created_at as rating_date,
        tr.stay_period_start,
        tr.stay_period_end
      FROM property_tenant_history pth
      JOIN tenants t ON pth.tenant_id = t.id
      LEFT JOIN tenant_ratings tr ON pth.tenant_id = tr.tenant_id 
                                 AND pth.property_id = tr.property_id
                                 AND pth.landlord_id = tr.landlord_id
      WHERE pth.property_id = $1
      ORDER BY pth.start_date DESC, pth.end_date DESC NULLS FIRST
    `, [propertyId]);
    
    console.log(`✅ Found ${result.rows.length} property history entries`);
    
    res.json({
      success: true,
      history: result.rows
    });
    
  } catch (err) {
    console.error('❌ Get property history error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get property history',
      history: []
    });
  }
});

// Search tenant by ID or name (ENHANCED with tenant overall stats and first_name, last_name)
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
        -- Overall tenant statistics across all properties
        COALESCE(COUNT(tr.id), 0) as total_ratings,
        COALESCE(ROUND(AVG(tr.overall_rating), 2), 0) as average_rating,
        -- Get detailed rating breakdown
        COALESCE(ROUND(AVG(tr.rent_payment), 2), 0) as avg_rent_payment,
        COALESCE(ROUND(AVG(tr.communication), 2), 0) as avg_communication,
        COALESCE(ROUND(AVG(tr.property_care), 2), 0) as avg_property_care,
        COALESCE(ROUND(AVG(tr.utilities), 2), 0) as avg_utilities,
        COALESCE(ROUND(AVG(tr.property_handover), 2), 0) as avg_property_handover,
        -- Calculate respect others percentage
        CASE 
          WHEN COUNT(tr.id) > 0 THEN 
            ROUND((COUNT(CASE WHEN tr.respect_others = true THEN 1 END)::NUMERIC / COUNT(tr.id)) * 100, 1)
          ELSE 0 
        END as respect_others_percentage,
        -- Get current property info if exists
        cp.address as current_property_address,
        cl.name as current_landlord_name,
        -- Count total properties stayed in
        COUNT(DISTINCT pth_all.property_id) as total_properties_stayed
      FROM tenants t
      LEFT JOIN tenant_ratings tr ON t.id = tr.tenant_id
      LEFT JOIN property_tenant_history cph ON t.id = cph.tenant_id AND cph.is_current = true
      LEFT JOIN properties cp ON cph.property_id = cp.id
      LEFT JOIN landlords cl ON cph.landlord_id = cl.id
      LEFT JOIN property_tenant_history pth_all ON t.id = pth_all.tenant_id
      WHERE 
        t.tenancy_id ILIKE $1 OR 
        t.name ILIKE $1 OR 
        t.email ILIKE $1
      GROUP BY t.id, t.name, t.email, t.phone, t.tenancy_id, cp.address, cl.name
      ORDER BY t.name
      LIMIT 10
    `, [`%${query}%`]);

    // Record search history
    if (searchResult.rows.length > 0 && landlordId) {
      for (const tenant of searchResult.rows) {
        await pool.query(
          'INSERT INTO tenant_search_history (landlord_id, tenant_id, search_type) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
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

// Get all tenants (UPDATED with tenant stats, not property stats, and first_name, last_name)
app.get('/api/landlord/all-tenants/:landlordId', async (req, res) => {
  const { landlordId } = req.params;
  
  try {
    const result = await pool.query(`
      SELECT 
        t.id,
        t.first_name,
        t.last_name,
        t.name,
        t.email,
        t.tenancy_id,
        COALESCE(AVG(tr.overall_rating), 0) as average_rating,
        COUNT(tr.id) as total_ratings,
        COUNT(DISTINCT pth.property_id) as total_properties_stayed
      FROM tenants t
      LEFT JOIN tenant_ratings tr ON t.id = tr.tenant_id
      LEFT JOIN property_tenant_history pth ON t.id = pth.tenant_id
      GROUP BY t.id, t.first_name, t.last_name, t.name, t.email, t.tenancy_id
      ORDER BY t.name
      LIMIT 20
    `);

    // Record that landlord viewed tenant list
    if (result.rows.length > 0) {
      for (const tenant of result.rows.slice(0, 5)) {
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
    console.log(`📚 Getting search history for landlord: ${landlordId}`);
    
    const result = await pool.query(`
      SELECT DISTINCT
        t.id,
        t.name,
        t.email,
        t.tenancy_id,
        tsh.searched_at,
        tsh.search_type,
        -- Rating summary for this tenant
        COALESCE(AVG(tr.overall_rating), 0) as average_rating,
        COUNT(tr.id) as total_ratings,
        -- Current property info if exists
        cp.address as current_property_address,
        cl.name as current_landlord_name
      FROM tenant_search_history tsh
      JOIN tenants t ON tsh.tenant_id = t.id
      LEFT JOIN tenant_ratings tr ON t.id = tr.tenant_id
      LEFT JOIN property_tenant_history cph ON t.id = cph.tenant_id AND cph.is_current = true
      LEFT JOIN properties cp ON cph.property_id = cp.id
      LEFT JOIN landlords cl ON cph.landlord_id = cl.id
      WHERE tsh.landlord_id = $1
      GROUP BY t.id, t.name, t.email, t.tenancy_id, tsh.searched_at, tsh.search_type, cp.address, cl.name
      ORDER BY tsh.searched_at DESC
      LIMIT 20
    `, [landlordId]);
    
    console.log(`✅ Found ${result.rows.length} search history entries for landlord ${landlordId}`);
    
    res.json({ 
      success: true,
      searchHistory: result.rows 
    });
    
  } catch (err) {
    console.error('❌ Get search history error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Failed to get search history', 
      searchHistory: [] 
    });
  }
});
app.get('/api/tenant/ratings/:tenantId', async (req, res) => {
  const { tenantId } = req.params;

  try {
    console.log(`📋 Getting tenant ratings for tenant: ${tenantId}`);

    // Get tenant basic info with summary stats
    const tenantResult = await pool.query(`
      SELECT 
        t.id,
        t.name,
        t.email,
        t.phone,
        t.tenancy_id,
        t.created_at,
        COUNT(tr.id) as total_ratings,
        COALESCE(ROUND(AVG(tr.overall_rating), 2), 0) as average_rating,
        COALESCE(ROUND(AVG(tr.rent_payment), 2), 0) as avg_rent_payment,
        COALESCE(ROUND(AVG(tr.communication), 2), 0) as avg_communication,
        COALESCE(ROUND(AVG(tr.property_care), 2), 0) as avg_property_care,
        COALESCE(ROUND(AVG(tr.utilities), 2), 0) as avg_utilities,
        COALESCE(ROUND(AVG(tr.property_handover), 2), 0) as avg_property_handover,
        CASE 
          WHEN COUNT(tr.id) > 0 THEN
            ROUND((COUNT(CASE WHEN tr.respect_others = true THEN 1 END)::NUMERIC / COUNT(tr.id)) * 100, 1)
          ELSE 0 
        END as respect_others_percentage
      FROM tenants t
      LEFT JOIN tenant_ratings tr ON t.id = tr.tenant_id
      WHERE t.id = $1
      GROUP BY t.id, t.name, t.email, t.phone, t.tenancy_id, t.created_at
    `, [tenantId]);

    if (tenantResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Tenant not found',
        ratings: []
      });
    }

    // Get ratings with property and landlord details - FIXED EXTRACT function
    const ratingsResult = await pool.query(`
      SELECT 
        tr.*,
        p.address as property_address,
        p.street as property_street,
        p.city as property_city,
        p.postal_code as property_postal_code,
        l.name as landlord_name,
        l.email as landlord_email,
        l.phone as landlord_phone,
        -- FIXED: Calculate days difference properly
        (CURRENT_DATE - tr.created_at::date) as rating_age_days
      FROM tenant_ratings tr
      JOIN properties p ON tr.property_id = p.id
      JOIN landlords l ON tr.landlord_id = l.id
      WHERE tr.tenant_id = $1
      ORDER BY tr.created_at DESC
    `, [tenantId]);

    console.log(`✅ Found ${ratingsResult.rows.length} ratings for tenant`);

    res.json({
      success: true,
      tenant: tenantResult.rows[0],
      ratings: ratingsResult.rows
    });

  } catch (err) {
    console.error('❌ Get tenant ratings error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get tenant ratings',
      ratings: []
    });
  }
});

// ALSO FIX: Get tenant details for landlord endpoint  
app.get('/api/tenant/ratings/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    // Get tenant basic info
    const tenantResult = await pool.query(`
      SELECT 
        id, 
        name, 
        email, 
        phone, 
        tenancy_id, 
        created_at 
      FROM tenants 
      WHERE id = $1
    `, [id]);
    
    if (tenantResult.rows.length === 0) {
      return res.status(404).json({ error: 'Tenant not found' });
    }
    
    // Get ONLY LAST 2 RATINGS for search popup (not all ratings)
    const ratingsResult = await pool.query(`
      SELECT 
        tr.*,
        p.address as property_address,
        p.street as property_street,
        p.city as property_city,
        p.postal_code as property_postal_code,
        l.name as landlord_name,
        l.email as landlord_email,
        l.phone as landlord_phone
      FROM tenant_ratings tr
      JOIN properties p ON tr.property_id = p.id
      JOIN landlords l ON tr.landlord_id = l.id
      WHERE tr.tenant_id = $1
      ORDER BY tr.created_at DESC
      LIMIT 2
    `, [id]);
    
    // Calculate summary statistics from ALL ratings (for display)
    const summaryResult = await pool.query(`
      SELECT 
        COUNT(tr.id) as total_ratings,
        COALESCE(ROUND(AVG(tr.overall_rating), 2), 0) as average_rating,
        COALESCE(ROUND(AVG(tr.rent_payment), 2), 0) as avg_rent_payment,
        COALESCE(ROUND(AVG(tr.communication), 2), 0) as avg_communication,
        COALESCE(ROUND(AVG(tr.property_care), 2), 0) as avg_property_care,
        COALESCE(ROUND(AVG(tr.utilities), 2), 0) as avg_utilities,
        COALESCE(ROUND(AVG(tr.property_handover), 2), 0) as avg_property_handover,
        -- Calculate respect others percentage
        CASE 
          WHEN COUNT(tr.id) > 0 THEN 
            ROUND((COUNT(CASE WHEN tr.respect_others = true THEN 1 END)::NUMERIC / COUNT(tr.id)) * 100, 1)
          ELSE 0 
        END as respect_others_percentage
      FROM tenant_ratings tr
      WHERE tr.tenant_id = $1
    `, [id]);
    
    res.json({
      tenant: {
        ...tenantResult.rows[0],
        ...summaryResult.rows[0]
      },
      ratings: ratingsResult.rows, // Only last 2 ratings for popup
      lastTwoStays: ratingsResult.rows // Same as ratings for this use case
    });
  } catch (err) {
    console.error('Get tenant ratings error:', err);
    res.status(500).json({ error: 'Failed to get tenant ratings' });
  }
});


// Rate a tenant
// Rate a tenant - CORRECTED VERSION
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
    console.log('📝 Rating tenant:', { tenantId, landlordId, propertyId });

    // Validate input values
    const ratingFields = [rentPayment, communication, propertyCare, utilities, propertyHandover];
    for (const rating of ratingFields) {
      if (!rating || rating < 1 || rating > 5) {
        return res.status(400).json({ 
          success: false,
          error: 'All ratings must be between 1 and 5 stars' 
        });
      }
    }

    // Validate required fields
    if (!tenantId || !landlordId || !propertyId || !stayPeriodStart) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields'
      });
    }

    // Validate dates
    if (stayPeriodEnd && new Date(stayPeriodEnd) < new Date(stayPeriodStart)) {
      return res.status(400).json({ 
        success: false,
        error: 'End date must be after start date' 
      });
    }

    // Check if rating already exists for this tenant-landlord-property combination
    const existingRating = await pool.query(
      'SELECT id FROM tenant_ratings WHERE tenant_id = $1 AND landlord_id = $2 AND property_id = $3',
      [tenantId, landlordId, propertyId]
    );

    if (existingRating.rows.length > 0) {
      return res.status(400).json({ 
        success: false,
        error: 'You have already rated this tenant for this property' 
      });
    }

    // Calculate overall rating
    const overallRating = (rentPayment + communication + propertyCare + utilities + propertyHandover) / 5;

    // Start transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Insert the rating
      const ratingResult = await client.query(`
        INSERT INTO tenant_ratings 
        (tenant_id, landlord_id, property_id, rent_payment, communication, property_care,
         utilities, respect_others, property_handover, overall_rating, comments,
         stay_period_start, stay_period_end, is_current_tenant)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        RETURNING id
      `, [
        tenantId, landlordId, propertyId, rentPayment, communication, propertyCare,
        utilities, respectOthers === 'Yes' ? true : respectOthers === 'No' ? false : null, 
        propertyHandover, overallRating, comments || '',
        stayPeriodStart, stayPeriodEnd, !stayPeriodEnd
      ]);

      // FIXED: Insert or update property tenant history with proper conflict handling
      await client.query(`
        INSERT INTO property_tenant_history (property_id, tenant_id, landlord_id, start_date, end_date, is_current)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (property_id, tenant_id, landlord_id) 
        DO UPDATE SET 
          start_date = COALESCE(EXCLUDED.start_date, property_tenant_history.start_date),
          end_date = EXCLUDED.end_date,
          is_current = EXCLUDED.is_current
      `, [propertyId, tenantId, landlordId, stayPeriodStart, stayPeriodEnd, !stayPeriodEnd]);

      // If this is current tenant, update property table
      if (!stayPeriodEnd) {
        const tenantInfo = await client.query(
          'SELECT name, tenancy_id FROM tenants WHERE id = $1', 
          [tenantId]
        );
        
        if (tenantInfo.rows.length > 0) {
          await client.query(`
            UPDATE properties 
            SET current_tenant_id = $1, 
                current_tenant_name = $2, 
                current_tenant_tenancy_id = $3
            WHERE id = $4
          `, [tenantId, tenantInfo.rows[0].name, tenantInfo.rows[0].tenancy_id, propertyId]);
        }
      }

      await client.query('COMMIT');

      console.log(`✅ Tenant rating submitted successfully`);
      
      res.json({
        success: true,
        message: 'Tenant rating submitted successfully',
        ratingId: ratingResult.rows[0].id
      });

    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

  } catch (err) {
    console.error('❌ Rate tenant error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Failed to submit tenant rating' 
    });
  }
});
app.get('/api/landlord/properties/:landlordId', async (req, res) => {
  const { landlordId } = req.params;

  try {
    console.log(`🏠 Getting properties for landlord: ${landlordId}`);

    const result = await pool.query(`
      SELECT 
        p.*,
        COUNT(tr.id) as total_ratings,
        COALESCE(ROUND(AVG(tr.overall_rating), 2), 0) as average_rating,
        t.name as current_tenant_name,
        t.tenancy_id as current_tenant_tenancy_id
      FROM properties p
      LEFT JOIN tenant_ratings tr ON p.id = tr.property_id
      LEFT JOIN tenants t ON p.current_tenant_id = t.id
      WHERE p.landlord_id = $1
      GROUP BY p.id, t.name, t.tenancy_id
      ORDER BY p.created_at DESC
    `, [landlordId]);

    console.log(`✅ Found ${result.rows.length} properties`);

    res.json({
      success: true,
      properties: result.rows
    });

  } catch (err) {
    console.error('❌ Get landlord properties error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get properties',
      properties: []
    });
  }
});


// ===================== TENANT ENDPOINTS =====================

// Tenant registration


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

    // Check if tenant needs verification
    if (user.role === 'tenant' && !user.verified) {
      return res.status(403).json({
        error: 'Please verify your email first',
        requiresVerification: true,
        isVerified: false,
        message: 'Check your email for OTP verification'
      });
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
        firstName: user.first_name,
        lastName: user.last_name,
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
      text: `Your OTP for ${purpose === 'reset' ? 'password reset' : purpose === 'admin_register' ? 'admin registration' : purpose === 'tenant_register' ? 'tenant verification' : 'verification'} is: ${otp}\n\nThis code expires in 5 minutes.\n\nIf you didn't request this, please ignore this email.\n\nBest regards,\nTenancy App Team`
    };

    await sendEmail(mailOptions);
    
    console.log(`OTP sent to ${emailLower} for ${purpose}`);
    res.json({ success: true, message: 'OTP sent successfully' });
  } catch (err) {
    console.error('Send OTP error:', err);
    res.status(500).json({ success: false, message: 'Failed to send OTP. Please check email configuration.' });
  }
});

// Verify OTP endpoint (UPDATED with tenant_register case)
// Send OTP route
app.post('/api/auth/send-otp', async (req, res) => {
  const { email, purpose } = req.body;
  
  try {
    const emailLower = email.toLowerCase();
    
    // For tenant_register, check if user exists and is unverified
    if (purpose === 'tenant_register') {
      const user = await findUser(emailLower);
      if (!user) {
        return res.json({ 
          success: false, 
          message: 'User not found' 
        });
      }
      if (user.role !== 'tenant') {
        return res.json({ 
          success: false, 
          message: 'Invalid user type' 
        });
      }
      if (user.verified) {
        return res.json({ 
          success: false, 
          message: 'Email already verified' 
        });
      }
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
    
    // Store OTP
    otpStore.set(emailLower, { otp, expiresAt, purpose });

    // Prepare email content based on purpose
    let subject, textContent;
    
    if (purpose === 'tenant_register') {
      subject = 'Verify Your Tenant Account - Tenancy App';
      textContent = `Welcome to Tenancy App!

Your OTP code is: ${otp}

This code will expire in 5 minutes.

After verification, you'll have access to your tenant account.

Best regards,
Tenancy App Team`;
    } else {
      subject = 'Your OTP Code - Tenancy App';
      textContent = `Your OTP code is: ${otp}

This code expires in 5 minutes.

Best regards,
Tenancy App Team`;
    }

    // Send email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: subject,
      text: textContent
    };

    await sendEmail(mailOptions);
    
    console.log(`OTP sent to ${emailLower} for ${purpose}`);
    res.json({ 
      success: true, 
      message: 'OTP sent successfully to your email' 
    });
    
  } catch (err) {
    console.error('Send OTP error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to send OTP. Please try again.' 
    });
  }
});

// Verify OTP route
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp, purpose } = req.body;

    const emailNormalized = email.toLowerCase();
    const storedOtp = otpStore.get(emailNormalized);

    console.log(`Verifying OTP for ${emailNormalized} with purpose ${purpose}`);

    if (!storedOtp || storedOtp.purpose !== purpose) {
      return res.json({ 
        success: false, 
        message: 'Invalid OTP request' 
      });
    }

    if (Date.now() > storedOtp.expiresAt) {
      otpStore.delete(emailNormalized);
      return res.json({ 
        success: false, 
        message: 'OTP expired. Please request a new one.' 
      });
    }

    if (storedOtp.otp !== otp.trim()) {
      return res.json({ 
        success: false, 
        message: 'Invalid OTP. Please check and try again.' 
      });
    }

    // Handle admin registration verification
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

    // Handle tenant registration verification
    if (purpose === 'tenant_register') {
      const tenantUpdate = await pool.query(
        'UPDATE tenants SET verified = true WHERE LOWER(email) = $1 RETURNING *',
        [emailNormalized]
      );

      if (tenantUpdate.rowCount === 0) {
        return res.json({ 
          success: false, 
          message: 'User not found' 
        });
      }

      const user = tenantUpdate.rows[0];
      const userData = {
        id: user.id,
        name: user.name,
        email: user.email,
        role: 'tenant',
        phone: user.phone,
        tenancyId: user.tenancy_id,
        verified: true
      };

      // Clear OTP from store
      otpStore.delete(emailNormalized);

      console.log(`Tenant email verified successfully: ${emailNormalized}`);

      return res.json({
        success: true,
        user: userData,
        message: 'Email verified successfully! Welcome to Tenancy App!',
      });
    }

    // Handle landlord registration verification
    if (purpose === 'register') {
      const landlordUpdate = await pool.query(
        'UPDATE landlords SET verified = true WHERE LOWER(email) = $1 RETURNING *',
        [emailNormalized]
      );

      if (landlordUpdate.rowCount === 0) {
        return res.json({ 
          success: false, 
          message: 'User not found' 
        });
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

    // Handle password reset verification
    if (purpose === 'reset') {
      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetExpires = Date.now() + 15 * 60 * 1000; // 15 minutes

      otpStore.set(emailNormalized, { resetToken, resetExpires, purpose: 'reset' });

      return res.json({
        success: true,
        resetToken,
        message: 'OTP verified successfully',
      });
    }

    return res.json({ 
      success: true, 
      message: 'OTP verified successfully' 
    });
    
  } catch (err) {
    console.error('Verify OTP error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'OTP verification failed. Please try again.' 
    });
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

// ===================== MISSING ADMIN ROUTES =====================

// Get all tenants for admin (UPDATED with first_name, last_name)
app.get('/api/admin/tenants', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        t.id,
        t.name,
        t.email,
        t.phone,
        t.tenancy_id,
        t.created_at,
        t.verified,
        COALESCE(COUNT(tr.id), 0) as total_ratings,
        COALESCE(ROUND(AVG(tr.overall_rating), 2), 0) as average_rating
      FROM tenants t
      LEFT JOIN tenant_ratings tr ON t.id = tr.tenant_id
      GROUP BY t.id, t.name, t.email, t.phone, t.tenancy_id, t.created_at, t.verified
      ORDER BY t.created_at DESC
    `);
    
    res.json({ tenants: result.rows });
  } catch (err) {
    console.error('Get all tenants error:', err);
    res.status(500).json({ error: 'Failed to get tenants', tenants: [] });
  }
});

// Get rating statistics for admin
app.get('/api/admin/rating-statistics', async (req, res) => {
  try {
    const statsResult = await pool.query(`
      SELECT 
        COUNT(*) as total_ratings,
        ROUND(AVG(overall_rating), 2) as avg_overall_rating,
        ROUND(AVG(rent_payment), 2) as avg_rent_payment,
        ROUND(AVG(communication), 2) as avg_communication,
        ROUND(AVG(property_care), 2) as avg_property_care,
        ROUND(AVG(utilities), 2) as avg_utilities,
        ROUND(AVG(property_handover), 2) as avg_property_handover,
        -- Distribution of ratings
        COUNT(CASE WHEN overall_rating >= 4.5 THEN 1 END) as excellent_ratings,
        COUNT(CASE WHEN overall_rating >= 3.5 AND overall_rating < 4.5 THEN 1 END) as good_ratings,
        COUNT(CASE WHEN overall_rating >= 2.5 AND overall_rating < 3.5 THEN 1 END) as average_ratings,
        COUNT(CASE WHEN overall_rating < 2.5 THEN 1 END) as poor_ratings,
        -- Respect others statistics
        ROUND((COUNT(CASE WHEN respect_others = true THEN 1 END)::NUMERIC / COUNT(*)) * 100, 1) as respect_others_percentage
      FROM tenant_ratings
      WHERE created_at >= CURRENT_DATE - INTERVAL '12 months'
    `);
    
    res.json(statsResult.rows[0] || {});
  } catch (err) {
    console.error('Get rating statistics error:', err);
    res.status(500).json({ error: 'Failed to get rating statistics' });
  }
});

// Get all landlords for admin
app.get('/api/admin/landlords', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        l.id,
        l.name,
        l.email,
        l.phone,
        l.address,
        l.city,
        l.postal_code,
        l.created_at,
        l.verified,
        l.admin_approved,
        COALESCE(COUNT(p.id), 0) as total_properties
      FROM landlords l
      LEFT JOIN properties p ON l.id = p.landlord_id AND p.approved = true
      WHERE l.verified = true AND l.admin_approved = true
      GROUP BY l.id, l.name, l.email, l.phone, l.address, l.city, l.postal_code, l.created_at, l.verified, l.admin_approved
      ORDER BY l.created_at DESC
    `);
    
    res.json({ landlords: result.rows });
  } catch (err) {
    console.error('Get all landlords error:', err);
    res.status(500).json({ error: 'Failed to get landlords', landlords: [] });
  }
});

// Get pending landlords for admin approval
app.get('/api/admin/pending-landlords', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, 
        name, 
        email, 
        phone, 
        address, 
        city, 
        postal_code, 
        created_at 
      FROM landlords 
      WHERE verified = true AND admin_approved = false
      ORDER BY created_at DESC
    `);
    
    res.json({ landlords: result.rows });
  } catch (err) {
    console.error('Get pending landlords error:', err);
    res.status(500).json({ error: 'Failed to get pending landlords', landlords: [] });
  }
});

// Verify/approve landlord by admin
app.post('/api/admin/verify-landlord/:id', async (req, res) => {
  const { id } = req.params;
  const { approve } = req.body;
  
  try {
    if (approve) {
      await pool.query('UPDATE landlords SET admin_approved = true WHERE id = $1', [id]);
      
      // Get landlord details for email notification
      const landlordResult = await pool.query(
        'SELECT name, email FROM landlords WHERE id = $1',
        [id]
      );
      
      if (landlordResult.rows.length > 0) {
        const landlord = landlordResult.rows[0];
        
        try {
          const mailOptions = {
            from: process.env.EMAIL_USER,
            to: landlord.email,
            subject: 'Account Approved - Welcome to Tenancy App!',
            text: `Dear ${landlord.name},\n\nGreat news! Your landlord account has been approved by our admin team.\n\nYou can now:\n- Log in to your account\n- Add property requests\n- Search and rate tenants\n- Manage your properties\n\nWelcome to Tenancy App!\n\nBest regards,\nTenancy App Team`
          };
          
          await sendEmail(mailOptions);
          console.log(`Landlord approval email sent to ${landlord.email}`);
        } catch (emailError) {
          console.error('Failed to send landlord approval email:', emailError);
        }
      }
      
      console.log(`Landlord ${id} approved successfully`);
    } else {
      await pool.query('DELETE FROM landlords WHERE id = $1', [id]);
      console.log(`Landlord ${id} rejected and deleted`);
    }
    
    res.json({ success: true, message: approve ? 'Landlord approved' : 'Landlord rejected' });
  } catch (err) {
    console.error('Verify landlord error:', err);
    res.status(500).json({ error: 'Failed to process landlord verification' });
  }
});

// Get tenant details for admin (UPDATED with first_name, last_name)
app.get('/api/admin/tenant/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    // Get tenant basic info with rating summary
    const tenantResult = await pool.query(`
      SELECT 
        t.id, 
        t.name, 
        t.email, 
        t.phone, 
        t.tenancy_id, 
        t.created_at, 
        t.verified,
        -- Rating summary
        COUNT(tr.id) as total_ratings,
        COALESCE(ROUND(AVG(tr.overall_rating), 2), 0) as average_rating,
        COALESCE(ROUND(AVG(tr.rent_payment), 2), 0) as avg_rent_payment,
        COALESCE(ROUND(AVG(tr.communication), 2), 0) as avg_communication,
        COALESCE(ROUND(AVG(tr.property_care), 2), 0) as avg_property_care,
        COALESCE(ROUND(AVG(tr.utilities), 2), 0) as avg_utilities,
        COALESCE(ROUND(AVG(tr.property_handover), 2), 0) as avg_property_handover,
        CASE 
          WHEN COUNT(tr.id) > 0 THEN 
            ROUND((COUNT(CASE WHEN tr.respect_others = true THEN 1 END)::NUMERIC / COUNT(tr.id)) * 100, 1)
          ELSE 0 
        END as respect_others_percentage
      FROM tenants t
      LEFT JOIN tenant_ratings tr ON t.id = tr.tenant_id
      WHERE t.id = $1
      GROUP BY t.id, t.name, t.email, t.phone, t.tenancy_id, t.created_at, t.verified
    `, [id]);
    
    if (tenantResult.rows.length === 0) {
      return res.status(404).json({ error: 'Tenant not found' });
    }
    
    // Get detailed ratings with property and landlord details - FIXED EXTRACT
    const ratingsResult = await pool.query(`
      SELECT 
        tr.*,
        p.address as property_address,
        p.street as property_street,
        p.city as property_city,
        p.postal_code as property_postal_code,
        l.name as landlord_name,
        l.email as landlord_email,
        l.phone as landlord_phone,
        -- FIXED: Calculate days difference properly
        (CURRENT_DATE - tr.created_at::date) as rating_age_days
      FROM tenant_ratings tr
      JOIN properties p ON tr.property_id = p.id
      JOIN landlords l ON tr.landlord_id = l.id
      WHERE tr.tenant_id = $1
      ORDER BY tr.created_at DESC
    `, [id]);
    
    console.log(`✅ Admin: Retrieved tenant details for ID ${id} with ${ratingsResult.rows.length} ratings`);
    
    res.json({
      tenant: tenantResult.rows[0],
      ratings: ratingsResult.rows
    });
  } catch (err) {
    console.error('❌ Get tenant details error:', err);
    res.status(500).json({ error: 'Failed to get tenant details' });
  }
});

// Get landlord details for admin
app.get('/api/admin/landlord/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    // Get landlord basic info
    const landlordResult = await pool.query(`
      SELECT 
        id, 
        name, 
        email, 
        phone, 
        address, 
        city, 
        postal_code, 
        created_at, 
        verified, 
        admin_approved 
      FROM landlords 
      WHERE id = $1
    `, [id]);
    
    if (landlordResult.rows.length === 0) {
      return res.status(404).json({ error: 'Landlord not found' });
    }
    
    // Get landlord properties with ratings
    const propertiesResult = await pool.query(`
      SELECT 
        p.*,
        COALESCE(COUNT(tr.id), 0) as total_ratings,
        COALESCE(AVG(tr.overall_rating), 0) as average_rating
      FROM properties p
      LEFT JOIN tenant_ratings tr ON p.id = tr.property_id
      WHERE p.landlord_id = $1
      GROUP BY p.id
      ORDER BY p.created_at DESC
    `, [id]);
    
    res.json({
      landlord: landlordResult.rows[0],
      properties: propertiesResult.rows
    });
  } catch (err) {
    console.error('Get landlord details error:', err);
    res.status(500).json({ error: 'Failed to get landlord details' });
  }
});

// ===================== CORRECTED TENANT ROUTES =====================

// Get tenant ratings with last 2 property history (UPDATED with first_name, last_name)
app.get('/api/tenant/ratings/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    // Get tenant basic info
    const tenantResult = await pool.query(`
      SELECT 
        id, 
        name, 
        email, 
        phone, 
        tenancy_id, 
        created_at 
      FROM tenants 
      WHERE id = $1
    `, [id]);
    
    if (tenantResult.rows.length === 0) {
      return res.status(404).json({ error: 'Tenant not found' });
    }
    
    // Get ONLY LAST 2 RATINGS for search popup (not all ratings)
    const ratingsResult = await pool.query(`
      SELECT 
        tr.*,
        p.address as property_address,
        p.street as property_street,
        p.city as property_city,
        p.postal_code as property_postal_code,
        l.name as landlord_name,
        l.email as landlord_email,
        l.phone as landlord_phone
      FROM tenant_ratings tr
      JOIN properties p ON tr.property_id = p.id
      JOIN landlords l ON tr.landlord_id = l.id
      WHERE tr.tenant_id = $1
      ORDER BY tr.created_at DESC
      LIMIT 2
    `, [id]);
    
    // Calculate summary statistics from ALL ratings (for display)
    const summaryResult = await pool.query(`
      SELECT 
        COUNT(tr.id) as total_ratings,
        COALESCE(ROUND(AVG(tr.overall_rating), 2), 0) as average_rating,
        COALESCE(ROUND(AVG(tr.rent_payment), 2), 0) as avg_rent_payment,
        COALESCE(ROUND(AVG(tr.communication), 2), 0) as avg_communication,
        COALESCE(ROUND(AVG(tr.property_care), 2), 0) as avg_property_care,
        COALESCE(ROUND(AVG(tr.utilities), 2), 0) as avg_utilities,
        COALESCE(ROUND(AVG(tr.property_handover), 2), 0) as avg_property_handover,
        -- Calculate respect others percentage
        CASE 
          WHEN COUNT(tr.id) > 0 THEN 
            ROUND((COUNT(CASE WHEN tr.respect_others = true THEN 1 END)::NUMERIC / COUNT(tr.id)) * 100, 1)
          ELSE 0 
        END as respect_others_percentage
      FROM tenant_ratings tr
      WHERE tr.tenant_id = $1
    `, [id]);
    
    res.json({
      tenant: {
        ...tenantResult.rows[0],
        ...summaryResult.rows[0]
      },
      ratings: ratingsResult.rows, // Only last 2 ratings for popup
      lastTwoStays: ratingsResult.rows // Same as ratings for this use case
    });
  } catch (err) {
    console.error('Get tenant ratings error:', err);
    res.status(500).json({ error: 'Failed to get tenant ratings' });
  }
});

// ===================== ENHANCED SEARCH ENDPOINTS =====================

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
  console.log('POST /api/auth/verify-otp - Verify OTP (supports tenant_register)');
  console.log('POST /api/auth/reset-password - Reset password');
  
  console.log('\n👨‍💼 ADMIN ENDPOINTS:');
  console.log('POST /api/admin/register - Admin registration');
  console.log('POST /api/admin/login - Admin login');
  console.log('GET /api/admin/dashboard-stats - Get dashboard stats');
  console.log('GET /api/admin/pending-properties - Get pending properties');
  console.log('POST /api/admin/approve-property/:id - Approve/reject property');
  console.log('GET /api/admin/tenants - Get all tenants');
  console.log('GET /api/admin/landlords - Get all landlords');
  console.log('GET /api/admin/pending-landlords - Get pending landlords');
  console.log('POST /api/admin/verify-landlord/:id - Approve/reject landlord');
  console.log('GET /api/admin/tenant/:id - Get tenant details');
  console.log('GET /api/admin/landlord/:id - Get landlord details');
  console.log('GET /api/admin/rating-statistics - Get rating statistics');
  
  console.log('\n🏠 LANDLORD ENDPOINTS:');
  console.log('POST /api/landlord/register - Landlord registration');
  console.log('GET /api/landlord/profile/:id - Get profile');
  console.log('PUT /api/landlord/profile/:id - Update profile');
  console.log('POST /api/landlord/add-property - Add property request');
  console.log('GET /api/landlord/properties/:id - Get properties');
  console.log('GET /api/landlord/property-history/:propertyId - Get property history');
  console.log('GET /api/landlord/search-tenant - Search tenant (enhanced with first_name, last_name)');
  console.log('GET /api/landlord/all-tenants/:landlordId - Get all tenants (enhanced with first_name, last_name)');
  console.log('GET /api/landlord/search-history/:landlordId - Get search history');
  console.log('POST /api/landlord/rate-tenant - Rate tenant');
  
  console.log('\n🏘️ TENANT ENDPOINTS:');
  console.log('POST /api/tenant/register - Tenant registration (with OTP verification)');
  console.log('GET /api/tenant/ratings/:id - Get tenant ratings (enhanced with first_name, last_name)');
});
