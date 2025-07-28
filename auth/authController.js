// auth/authController.js
const authModel = require('./authModel');

const registerLandlord = async (req, res) => {
  try {
    const existingUser = await authModel.findUserByEmail(req.body.email);
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const newUser = await authModel.createLandlord(req.body);
    res.status(201).json({ 
      message: 'Landlord registration successful', 
      user: newUser 
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Landlord registration failed' });
  }
};

const registerTenant = async (req, res) => {
  try {
    const existingUser = await authModel.findUserByEmail(req.body.email);
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const newUser = await authModel.createTenant(req.body);
    res.status(201).json({ 
      message: 'Tenant registration successful', 
      user: newUser 
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Tenant registration failed' });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await authModel.verifyCredentials(email, password);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    res.json({ 
      message: 'Login successful',
      user
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
};

module.exports = {
  registerLandlord,
  registerTenant,
  login
};