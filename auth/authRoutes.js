// auth/authRoutes.js
const express = require('express');
const router = express.Router();
const authController = require('./authController');

router.post('/register/landlord', authController.registerLandlord);
router.post('/register/tenant', authController.registerTenant);
router.post('/login', authController.login);

module.exports = router;