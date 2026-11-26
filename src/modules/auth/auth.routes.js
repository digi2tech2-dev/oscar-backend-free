'use strict';

/**
 * auth.routes.js
 *
 * Public authentication routes:
 *   POST  /api/auth/register
 *   POST  /api/auth/login
 *   GET   /api/auth/verify-email?token=…
 *   POST  /api/auth/resend-verification
 *   GET   /api/auth/google                  → Passport redirect to Google
 *   GET   /api/auth/google/callback         → Passport OAuth callback
 *
 * 2FA routes:
 *   POST  /api/auth/2fa/generate            → Send email OTP before enabling 2FA (authenticated)
 *   POST  /api/auth/2fa/enable              → Confirm email OTP and activate 2FA (authenticated)
 *   POST  /api/auth/2fa/disable             → Deactivate 2FA (authenticated)
 *   POST  /api/auth/verify-2fa              → Exchange temp token + code for JWT (public)
 */

const { Router } = require('express');
const crypto = require('node:crypto');
const passport = require('../../config/google.strategy');
const authController = require('./auth.controller');
const {
    registerValidation,
    loginValidation,
    enable2FAValidation,
    disable2FAValidation,
    verify2FAValidation,
} = require('./auth.validation');
const validate = require('../../shared/middlewares/validate');
const authenticate = require('../../shared/middlewares/authenticate');
const { body } = require('express-validator');
const config = require('../../config/config');
const { authLimiter } = require('../../shared/middlewares/rateLimiter');

const router = Router();

// ── Guard middleware: return 503 when Google credentials are not configured ───
const requireGoogleConfig = (req, res, next) => {
    if (!config.google.clientId || !config.google.clientSecret) {
        return res.status(503).json({
            success: false,
            message: 'Google OAuth is not configured on this server. ' +
                'Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your .env.',
        });
    }
    next();
};

const cookieValue = (req, name) => String(req.headers.cookie || '')
    .split(';').map((item) => item.trim()).find((item) => item.startsWith(`${name}=`))
    ?.slice(name.length + 1);

const googleOAuthStart = (req, res, next) => {
    const state = crypto.randomBytes(32).toString('base64url');
    res.cookie('oauth_state', state, {
        httpOnly: true,
        secure: config.env === 'production',
        sameSite: 'lax',
        path: '/api/auth/google/callback',
        maxAge: 5 * 60 * 1000,
    });
    passport.authenticate('google', {
        scope: ['profile', 'email'],
        session: false,
        state,
    })(req, res, next);
};

const validateGoogleOAuthState = (req, res, next) => {
    const cookieState = cookieValue(req, 'oauth_state');
    const queryState = String(req.query.state || '');
    const expected = Buffer.from(cookieState || '');
    const provided = Buffer.from(queryState);
    const matches = expected.length === provided.length
        && expected.length > 0
        && crypto.timingSafeEqual(expected, provided);
    res.clearCookie('oauth_state', {
        httpOnly: true,
        secure: config.env === 'production',
        sameSite: 'lax',
        path: '/api/auth/google/callback',
    });
    if (!matches) return res.status(400).json({ success: false, message: 'Google sign-in state is invalid or expired.' });
    next();
};

// ─── Email / Password ─────────────────────────────────────────────────────────

/**
 * @route  POST /api/auth/register
 * @desc   Create a new customer account + send verification email
 * @access Public
 */
router.post('/register', authLimiter, registerValidation, validate, authController.register);

/**
 * @route  POST /api/auth/login
 * @desc   Authenticate user and get JWT
 * @access Public
 */
router.post('/login', authLimiter, loginValidation, validate, authController.login);

// ─── Email Verification ───────────────────────────────────────────────────────

/**
 * @route  GET /api/auth/verify-email?token=RAW_TOKEN
 * @desc   Verify email address via link in email
 * @access Public (token-gated)
 */
router.get('/verify-email', authController.verifyEmail);

/**
 * @route  POST /api/auth/resend-verification
 * @desc   Re-send verification email
 * @access Public
 * @note   Apply express-rate-limit in production (e.g. 3 requests / hour)
 */
router.post(
    '/resend-verification',
    authLimiter,
    [
        body('email')
            .isEmail().withMessage('A valid email address is required.')
            .normalizeEmail(),
    ],
    validate,
    authController.resendVerification
);

// ─── Google OAuth ─────────────────────────────────────────────────────────────

/**
 * @route  GET /api/auth/google
 * @desc   Redirect user to Google consent screen
 * @access Public
 */
router.get(
    '/google',
    authLimiter,
    requireGoogleConfig,
    googleOAuthStart
);

/**
 * @route  GET /api/auth/google/callback
 * @desc   Google calls this after authentication
 * @access Public (OAuth callback)
 */
router.get(
    '/google/callback',
    requireGoogleConfig,
    validateGoogleOAuthState,
    passport.authenticate('google', {
        session: false,
        failureRedirect: '/api/auth/google/failure',
    }),
    authController.googleCallback
);

router.post('/oauth-session', authController.exchangeOAuthSession);

/**
 * @route  GET /api/auth/google/failure
 * @desc   Generic fallback when Google OAuth fails
 * @access Public
 */
router.get('/google/failure', (req, res) => {
    res.status(401).json({
        success: false,
        message: 'Google authentication failed. Please try again.',
    });
});

// ─── Two-Factor Authentication ─────────────────────────────────────────────────────

/**
 * @route  POST /api/auth/2fa/generate
 * @desc   Send email OTP before enabling 2FA
 * @access Private (requires valid JWT)
 */
router.post('/2fa/generate', authenticate, authController.generate2FA);

/**
 * @route  POST /api/auth/2fa/enable
 * @desc   Confirm email OTP and activate 2FA for the authenticated user
 * @access Private (requires valid JWT)
 */
router.post('/2fa/enable', authenticate, enable2FAValidation, validate, authController.enable2FA);

/**
 * @route  POST /api/auth/2fa/disable
 * @desc   Deactivate 2FA (requires password)
 * @access Private (requires valid JWT)
 */
router.post('/2fa/disable', authenticate, disable2FAValidation, validate, authController.disable2FA);

/**
 * @route  POST /api/auth/verify-2fa
 * @desc   Exchange a 2FA temp token + email OTP code for a full auth JWT
 * @access Public (uses temp token in body, not Bearer header)
 */
router.post('/verify-2fa', authLimiter, verify2FAValidation, validate, authController.verify2FA);

module.exports = router;
