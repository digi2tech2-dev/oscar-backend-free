'use strict';

/**
 * auth.controller.js — thin HTTP adapter for auth.service.js
 *
 * Routes:
 *   POST   /api/auth/register            – email/password registration
 *   POST   /api/auth/login               – email/password login
 *   GET    /api/auth/verify-email        – consume email verification token
 *   POST   /api/auth/resend-verification – re-send verification email
 *   GET    /api/auth/google              – redirect to Google login (handled by passport)
 *   GET    /api/auth/google/callback     – Google callback
 */

const authService = require('./auth.service');
const { sendSuccess, sendCreated } = require('../../shared/utils/apiResponse');
const catchAsync = require('../../shared/utils/catchAsync');
const config = require('../../config/config');

// ─── Email / Password ─────────────────────────────────────────────────────────

/**
 * POST /api/auth/register
 */
const register = catchAsync(async (req, res) => {
    const { name, email, password, currency, country, phone, username } = req.body;
    const result = await authService.register({ name, email, password, currency, country, phone, username });
    sendCreated(res, result, result.message);
});

/**
 * POST /api/auth/login
 */
const login = catchAsync(async (req, res) => {
    const { email, password } = req.body;
    const result = await authService.login({ email, password });
    sendSuccess(res, result, 'Logged in successfully.');
});

// ─── Email Verification ───────────────────────────────────────────────────────

/**
 * GET /api/auth/verify-email?token=RAW_TOKEN
 *
 * On success  → 302 redirect to frontend URL (FRONTEND_VERIFY_REDIRECT_URL)
 * On failure  → JSON 422 error (invalid / expired token)
 */
const verifyEmail = async (req, res) => {
    const redirectUrl = process.env.FRONTEND_VERIFY_REDIRECT_URL || 'http://localhost:5173/email-verified';
    try {
        const { token } = req.query;
        if (!token) {
            return res.redirect(`${redirectUrl}?status=error&message=${encodeURIComponent('Token is required')}`);
        }
        await authService.verifyEmail(token);
        return res.redirect(`${redirectUrl}?status=success`);
    } catch (error) {
        return res.redirect(`${redirectUrl}?status=error&message=${encodeURIComponent(error.message)}`);
    }
};

/**
 * POST /api/auth/resend-verification
 * Body: { email }
 *
 * Always returns the same message to prevent user enumeration.
 */
const resendVerification = catchAsync(async (req, res) => {
    const { email } = req.body;
    const result = await authService.resendVerification(email);
    sendSuccess(res, null, result.message);
});

// ─── Google OAuth ─────────────────────────────────────────────────────────────

/**
 * GET /api/auth/google/callback
 *
 * Called by Passport after Google authenticates the user.
 * req.user is set by the Passport strategy.
 */
const googleCallback = catchAsync(async (req, res) => {
    const result = await authService.loginWithGoogle(req.user);

    // Derive the FE base URL from the configured verify-redirect URL
    const frontendBase = config.frontend.verifyRedirectUrl
        .replace(/\/email-verified.*$/, '')   // strip path, keep origin
        .replace(/\/+$/, '');                  // strip trailing slashes

    // If admin not yet approved — redirect frontend can show "pending" message
    if (!result.token) {
        if (result.requires2FA) {
            res.cookie('oauth_2fa', result.tempToken, {
                httpOnly: true,
                secure: config.env === 'production',
                sameSite: config.env === 'production' ? 'none' : 'lax',
                path: '/api/auth/verify-2fa',
                maxAge: 5 * 60 * 1000,
            });
            return res.redirect(`${frontendBase}/auth?status=requires-2fa`);
        }
        return res.redirect(`${frontendBase}/auth?status=pending`);
    }
    // OAuth session is handed off through a short-lived HttpOnly cookie.
    res.cookie('oauth_session', result.token, {
        httpOnly: true,
        secure: config.env === 'production',
        sameSite: config.env === 'production' ? 'none' : 'lax',
        path: '/api/auth/oauth-session',
        maxAge: 60 * 1000,
    });
    res.redirect(`${frontendBase}/auth?status=complete`);
});

const exchangeOAuthSession = catchAsync(async (req, res) => {
    const expectedOrigin = new URL(config.frontend.url).origin;
    if (req.get('Origin') !== expectedOrigin) return res.status(403).json({ success: false, message: 'Origin is not allowed.' });
    const cookieToken = String(req.headers.cookie || '').split(';').map((item) => item.trim()).find((item) => item.startsWith('oauth_session='))?.slice('oauth_session='.length);
    if (!cookieToken) return res.status(401).json({ success: false, message: 'OAuth handoff expired. Please sign in again.' });
    res.clearCookie('oauth_session', { path: '/api/auth/oauth-session' });
    res.set('Cache-Control', 'no-store');
    sendSuccess(res, { token: cookieToken }, 'OAuth session established.');
});

// ─── Two-Factor Authentication ────────────────────────────────────────────────

/**
 * POST /api/auth/2fa/generate
 * Requires authentication. Sends an email OTP before enabling 2FA.
 */
const generate2FA = catchAsync(async (req, res) => {
    const result = await authService.generate2FASecret(req.user._id);
    sendSuccess(res, null, result.message);
});

/**
 * POST /api/auth/2fa/enable
 * Requires authentication. Confirms email OTP and activates 2FA.
 */
const enable2FA = catchAsync(async (req, res) => {
    const result = await authService.enable2FA(req.user._id, req.body.code);
    sendSuccess(res, null, result.message);
});

/**
 * POST /api/auth/2fa/disable
 * Requires authentication. Deactivates 2FA (requires password).
 */
const disable2FA = catchAsync(async (req, res) => {
    const { password } = req.body;
    const result = await authService.disable2FA(req.user._id, { password });
    sendSuccess(res, null, result.message);
});

/**
 * POST /api/auth/verify-2fa
 * Public (uses temp token in body, not Bearer header).
 * Exchanges a 2FA-pending temp token + email OTP code for a full JWT.
 */
const verify2FA = catchAsync(async (req, res) => {
    const cookieToken = String(req.headers.cookie || '').split(';').map((item) => item.trim()).find((item) => item.startsWith('oauth_2fa='))?.slice('oauth_2fa='.length);
    if (!req.body.tempToken && cookieToken) {
        const expectedOrigin = new URL(config.frontend.url).origin;
        if (req.get('Origin') !== expectedOrigin) return res.status(403).json({ success: false, message: 'Origin is not allowed.' });
    }
    const { code } = req.body;
    const tempToken = req.body.tempToken || cookieToken;
    const result = await authService.verify2FA(tempToken, code);
    res.clearCookie('oauth_2fa', { path: '/api/auth/verify-2fa' });
    sendSuccess(res, result, 'Logged in successfully.');
});

module.exports = {
    register,
    login,
    verifyEmail,
    resendVerification,
    googleCallback,
    exchangeOAuthSession,
    generate2FA,
    enable2FA,
    disable2FA,
    verify2FA,
};
