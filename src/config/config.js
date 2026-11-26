'use strict';

/**
 * Centralized application configuration.
 * All environment variable access should go through this file.
 */
const parseBoolean = (value, defaultValue = false) => {
    if (value === undefined || value === null || value === '') return defaultValue;
    return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase());
};

const parseNumber = (value, defaultValue) => {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? numeric : defaultValue;
};

const DEFAULT_RECEIPT_OCR_KEYWORDS = [
    'تم',
    'نجاح',
    'فودافون',
    'vodafone',
    'cash',
    'كاش',
    'تحويل',
];

const config = {
    env: process.env.NODE_ENV || 'development',
    port: parseInt(process.env.PORT, 10) || 5000,

    db: {
        uri: process.env.MONGO_URI,
    },

    jwt: {
        secret: process.env.JWT_SECRET,
        expiresIn: process.env.JWT_EXPIRES_IN || '15m',
        issuer: process.env.JWT_ISSUER || 'oscar-api',
        audience: process.env.JWT_AUDIENCE || 'oscar-client',
    },
    security: {
        trustedProviderHosts: (process.env.TRUSTED_PROVIDER_HOSTS || '').split(',').map((host) => host.trim().toLowerCase()).filter(Boolean),
        financialExecutionEnabled: parseBoolean(process.env.FINANCIAL_EXECUTION_ENABLED, true),
    },

    bcrypt: {
        rounds: parseInt(process.env.BCRYPT_ROUNDS, 10) || 12,
    },

    // ── Google OAuth ────────────────────────────────────────────────────────────
    google: {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackUrl: process.env.GOOGLE_CALLBACK_URL ||
            `http://localhost:${process.env.PORT || 5000}/api/auth/google/callback`,
    },

    // ── Email / SMTP ────────────────────────────────────────────────────────────
    email: {
        host: process.env.SMTP_HOST || 'smtp.mailtrap.io',
        port: parseInt(process.env.SMTP_PORT || '587', 10),
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
        from: process.env.EMAIL_FROM || 'noreply@platform.com',
        // Base URL for verification links (server-side)
        appUrl: process.env.APP_URL || `http://localhost:${process.env.PORT || 5000}`,
    },

    // ── Frontend ────────────────────────────────────────────────────────────────
    frontend: {
        url: process.env.FRONTEND_URL || 'http://localhost:3000',
        verifyRedirectUrl: process.env.FRONTEND_VERIFY_REDIRECT_URL ||
            `${process.env.FRONTEND_URL || 'http://localhost:3000'}/email-verified`,
    },

    // ── CORS ────────────────────────────────────────────────────────────────────
    cors: {
        allowedOrigins: process.env.ALLOWED_ORIGINS || 'http://localhost:3000',
    },

    // ── Receipt Analyzer (anti-fraud checks for deposit receipts) ──────────────
    receiptAnalyzer: {
        enableOcr: parseBoolean(process.env.RECEIPT_ANALYZER_ENABLE_OCR, false),
        minEntropy: parseNumber(process.env.RECEIPT_ANALYZER_MIN_ENTROPY, 1.0),
        blackMeanMax: parseNumber(process.env.RECEIPT_ANALYZER_BLACK_MEAN_MAX, 8),
        whiteMeanMin: parseNumber(process.env.RECEIPT_ANALYZER_WHITE_MEAN_MIN, 247),
        solidStdDevMax: parseNumber(process.env.RECEIPT_ANALYZER_SOLID_STDDEV_MAX, 2.5),
        lowEntropyStdDevMax: parseNumber(process.env.RECEIPT_ANALYZER_LOW_ENTROPY_STDDEV_MAX, 3.2),
        maxInputPixels: parseNumber(process.env.RECEIPT_ANALYZER_MAX_INPUT_PIXELS, 40_000_000),
        ocrTimeoutMs: parseNumber(process.env.RECEIPT_ANALYZER_OCR_TIMEOUT_MS, 3500),
        ocrResizeWidth: parseNumber(process.env.RECEIPT_ANALYZER_OCR_RESIZE_WIDTH, 1200),
        ocrMinKeywordMatches: parseNumber(process.env.RECEIPT_ANALYZER_OCR_MIN_KEYWORD_MATCHES, 1),
        ocrKeywords: String(process.env.RECEIPT_ANALYZER_OCR_KEYWORDS || '')
            .split(',')
            .map((keyword) => keyword.trim())
            .filter(Boolean)
            .length
            ? String(process.env.RECEIPT_ANALYZER_OCR_KEYWORDS || '')
                .split(',')
                .map((keyword) => keyword.trim())
                .filter(Boolean)
            : DEFAULT_RECEIPT_OCR_KEYWORDS,
    },
};

// Guard: fail fast if critical configs are missing
const required = ['MONGO_URI', 'JWT_SECRET'];
const missing = required.filter((key) => !process.env[key]);
if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
}

if (config.env === 'production') {
    const jwtBytes = Buffer.from(config.jwt.secret, 'base64');
    const canonicalBase64 = jwtBytes.length === 32
        && jwtBytes.toString('base64').replace(/=+$/, '') === config.jwt.secret.replace(/=+$/, '');
    const hexEncoded = /^[a-f0-9]{64}$/i.test(config.jwt.secret);
    const jwtKeyBytes = canonicalBase64 ? jwtBytes : (hexEncoded ? Buffer.from(config.jwt.secret, 'hex') : Buffer.alloc(0));
    const weakSecret = (!canonicalBase64 && !hexEncoded)
        || new Set(config.jwt.secret).size < 16
        || /change.?me|your_super|example|secret123/i.test(config.jwt.secret);
    if (weakSecret) throw new Error('JWT_SECRET must be a high-entropy secret of at least 32 characters in production');
    const lifetime = /^(\d+)(s|m|h)$/.exec(config.jwt.expiresIn);
    const lifetimeSeconds = lifetime
        ? Number(lifetime[1]) * ({ s: 1, m: 60, h: 3600 }[lifetime[2]])
        : Infinity;
    if (!Number.isSafeInteger(lifetimeSeconds) || lifetimeSeconds < 1 || lifetimeSeconds > 3600) {
        throw new Error('JWT_EXPIRES_IN must be between 1 second and 1 hour in production');
    }
    const themePepper = process.env.THEME_CODE_PEPPER || '';
    const themeBase64 = Buffer.from(themePepper, 'base64');
    const canonicalThemeBase64 = themeBase64.length === 32
        && themeBase64.toString('base64').replace(/=+$/, '') === themePepper.replace(/=+$/, '');
    const themeHex = /^[a-f0-9]{64}$/i.test(themePepper);
    const themeKeyBytes = canonicalThemeBase64 ? themeBase64 : (themeHex ? Buffer.from(themePepper, 'hex') : Buffer.from(themePepper, 'utf8'));
    if (themePepper.length < 32 || new Set(themePepper).size < 16
        || themePepper === config.jwt.secret
        || (jwtKeyBytes.length === 32 && themeKeyBytes.equals(jwtKeyBytes))) {
        throw new Error('THEME_CODE_PEPPER must be an independent high-entropy secret in production');
    }
    if (!process.env.PROVIDER_CREDENTIAL_ENCRYPTION_KEY) throw new Error('PROVIDER_CREDENTIAL_ENCRYPTION_KEY is required in production');
    const providerKeyBytes = Buffer.from(process.env.PROVIDER_CREDENTIAL_ENCRYPTION_KEY, 'base64');
    if (providerKeyBytes.length !== 32 || new Set(providerKeyBytes).size < 16
        || providerKeyBytes.equals(jwtKeyBytes) || providerKeyBytes.equals(themeKeyBytes)) {
        throw new Error('PROVIDER_CREDENTIAL_ENCRYPTION_KEY must be an independent base64 encoded 32-byte key');
    }
    if (config.security.trustedProviderHosts.length === 0) throw new Error('TRUSTED_PROVIDER_HOSTS must explicitly list approved supplier hostnames in production');
}

module.exports = config;
