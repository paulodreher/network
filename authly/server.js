require('dotenv').config()

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const winston = require('winston');
var querystring = require('querystring');

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [new winston.transports.Console()]
});

const REQUIRED_ENV = ['CLIENT_ID', 'CLIENT_SECRET', 'SESSION_SECRET', 'AUTH_ENDPOINT',
    'TOKEN_ENDPOINT', 'USER_ENDPOINT', 'REDIRECT_URI'];
for (const key of REQUIRED_ENV) {
    if (!process.env[key] || process.env[key].startsWith('REPLACE_ME')) {
        throw new Error(`Missing or unset environment variable: ${key}`);
    }
}

const app = express();

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'"],
            imgSrc: ["'self'", 'data:'],
            connectSrc: ["'self'", new URL(process.env.AUTH_ENDPOINT).origin]
        }
    }
}));

app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : [],
    credentials: true,
    methods: ['GET'],
    maxAge: 3600
}));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'Lax',
        maxAge: 3600000
    }
}));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });
const callbackLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false });

// Prevents authorization code replay within the same 5-minute window
const usedCodes = new Set();
setInterval(() => usedCodes.clear(), 5 * 60 * 1000);


app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/login', authLimiter, (req, res) => {
    const state = crypto.randomBytes(16).toString('hex');
    const nonce = crypto.randomBytes(16).toString('hex');
    const pkceVerifier = crypto.randomBytes(32).toString('base64url');
    const pkceChallenge = crypto.createHash('sha256').update(pkceVerifier).digest('base64url');

    req.session.regenerate((err) => {
        if (err) {
            logger.error('Session regeneration failed', { error: err.message });
            return res.status(500).send('Internal server error');
        }

        req.session.oauthState = state;
        req.session.oauthNonce = nonce;
        req.session.pkceVerifier = pkceVerifier;

        const queryParams = new URLSearchParams({
            response_type: 'code',
            client_id: process.env.CLIENT_ID,
            redirect_uri: process.env.REDIRECT_URI,
            scope: 'openid',
            state,
            nonce,
            code_challenge: pkceChallenge,
            code_challenge_method: 'S256'
        });

        logger.info('Redirecting to authorization server');
        res.redirect(`${process.env.AUTH_ENDPOINT}?${queryParams}`);
    });
});

app.get('/callback', callbackLimiter, (req, res) => {
    const incomingState = req.query.state || '';
    const sessionState = req.session.oauthState || '';

    const statesMatch = incomingState.length > 0 &&
        incomingState.length === sessionState.length &&
        crypto.timingSafeEqual(Buffer.from(incomingState), Buffer.from(sessionState));

    if (!statesMatch) {
        logger.warn('State mismatch in callback', { ip: req.ip });
        return res.status(403).send('State mismatch');
    }

    const { code } = req.query;

    if (!code || typeof code !== 'string' || code.length > 500 || !/^[a-zA-Z0-9\-._~]+$/.test(code)) {
        return res.status(400).send('Invalid authorization code');
    }

    if (usedCodes.has(code)) {
        logger.warn('Authorization code replay attempt', { ip: req.ip });
        return res.status(400).send('Authorization code already used');
    }
    usedCodes.add(code);

    const { pkceVerifier, oauthNonce } = req.session;
    delete req.session.oauthState;
    delete req.session.oauthNonce;
    delete req.session.pkceVerifier;

    const requestBody = querystring.stringify({
        grant_type: 'authorization_code',
        code,
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        redirect_uri: process.env.REDIRECT_URI,
        code_verifier: pkceVerifier
    });

    const tokenUrl = new URL(process.env.TOKEN_ENDPOINT);
    const requestParams = {
        host: tokenUrl.hostname,
        method: 'POST',
        port: tokenUrl.port || (tokenUrl.protocol === 'https:' ? 443 : 80),
        path: tokenUrl.pathname,
        timeout: 5000,
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(requestBody)
        }
    };

    makeRequest(requestParams, requestBody, tokenUrl.protocol).then((body) => {
        let tokenData;
        try {
            tokenData = JSON.parse(body);
        } catch {
            return res.status(500).send('Invalid token response');
        }

        if (!tokenData.access_token) {
            return res.status(500).send('Missing access token in response');
        }

        // Validate nonce claim in ID token to prevent token replay
        if (tokenData.id_token && oauthNonce) {
            try {
                const decoded = jwt.decode(tokenData.id_token);
                if (!decoded || decoded.nonce !== oauthNonce) {
                    logger.warn('Nonce mismatch in ID token', { ip: req.ip });
                    return res.status(403).send('Nonce validation failed');
                }
            } catch {
                return res.status(500).send('ID token validation failed');
            }
        }

        const expiresIn = (tokenData.expires_in || 3600) * 1000;
        req.session.accessToken = tokenData.access_token;
        req.session.refreshToken = tokenData.refresh_token || null;
        req.session.expiresAt = Date.now() + expiresIn;
        req.session.cookie.maxAge = Math.min(expiresIn, 3600000);

        res.redirect('/user');
    }).catch((err) => {
        logger.error('Token exchange failed', { error: err.message });
        res.status(500).send('Token exchange failed');
    });
});

function requireAuth(req, res, next) {
    if (!req.session.accessToken) {
        return res.redirect('/login');
    }

    if (req.session.expiresAt && Date.now() > req.session.expiresAt) {
        if (req.session.refreshToken) {
            doTokenRefresh(req.session.refreshToken).then((tokenData) => {
                if (!tokenData.access_token) {
                    return req.session.destroy(() => res.redirect('/login'));
                }
                const expiresIn = (tokenData.expires_in || 3600) * 1000;
                req.session.accessToken = tokenData.access_token;
                req.session.refreshToken = tokenData.refresh_token || null;
                req.session.expiresAt = Date.now() + expiresIn;
                req.session.cookie.maxAge = Math.min(expiresIn, 3600000);
                next();
            }).catch(() => req.session.destroy(() => res.redirect('/login')));
        } else {
            req.session.destroy(() => res.redirect('/login'));
        }
        return;
    }

    next();
}

app.get('/user', requireAuth, (req, res) => {
    const userUrl = new URL(process.env.USER_ENDPOINT);
    const requestParams = {
        host: userUrl.hostname,
        method: 'GET',
        port: userUrl.port || (userUrl.protocol === 'https:' ? 443 : 80),
        path: userUrl.pathname,
        timeout: 5000,
        headers: {
            'Authorization': `Bearer ${req.session.accessToken}`
        }
    };

    const transport = userUrl.protocol === 'https:' ? https : http;
    const request = transport.request(requestParams, (resp) => {
        let data = '';
        resp.on('data', (chunk) => { data += chunk; });
        resp.on('end', () => {
            try {
                res.json(JSON.parse(data));
            } catch {
                res.status(502).send('Invalid response from user endpoint');
            }
        });
    });

    request.on('error', (err) => {
        logger.error('User endpoint request failed', { error: err.message });
        if (!res.headersSent) res.status(502).send('Failed to fetch user info');
    });

    request.on('timeout', () => {
        request.destroy();
        if (!res.headersSent) res.status(504).send('User endpoint timed out');
    });

    request.end();
});

app.get('/logout', (req, res) => {
    const logoutUrl = new URL(process.env.AUTH_ENDPOINT.replace('/auth', '/logout'));
    logoutUrl.searchParams.set('redirect_uri', process.env.REDIRECT_URI);

    req.session.destroy((err) => {
        if (err) logger.error('Session destroy failed on logout', { error: err.message });
        res.redirect(logoutUrl.toString());
    });
});


function doTokenRefresh(refreshToken) {
    const tokenUrl = new URL(process.env.TOKEN_ENDPOINT);
    const requestBody = querystring.stringify({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET
    });

    const requestParams = {
        host: tokenUrl.hostname,
        method: 'POST',
        port: tokenUrl.port || (tokenUrl.protocol === 'https:' ? 443 : 80),
        path: tokenUrl.pathname,
        timeout: 5000,
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(requestBody)
        }
    };

    return makeRequest(requestParams, requestBody, tokenUrl.protocol).then((body) => JSON.parse(body));
}

function makeRequest(requestParams, requestBody, protocol) {
    const transport = protocol === 'https:' ? https : http;
    return new Promise((resolve, reject) => {
        const req = transport.request(requestParams, (response) => {
            if (response.statusCode < 200 || response.statusCode >= 300) {
                return reject(new Error(`Status Code: ${response.statusCode}`));
            }

            const data = [];
            response.on('data', (chunk) => { data.push(chunk); });
            response.on('end', () => resolve(Buffer.concat(data).toString()));
        });

        req.on('error', reject);
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Request timed out'));
        });

        if (requestBody) req.write(requestBody);
        req.end();
    });
}

app.use((err, req, res, next) => {
    logger.error('Unhandled error', { error: err.message });
    res.status(500).send('Internal server error');
});

app.listen(3000, () => {
    logger.info('Server listening', { address: 'http://localhost:3000' });
});
