const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { CloudWatchLogsClient, GetLogEventsCommand } = require('@aws-sdk/client-cloudwatch-logs');
const cors = require('cors');
const express = require('express');
const session = require('express-session');
const { Issuer, generators } = require('openid-client');

const app = express();

// SSL configuration
const sslOptions = {
    key: fs.readFileSync('/root/ssl-certificates/private.key'),
    cert: fs.readFileSync('/root/ssl-certificates/certificate.pem')
};

// Enhanced CORS configuration
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type']
}));

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Session middleware (only once)
app.use(session({
    secret: 'some secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true, // for HTTPS
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Configuration
const CONFIG = {
    cognito: {
        domain: 'us-east-1oy2eu7gpq.auth.us-east-1.amazoncognito.com', // Replace with your Cognito domain
        userPoolUrl: 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_OY2eU7GPq',
        clientId: '3o1moi7kpbon75fpli0dq1p84b',
        clientSecret: '1nno9pmjr450erv0hgofh5o3og5af40vshin5kkclsclig7imhjp', // Replace with actual secret
        callbackUrl: 'https://cognito-alb-1271424632.us-east-1.elb.amazonaws.com/callback',
        logoutUrl: 'https://cognito-alb-1271424632.us-east-1.elb.amazonaws.com'
    },
    server: {
        host: '172.31.8.65',
        httpPort: 3001,
        httpsPort: 443
    }
};

// OpenID Client
let oidcClient;

// Initialize CloudWatch client (renamed to avoid conflict)
const cloudWatchClient = new CloudWatchLogsClient({
    region: 'us-east-1',
});

// Initialize OpenID Client
async function initializeOIDCClient() {
    try {
        const issuer = await Issuer.discover(CONFIG.cognito.userPoolUrl);
        oidcClient = new issuer.Client({
            client_id: CONFIG.cognito.clientId,
            client_secret: CONFIG.cognito.clientSecret,
            redirect_uris: [CONFIG.cognito.callbackUrl],
            response_types: ['code']
        });
        console.log('OIDC Client initialized successfully');
    } catch (error) {
        console.error('Failed to initialize OIDC client:', error);
        throw error;
    }
}

// Authentication middleware
const checkAuth = (req, res, next) => {
    req.isAuthenticated = !!req.session.userInfo;
    next();
};

// Ensure OIDC client is initialized middleware
const ensureOIDCClient = (req, res, next) => {
    if (!oidcClient) {
        return res.status(503).json({ error: 'Authentication service not ready' });
    }
    next();
};

// ==================== ROUTES ====================

// Home route
app.get('/', checkAuth, (req, res) => {
    res.render('home', {
        isAuthenticated: req.isAuthenticated,
        userInfo: req.session.userInfo || {}
    });
});

// Login route
app.get('/login', ensureOIDCClient, (req, res) => {
    const nonce = generators.nonce();
    const state = generators.state();

    req.session.nonce = nonce;
    req.session.state = state;

    const authUrl = oidcClient.authorizationUrl({
        scope: 'phone openid email',
        state: state,
        nonce: nonce,
    });

    res.redirect(authUrl);
});

// OAuth callback route (renamed from /health to /callback)
app.get('/callback', ensureOIDCClient, async (req, res) => {
    try {
        const params = oidcClient.callbackParams(req);
        const tokenSet = await oidcClient.callback(
            CONFIG.cognito.callbackUrl,
            params,
            {
                nonce: req.session.nonce,
                state: req.session.state
            }
        );

        const userInfo = await oidcClient.userinfo(tokenSet.access_token);
        req.session.userInfo = userInfo;
        
        // Store tokens if needed
        req.session.tokenSet = {
            access_token: tokenSet.access_token,
            id_token: tokenSet.id_token,
            refresh_token: tokenSet.refresh_token
        };

        console.log('User logged in:', userInfo.email || userInfo.sub);
        res.redirect('/');
    } catch (err) {
        console.error('Callback error:', err);
        res.redirect('/?error=authentication_failed');
    }
});

// Health check route (separate from callback)
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        oidcClientReady: !!oidcClient
    });
});

// Logs endpoint
app.get('/api/logs', checkAuth, async (req, res) => {
    // Optional: Require authentication for logs
    // if (!req.isAuthenticated) {
    //     return res.status(401).json({ error: 'Unauthorized' });
    // }

    console.log('Received request for logs at:', new Date().toISOString());

    try {
        const params = {
            logGroupName: 'test',
            logStreamName: 'custom',
            limit: 100,
            startFromHead: true
        };

        console.log('Fetching logs with params:', params);

        const command = new GetLogEventsCommand(params);
        const response = await cloudWatchClient.send(command);

        console.log(`Successfully fetched ${response.events.length} logs`);

        const responseData = {
            timestamp: new Date().toISOString(),
            events: response.events,
            nextForwardToken: response.nextForwardToken,
            nextBackwardToken: response.nextBackwardToken
        };

        res.json(responseData);

    } catch (error) {
        console.error('Error fetching logs:', error);

        res.status(500).json({
            error: error.message,
            timestamp: new Date().toISOString(),
            details: {
                code: error.code,
                requestId: error.$metadata?.requestId,
                cfId: error.$metadata?.cfId
            }
        });
    }
});

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Session destruction error:', err);
        }
        
        const logoutUrl = `https://${CONFIG.cognito.domain}/logout?` +
            `client_id=${CONFIG.cognito.clientId}&` +
            `logout_uri=${encodeURIComponent(CONFIG.cognito.logoutUrl)}`;
        
        res.redirect(logoutUrl);
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        error: 'Internal Server Error',
        message: err.message,
        timestamp: new Date().toISOString()
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Not Found',
        path: req.path,
        timestamp: new Date().toISOString()
    });
});

// ==================== SERVER STARTUP ====================

async function startServer() {
    try {
        // Initialize OIDC client first
        await initializeOIDCClient();

        const httpServer = http.createServer(app);
        const httpsServer = https.createServer(sslOptions, app);

        httpServer.listen(CONFIG.server.httpPort, CONFIG.server.host, () => {
            console.log(`HTTP server running on http://${CONFIG.server.host}:${CONFIG.server.httpPort}`);
        });

        httpsServer.listen(CONFIG.server.httpsPort, CONFIG.server.host, () => {
            console.log(`Server started at ${new Date().toISOString()}`);
            console.log(`HTTPS server running on https://${CONFIG.server.host}:${CONFIG.server.httpsPort}`);
            console.log('Environment:', process.env.NODE_ENV || 'development');
        });

    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Start the server
startServer();

// Handle unhandled rejections
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    process.exit(1);
});
