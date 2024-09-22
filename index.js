

// Imports
const express = require('express');
const jwt = require('jsonwebtoken');
const keyManager = require('./keys');

const app = express();  // Express application
const PORT = 8080;      // Current PORT

// Middleware to parse JSON
app.use(express.json());

// Logging middleware to log all requests
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

// Root endpoint to show available endpoints
app.get('/', (req, res) => {
  res.status(200).send('JWKS Server: Use the endpoints /.well-known/jwks.json and /auth.');
});

// Endpoint to get JWKS 
app.get('/.well-known/jwks.json', (req, res) => {

  const keys = keyManager.getValidKeys();
  res.status(200).json({keys});

});

// Authentication endpoint to generate a JWT
app.post('/auth', (req, res) => {
  
  try {
    // Check if the request has an expired token
    const expired = req.query.expired === 'true';
    const kid = expired ? 'expired-key-id' : 'active-key-id'; // Use the expired key if requested
    const privateKey = keyManager.getPrivateKey(kid);         // Get the private key

    // Check if the private key exists
    if (!privateKey) {
      return res.status(404).json({ error: 'Key not found' }); // 404 Not Found
    }

    // Sign the JWT
    const token = jwt.sign(
      { username: 'user' },                  // Payload
      privateKey,                           // Private key
      {
        algorithm: 'RS256',                 // Specify the algorithm
        expiresIn: expired ? -10 : '1h',    // 1 hour expiration
        keyid: kid,                        // Key ID
      }
    );

    res.status(201).json({ token }); // 201 Created for successful creation of the token

  } catch (error) {

    console.error(error); // Log the error
    res.status(500).json({ error: 'Internal Server Error' }); // 500 Internal Server Error

  }
});

// Handle unsupported HTTP methods
app.use((req, res) => {
  res.status(405).json({ error: 'Method Not Allowed' }); // 405 Method Not Allowed
});

// Start the server
app.listen(PORT, () => {
  console.log(`JWKS server is running on http://localhost:${PORT}`);
});
