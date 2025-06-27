const express = require('express');
const { google } = require('googleapis');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// Validate secrets
if (!process.env.CLIENT_ID || !process.env.CLIENT_SECRET) {
  console.error('\n Missing CLIENT_ID or CLIENT_SECRET in Secrets!');
  process.exit(1);
}

const REDIRECT_URI = "https://cloud-phish-protector.onrender.com/oauth2callback";
console.log(`Using redirect URI: ${REDIRECT_URI}`);


// Set up OAuth2 client
const oAuth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  REDIRECT_URI
);

// Route: Home page
app.get('/', (req, res) => {
  const authUrl = oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/gmail.readonly'],
  });

  res.send(`
    <h2>Phish Protector</h2>
    <a href="${authUrl}">Login with Gmail</a>
  `);
});

// Route: OAuth2 callback
app.get('/oauth2callback', async (req, res) => {
  const code = req.query.code;
  const error = req.query.error;

  if (error) {
    console.error(`OAuth error: ${error}`);
    return res.send(`Access denied: ${error}`);
  }

  if (!code) {
    return res.send('No auth code found. Something went wrong.');
  }

  try {
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);

    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });
    const response = await gmail.users.messages.list({
      userId: 'me',
      maxResults: 5,
    });

    const messages = response.data.messages || [];
    let output = '<h2>Last 5 Gmail Message IDs</h2><ul>';

    for (let msg of messages) {
      output += `<li>${msg.id}</li>`;
    }

    output += '</ul>';
    res.send(output);
  } catch (err) {
    console.error('Error during OAuth flow:', err);
    res.send('Something went wrong during login.');
  }
});

// Start server
app.listen(port, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${port}`);
});
