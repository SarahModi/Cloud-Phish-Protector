const express = require('express');
const { google } = require('googleapis');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// Validate secrets
if (!process.env.CLIENT_ID || !process.env.CLIENT_SECRET) {
  console.error('\n❌ Missing CLIENT_ID or CLIENT_SECRET in Secrets!');
  process.exit(1);
}

const REDIRECT_URI = "https://cloud-phish-protector.onrender.com/oauth2callback";
console.log(`🔁 Using redirect URI: ${REDIRECT_URI}`);

// Set up OAuth2 client
const oAuth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  REDIRECT_URI
);

// 📌 Basic phishing keyword list
const phishingKeywords = [
  'suspended', 'urgent', 'verify your account', 'click here',
  'free', 'reset your password', 'security alert', 'confirm',
  'login now', 'gift card', 'won', 'account locked'
];

// 🔎 Simple phishing detector
function isPhishing(subject, from) {
  subject = subject.toLowerCase();
  from = from.toLowerCase();

  return phishingKeywords.some(keyword =>
    subject.includes(keyword) || from.includes(keyword)
  );
}

// Route: Home page
app.get('/', (req, res) => {
  const authUrl = oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: [
      'openid',
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile',
      'https://www.googleapis.com/auth/gmail.readonly'
    ],
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
    console.error(`❌ OAuth error: ${error}`);
    return res.send(`❌ Access denied: ${error}`);
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
    let output = '<h2>Last 5 Emails</h2><ul>';

  for (let msg of messages) {
  const msgData = await gmail.users.messages.get({
    userId: 'me',
    id: msg.id,
    format: 'full',
  });

  const headers = msgData.data.payload.headers;
  const subject = headers.find(h => h.name === 'Subject')?.value || 'No Subject';
  const from = headers.find(h => h.name === 'From')?.value || 'Unknown Sender';

  let body = '';

  const parts = msgData.data.payload.parts;
  if (parts && parts.length) {
    const textPart = parts.find(part => part.mimeType === 'text/plain');
    if (textPart && textPart.body && textPart.body.data) {
      body = Buffer.from(textPart.body.data, 'base64').toString('utf8');
    }
  }

  output += `<li>
    <strong>From:</strong> ${from}<br/>
    <strong>Subject:</strong> ${subject}<br/>
    <strong>Body:</strong> <pre>${body.slice(0, 300)}...</pre>
  </li><br/>`;
  }
    }

    output += '</ul>';
    res.send(output);
  } catch (err) {
    console.error('❌ Error during OAuth flow:', err);
    res.send('Something went wrong during login.');
  }
});

// Start server
app.listen(port, '0.0.0.0', () => {
  console.log(`✅ Server running on http://0.0.0.0:${port}`);
});
