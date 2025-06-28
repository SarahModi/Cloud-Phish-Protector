// Updated index.js - Phase 2 (Extract links from email body)

const express = require('express');
const { google } = require('googleapis');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

if (!process.env.CLIENT_ID || !process.env.CLIENT_SECRET) {
  console.error('\n❌ Missing CLIENT_ID or CLIENT_SECRET in Secrets!');
  process.exit(1);
}

const REDIRECT_URI = "https://cloud-phish-protector.onrender.com/oauth2callback";
console.log(`🔁 Using redirect URI: ${REDIRECT_URI}`);

const oAuth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  REDIRECT_URI
);

const phishingKeywords = [
  'suspended', 'urgent', 'verify your account', 'click here',
  'free', 'reset your password', 'security alert', 'confirm',
  'login now', 'gift card', 'won', 'account locked'
];

function extractLinks(text) {
  const linkRegex = /(https?:\/\/[^\s]+)/g;
  return text.match(linkRegex) || [];
}

function isPhishing(subject, from, links) {
  subject = subject.toLowerCase();
  from = from.toLowerCase();

  const keywordHit = phishingKeywords.some(keyword =>
    subject.includes(keyword) || from.includes(keyword)
  );

  const suspiciousLinks = links.length > 0;

  if (keywordHit && suspiciousLinks) return 'Dangerous';
  if (keywordHit || suspiciousLinks) return 'Suspicious';
  return 'Safe';
}

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

app.get('/oauth2callback', async (req, res) => {
  const code = req.query.code;
  const error = req.query.error;

  if (error) return res.send(`Access denied: ${error}`);
  if (!code) return res.send('No auth code found. Something went wrong.');

  try {
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);

    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });
    const response = await gmail.users.messages.list({ userId: 'me', maxResults: 5 });
    const messages = response.data.messages || [];

    let output = '<h2>Last 5 Emails (Phishing Status)</h2><ul>';

    for (let msg of messages) {
      const msgData = await gmail.users.messages.get({
        userId: 'me',
        id: msg.id,
        format: 'full'
      });

      const headers = msgData.data.payload.headers;
      const subject = headers.find(h => h.name === 'Subject')?.value || 'No Subject';
      const from = headers.find(h => h.name === 'From')?.value || 'Unknown Sender';

      let body = '';
      const parts = msgData.data.payload.parts;
      if (parts && parts.length) {
        const textPart = parts.find(p => p.mimeType === 'text/plain');
        if (textPart?.body?.data) {
          body = Buffer.from(textPart.body.data, 'base64').toString('utf8');
        }
      }

      const links = extractLinks(body);
      const verdict = isPhishing(subject, from, links);

      output += `<li>
        <strong>From:</strong> ${from}<br/>
        <strong>Subject:</strong> ${subject}<br/>
        <strong>Status:</strong> ${verdict}<br/>
        <strong>Links:</strong> <pre>${links.join('\n') || 'None'}</pre>
      </li><br/>`;
    }

    output += '</ul>';
    res.send(output);
  } catch (err) {
    console.error('❌ Error during OAuth flow:', err);
    res.send('Something went wrong during login.');
  }
});

app.listen(port, '0.0.0.0', () => {
  console.log(`✅ Server running on http://0.0.0.0:${port}`);
});
