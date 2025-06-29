const express = require('express');
const { google } = require('googleapis');
const axios = require('axios');
require('dotenv').config();
const path = require('path');

const app = express();
const port = process.env.PORT || 5000;

// Serve static files from "public"
app.use(express.static(path.join(__dirname, 'public')));

// Check env vars
if (!process.env.CLIENT_ID || !process.env.CLIENT_SECRET || !process.env.VIRUSTOTAL_API_KEY) {
  console.error('❌ Missing CLIENT_ID, CLIENT_SECRET, or VIRUSTOTAL_API_KEY!');
  process.exit(1);
}

const REDIRECT_URI = "https://cloud-phish-protector.onrender.com/oauth2callback";
console.log(`✅ Using redirect URI: ${REDIRECT_URI}`);

const oAuth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  REDIRECT_URI
);

// Keywords for phishing detection
const phishingKeywords = [
  'suspended', 'urgent', 'verify your account', 'click here',
  'free', 'reset your password', 'security alert', 'confirm',
  'login now', 'gift card', 'won', 'account locked'
];

function isPhishing(subject, from, body) {
  const content = (subject + ' ' + from + ' ' + body).toLowerCase();
  return phishingKeywords.some(keyword => content.includes(keyword));
}

async function checkLinkSafety(link) {
  try {
    const response = await axios.get(`https://www.virustotal.com/api/v3/urls`, {
      headers: {
        'x-apikey': process.env.VIRUSTOTAL_API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      data: `url=${link}`,
      method: 'POST'
    });

    const urlId = response.data.data.id;
    const analysis = await axios.get(`https://www.virustotal.com/api/v3/analyses/${urlId}`, {
      headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
    });

    const stats = analysis.data.data.attributes.stats;
    return stats.malicious > 0 ? 'Dangerous' : stats.suspicious > 0 ? 'Suspicious' : 'Safe';
  } catch (error) {
    console.error('⚠️ VirusTotal error:', error.message);
    return 'Unknown';
  }
}

// ✅ Serve landing page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ✅ Google OAuth login
app.get('/auth', (req, res) => {
  const mode = req.query.mode || 'inbox'; // default to inbox scan
  const authUrl = oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: [
      'openid',
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile',
      'https://www.googleapis.com/auth/gmail.readonly'
    ],
    state: mode
  });
  res.redirect(authUrl);
});

// ✅ After login, redirect to landing page
app.get('/oauth2callback', async (req, res) => {
  const code = req.query.code;
  const error = req.query.error;
  const mode = req.query.state;

  if (error) return res.send(`❌ Access denied: ${error}`);
  if (!code) return res.send('No auth code found.');

  try {
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);
    res.redirect(`/index.html?loggedin=true&mode=${mode}`);
  } catch (err) {
    console.error('❌ OAuth error:', err);
    res.send(`<p style="color:red;">Something went wrong during login. Try again.</p>`);
  }
});

// ✅ Scanning route (fetches emails based on mode)
app.get('/scan', async (req, res) => {
  const mode = req.query.mode || 'inbox';

  let maxResults = 5;
  if (mode === 'inbox') maxResults = 50;
  else if (mode === 'junk') maxResults = 30;
  else if (mode === 'archive') maxResults = 100;

  try {
    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });
    const response = await gmail.users.messages.list({
      userId: 'me',
      maxResults
    });

    const messages = response.data.messages || [];
    const results = [];

    for (const msg of messages) {
      const msgData = await gmail.users.messages.get({
        userId: 'me',
        id: msg.id,
        format: 'full',
      });

      const headers = msgData.data.payload.headers;
      const subject = headers.find(h => h.name === 'Subject')?.value || 'No Subject';
      const from = headers.find(h => h.name === 'From')?.value || 'Unknown Sender';

      let body = '', links = [], risk = 'Safe';
      const parts = msgData.data.payload.parts || [];
      const textPart = parts.find(p => p.mimeType === 'text/plain');
      if (textPart?.body?.data) {
        body = Buffer.from(textPart.body.data, 'base64').toString('utf8');
        const linkRegex = /https?:\/\/[\w.-]+(?:\/[\w._~:/?#\[\]@!$&'()*+,;=-]*)?/gi;
        links = body.match(linkRegex) || [];
        for (const link of links) {
          const verdict = await checkLinkSafety(link);
          if (verdict === 'Dangerous') {
            risk = 'Dangerous'; break;
          } else if (verdict === 'Suspicious' && risk !== 'Dangerous') {
            risk = 'Suspicious';
          }
        }
      }

      if (isPhishing(subject, from, body)) {
        risk = risk === 'Safe' ? 'Suspicious' : risk;
      }

      results.push({ from, subject, riskLevel: risk, links });
    }

    res.json(results);
  } catch (err) {
    console.error('❌ Scan error:', err);
    res.status(500).json({ error: 'Scan failed' });
  }
});

app.listen(port, '0.0.0.0', () => {
  console.log(`🚀 Server running on http://0.0.0.0:${port}`);
});
