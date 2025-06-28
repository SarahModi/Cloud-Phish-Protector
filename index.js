const express = require('express');
const { google } = require('googleapis');
const axios = require('axios');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

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

app.get('/', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Phish Protector</title>
        <style>
          body { font-family: Arial; background: #f0f4f8; color: #222; padding: 30px; }
          h2 { color: #0a76d8; }
          form { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px #ccc; max-width: 400px; }
          select, button { padding: 8px; margin-top: 10px; width: 100%; }
          footer { margin-top: 50px; font-size: 14px; color: #666; }
        </style>
      </head>
      <body>
        <h2>🛡️ Phish Protector</h2>
        <form action="/auth">
          <label>Select Scan Mode:</label><br>
          <select name="mode">
            <option value="5">Quick Scan (Last 5 emails)</option>
            <option value="50">Thorough Scan (Last 50 emails)</option>
            <option value="all">Deep Scan (Entire inbox)</option>
          </select><br>
          <button type="submit">Login with Gmail</button>
        </form>
        <footer>Made with ❤️ by Sarah | Phish Protector v1.0</footer>
      </body>
    </html>
  `);
});

app.get('/auth', (req, res) => {
  const mode = req.query.mode || '5';
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

app.get('/oauth2callback', async (req, res) => {
  const code = req.query.code;
  const error = req.query.error;
  const mode = req.query.state;

  if (error) return res.send(`❌ Access denied: ${error}`);
  if (!code) return res.send('No auth code found.');

  try {
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);

    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });
    let maxResults = 5;
    if (mode === '50') maxResults = 50;
    if (mode === 'all') maxResults = 500;

    const response = await gmail.users.messages.list({
      userId: 'me',
      maxResults: maxResults,
    });

    const messages = response.data.messages || [];
    let output = `
      <html>
        <head>
          <style>
            body { font-family: Arial; padding: 30px; background: #fffbe6; color: #333; }
            li { margin-bottom: 15px; padding: 10px; background: #f9f9f9; border-left: 5px solid #ccc; border-radius: 5px; }
            .Safe { border-color: green; }
            .Suspicious { border-color: orange; }
            .Dangerous { border-color: red; }
          </style>
        </head>
        <body>
        <h2>🔍 Scan Result (${messages.length} emails)</h2>
        <ul>
    `;

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

      output += `<li class="${risk}">
        <strong>From:</strong> ${from}<br/>
        <strong>Subject:</strong> ${subject}<br/>
        <strong>Risk:</strong> <span style="color: ${risk === 'Dangerous' ? 'red' : risk === 'Suspicious' ? 'orange' : 'green'}">${risk}</span><br/>
        ${links.length ? `<strong>Links:</strong><br/> ${links.join('<br/>')}` : ''}
      </li>`;
    }

    output += '</ul><br/><a href="/">🔙 Scan again</a></body></html>';
    res.send(output);
  } catch (err) {
    console.error('❌ OAuth flow error:', err);
    res.send(`<p style="color:red;">Something went wrong. Please try again later.</p>`);
  }
});

app.listen(port, '0.0.0.0', () => {
  console.log(`🚀 Server running on http://0.0.0.0:${port}`);
});
