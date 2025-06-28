const express = require('express');
const { google } = require('googleapis');
const axios = require('axios');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

if (!process.env.CLIENT_ID || !process.env.CLIENT_SECRET || !process.env.VIRUSTOTAL_API_KEY) {
  console.error('Missing CLIENT_ID, CLIENT_SECRET, or VIRUSTOTAL_API_KEY in Secrets!');
  process.exit(1);
}

const REDIRECT_URI = "https://cloud-phish-protector.onrender.com/oauth2callback";
console.log(`Using redirect URI: ${REDIRECT_URI}`);

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
    console.error('VirusTotal error:', error.message);
    return 'Unknown';
  }
}

app.get('/', (req, res) => {
  res.send(`
    <h2>Phish Protector</h2>
    <form action="/auth">
      <label>Select Scan Mode:</label><br>
      <select name="mode">
        <option value="5">Quick Scan (Last 5 emails)</option>
        <option value="50">Thorough Scan (Last 50 emails)</option>
        <option value="all">Deep Scan (Entire inbox)</option>
      </select><br><br>
      <button type="submit">Login with Gmail</button>
    </form>
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

  if (error) return res.send(`Access denied: ${error}`);
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
    let output = `<h2>Scanned ${messages.length} Emails</h2><ul>`;

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

      output += `<li>
        <strong>From:</strong> ${from}<br/>
        <strong>Subject:</strong> ${subject}<br/>
        <strong>Risk:</strong> <span style="color: ${risk === 'Dangerous' ? 'red' : risk === 'Suspicious' ? 'orange' : 'green'}">${risk}</span><br/>
        ${links.length ? `<strong>Links:</strong> ${links.join('<br/>')}` : ''}
      </li><br/>`;
    }

    output += '</ul>';
    res.send(output);
  } catch (err) {
    console.error('Error during OAuth flow:', err);
    res.send('Something went wrong during login.');
  }
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${port}`);
});
