const express = require('express');
const { google } = require('googleapis');
const axios = require('axios');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

if (!process.env.CLIENT_ID || !process.env.CLIENT_SECRET || !process.env.VIRUSTOTAL_API_KEY) {
  console.error('\n❌ Missing CLIENT_ID, CLIENT_SECRET, or VIRUSTOTAL_API_KEY in Secrets!');
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

function isPhishing(subject, from, body, linkResults) {
  subject = subject.toLowerCase();
  from = from.toLowerCase();
  body = body.toLowerCase();

  const keywordMatch = phishingKeywords.some(keyword =>
    subject.includes(keyword) || from.includes(keyword) || body.includes(keyword)
  );

  const hasMaliciousLink = linkResults.some(result => result.status === 'malicious');

  if (hasMaliciousLink) return '❌ Dangerous';
  if (keywordMatch) return '⚠️ Suspicious';
  return '✅ Safe';
}

function extractLinks(text) {
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  return text.match(urlRegex) || [];
}

async function checkLinkWithVirusTotal(link) {
  try {
    const url = `https://www.virustotal.com/api/v3/urls`;
    const encodedLink = Buffer.from(link).toString('base64').replace(/=+$/, '');
    const reportUrl = `https://www.virustotal.com/api/v3/urls/${encodedLink}`;

    const headers = { 'x-apikey': process.env.VIRUSTOTAL_API_KEY };
    const response = await axios.get(reportUrl, { headers });

    const stats = response.data.data.attributes.last_analysis_stats;
    return stats.malicious > 0 ? 'malicious' : 'clean';
  } catch (error) {
    console.error('❌ VirusTotal error:', error.message);
    return 'unknown';
  }
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

      const links = extractLinks(body);
      const linkResults = [];

      for (let link of links) {
        const status = await checkLinkWithVirusTotal(link);
        linkResults.push({ link, status });
      }

      const verdict = isPhishing(subject, from, body, linkResults);

      output += `<li>
        <strong>From:</strong> ${from}<br/>
        <strong>Subject:</strong> ${subject}<br/>
        <strong>Verdict:</strong> ${verdict}<br/>
        <strong>Body:</strong> <pre>${body.slice(0, 300)}...</pre><br/>
        <strong>Links:</strong> <ul>`;
      for (let result of linkResults) {
        output += `<li>${result.link} - ${result.status}</li>`;
      }
      output += '</ul></li><br/>';
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
