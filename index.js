const express = require('express');
const { google } = require('googleapis');
const dotenv = require('dotenv');
const axios = require('axios');

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// Check for required secrets
if (!process.env.CLIENT_ID || !process.env.CLIENT_SECRET || !process.env.VIRUSTOTAL_API_KEY) {
  console.error('\n❌ Missing CLIENT_ID, CLIENT_SECRET, or VIRUSTOTAL_API_KEY in Secrets!');
  process.exit(1);
}

const REDIRECT_URI = "https://cloud-phish-protector.onrender.com/oauth2callback";
console.log(`🔁 Using redirect URI: ${REDIRECT_URI}`);

// OAuth client setup
const oAuth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  REDIRECT_URI
);

// Function to extract links from email body
function extractLinks(text) {
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  return text.match(urlRegex) || [];
}

// Check each link using VirusTotal
async function checkLinksWithVirusTotal(links) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  const verdicts = [];

  for (let link of links) {
    try {
      // Step 1: Submit the URL
      const scanResp = await axios.post('https://www.virustotal.com/api/v3/urls', 
        new URLSearchParams({ url: link }).toString(),
        {
          headers: {
            'x-apikey': apiKey,
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );

      const scanId = scanResp.data.data.id;

      // Step 2: Get the scan report
      const reportResp = await axios.get(`https://www.virustotal.com/api/v3/analyses/${scanId}`, {
        headers: { 'x-apikey': apiKey }
      });

      const malicious = reportResp.data.data.attributes.stats.malicious;
      const suspicious = reportResp.data.data.attributes.stats.suspicious;

      if (malicious > 0) {
        verdicts.push({ link, verdict: '❌ Dangerous' });
      } else if (suspicious > 0) {
        verdicts.push({ link, verdict: '⚠️ Suspicious' });
      } else {
        verdicts.push({ link, verdict: '✅ Safe' });
      }

    } catch (err) {
      console.error(`🛑 Error checking link ${link}:`, err.message);
      verdicts.push({ link, verdict: '❓ Unknown (Error)' });
    }
  }

  return verdicts;
}

// Home route
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

// OAuth callback
app.get('/oauth2callback', async (req, res) => {
  const code = req.query.code;
  const error = req.query.error;

  if (error) return res.send(`❌ Access denied: ${error}`);
  if (!code) return res.send('No auth code found.');

  try {
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);

    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });
    const response = await gmail.users.messages.list({
      userId: 'me',
      maxResults: 3,
    });

    const messages = response.data.messages || [];
    let output = '<h2>Last 3 Emails & Risk Check</h2><ul>';

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
      const verdicts = await checkLinksWithVirusTotal(links);

      output += `<li>
        <strong>From:</strong> ${from}<br/>
        <strong>Subject:</strong> ${subject}<br/>
        <strong>Body:</strong> <pre>${body.slice(0, 300)}...</pre>
        <strong>Links:</strong><ul>
          ${verdicts.map(v => `<li>${v.link} — ${v.verdict}</li>`).join('')}
        </ul>
      </li><br/>`;
    }

    output += '</ul>';
    res.send(output);

  } catch (err) {
    console.error('❌ Error during OAuth flow:', err.message);
    res.send('Something went wrong during login.');
  }
});

// Start server
app.listen(port, '0.0.0.0', () => {
  console.log(`✅ Server running on http://0.0.0.0:${port}`);
});
