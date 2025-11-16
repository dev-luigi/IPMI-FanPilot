const express = require('express');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

// Percorso della cartella corrente (dove è il server.js)
const APP_DIR = __dirname;
const PUBLIC_DIR = path.join(APP_DIR, 'public');
const INDEX_FILE = path.join(PUBLIC_DIR, 'index.html');
const CREDENTIALS_FILE = path.join(APP_DIR, 'credentials.json');

// Chiave di crittografia (generata dalla prima esecuzione)
const ENCRYPTION_KEY = crypto.scryptSync('ipmi-fanpilot-encryption-key', 'salt', 32);
const IV_LENGTH = 16;

// Rileva se siamo su Windows o Linux
const isWindows = os.platform() === 'win32';

console.log('');
console.log('========================================');
console.log('IPMI-FanPilot Server');
console.log('========================================');
console.log('Application folder:', APP_DIR);
console.log('Operating system:', os.platform());
console.log('Platform:', isWindows ? 'Windows' : 'Linux/Docker');
console.log('========================================');
console.log('');

// Middleware
app.use(express.json());

// Serve file statici dalla cartella public
app.use(express.static(PUBLIC_DIR));

function validateInput(str) {
  return str.replace(/[;&|`$(){}[\]<>\n\r]/g, '');
}

function validateIP(ip) {
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipRegex.test(ip)) return false;
  const parts = ip.split('.');
  return parts.every(part => parseInt(part) >= 0 && parseInt(part) <= 255);
}

function encryptCredentials(credentials) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(credentials), 'utf8'), cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decryptCredentials(encryptedData) {
  const parts = encryptedData.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encryptedText = Buffer.from(parts[1], 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
  return JSON.parse(decrypted.toString('utf8'));
}

function executeIpmitool(args) {
  return new Promise((resolve, reject) => {
    console.log('Executing ipmitool with args:', args.join(' '));
    
    let proc;
    
    if (isWindows) {
      // Windows: usa PowerShell
      const cmdString = `ipmitool ${args.join(' ')}`;
      proc = spawn('powershell.exe', [
        '-NoProfile',
        '-Command',
        cmdString
      ], {
        stdio: ['pipe', 'pipe', 'pipe'],
        shell: false
      });
    } else {
      // Linux/Docker: usa ipmitool direttamente
      proc = spawn('ipmitool', args, {
        stdio: ['pipe', 'pipe', 'pipe']
      });
    }

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (data) => {
      stdout += data.toString();
      console.log('STDOUT:', data.toString());
    });

    proc.stderr.on('data', (data) => {
      stderr += data.toString();
      console.log('STDERR:', data.toString());
    });

    proc.on('close', (code) => {
      console.log('Process closed with code:', code);
      if (code === 0) {
        resolve(stdout);
      } else {
        reject(new Error(stderr || `Command exited with code ${code}`));
      }
    });

    proc.on('error', (err) => {
      console.log('Process error:', err.message);
      reject(err);
    });
  });
}

// ENDPOINT: Save credentials (encrypted)
app.post('/api/credentials/save', (req, res) => {
  try {
    const { ip, username, password } = req.body;
    if (!ip || !username || !password) {
      return res.json({ success: false, error: 'Missing parameters' });
    }

    const credentials = { ip, username, password };
    const encrypted = encryptCredentials(credentials);
    fs.writeFileSync(CREDENTIALS_FILE, encrypted, 'utf-8');
    console.log('Credentials saved (encrypted):', CREDENTIALS_FILE);
    res.json({ success: true, message: 'Credentials saved successfully' });
  } catch (error) {
    console.error('Error saving credentials:', error);
    res.json({ success: false, error: error.message });
  }
});

// ENDPOINT: Load credentials (decrypted)
app.get('/api/credentials/load', (req, res) => {
  try {
    if (fs.existsSync(CREDENTIALS_FILE)) {
      const encryptedData = fs.readFileSync(CREDENTIALS_FILE, 'utf-8');
      const credentials = decryptCredentials(encryptedData);
      console.log('Credentials loaded (decrypted)');
      res.json({ success: true, credentials });
    } else {
      console.log('No credentials file found');
      res.json({ success: false, message: 'No credentials found' });
    }
  } catch (error) {
    console.error('Error loading credentials:', error);
    res.json({ success: false, error: error.message });
  }
});

// ENDPOINT: Delete credentials
app.delete('/api/credentials/clear', (req, res) => {
  try {
    if (fs.existsSync(CREDENTIALS_FILE)) {
      fs.unlinkSync(CREDENTIALS_FILE);
      console.log('Credentials deleted');
      res.json({ success: true, message: 'Credentials cleared successfully' });
    } else {
      res.json({ success: false, message: 'No credentials to clear' });
    }
  } catch (error) {
    console.error('Error clearing credentials:', error);
    res.json({ success: false, error: error.message });
  }
});

app.post('/api/execute', async (req, res) => {
  try {
    const { ip, username, password, mode, speed } = req.body;
    console.log('API call received:', { ip, username, mode, speed });

    if (!ip || !username || !password) {
      return res.json({ success: false, error: 'Missing parameters' });
    }

    if (!validateIP(ip)) {
      return res.json({ success: false, error: 'Invalid IP format' });
    }

    const safeIP = validateInput(ip);
    const safeUsername = validateInput(username);
    const safePassword = validateInput(password);

    try {
      if (mode === 'auto') {
        console.log('Setting automatic mode...');
        const args = [
          '-I', 'lanplus',
          '-H', safeIP,
          '-U', safeUsername,
          '-P', safePassword,
          'raw', '0x30', '0x30', '0x01', '0x01'
        ];

        await executeIpmitool(args);
        return res.json({
          success: true,
          message: 'Auto mode activated'
        });
      } else {
        const speedValue = Math.max(0, Math.min(100, parseInt(speed) || 20));
        const hexValue = '0x' + speedValue.toString(16).padStart(2, '0').toUpperCase();
        console.log(`Setting manual mode to ${speedValue}% (${hexValue})...`);

        // First command: enable manual control
        console.log('Step 1: Enable manual control');
        const args1 = [
          '-I', 'lanplus',
          '-H', safeIP,
          '-U', safeUsername,
          '-P', safePassword,
          'raw', '0x30', '0x30', '0x01', '0x00'
        ];

        await executeIpmitool(args1);
        console.log('Step 1 completed');

        // Wait a bit between commands
        await new Promise(resolve => setTimeout(resolve, 500));

        // Second command: set fan speed
        console.log('Step 2: Set fan speed');
        const args2 = [
          '-I', 'lanplus',
          '-H', safeIP,
          '-U', safeUsername,
          '-P', safePassword,
          'raw', '0x30', '0x30', '0x02', '0xff',
          hexValue
        ];

        await executeIpmitool(args2);
        console.log('Step 2 completed');

        return res.json({
          success: true,
          message: `Speed set to ${speedValue}%`
        });
      }
    } catch (err) {
      console.error('IPMI Error:', err.message);
      return res.json({
        success: false,
        error: err.message || 'Error executing IPMI command'
      });
    }
  } catch (error) {
    console.error('Server Error:', error.message);
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/health', (req, res) => {
  console.log('Health check requested');
  res.json({
    status: 'ok',
    message: 'Server running',
    time: new Date().toISOString()
  });
});

// Root route - serve index.html
app.get('/', (req, res) => {
  console.log('Root request - serving index.html');
  if (fs.existsSync(INDEX_FILE)) {
    res.sendFile(INDEX_FILE);
  } else {
    res.status(404).json({
      error: 'index.html not found',
      path: INDEX_FILE
    });
  }
});

// 404 error handling
app.use((req, res) => {
  console.log('404 - Not found:', req.path);
  res.status(404).json({
    error: 'Resource not found',
    path: req.path
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('========================================');
  console.log('SERVER STARTED SUCCESSFULLY');
  console.log('========================================');
  console.log(`Access at: http://localhost:${PORT}`);
  console.log(`or: http://127.0.0.1:${PORT}`);
  console.log('');
  if (isWindows) {
    console.log('IMPORTANT: Run the server as Administrator');
  } else {
    console.log('IMPORTANT: Ensure ipmitool is installed (apt-get install ipmitool)');
  }
  console.log('');
  console.log('Press Ctrl+C to stop the server');
  console.log('========================================');
  console.log('');
});