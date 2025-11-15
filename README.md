# IPMI-FanPilot

A simple and effective IPMI fan controller for servers. Simply enter your server's IP, username, and password, then tweak the fan speed or set it to automatic mode. Save your credentials securely and adjust settings anytime through a clean web interface. It's a simple and handy tool to keep your servers cool and quiet.

---

## Requirements

This application requires the following components to run properly:

- Node.js 14.0 or higher
- npm (Node Package Manager)
- ipmitool installed and accessible on Windows PATH
- A server with IPMI interface enabled (Dell, HP, Lenovo, Supermicro, IBM)

---

## Installation

### Step 1: Install Node.js

Download and install Node.js from https://nodejs.org/ (LTS version recommended). This will automatically include npm.

### Step 2: Install ipmitool

Download ipmitool for Windows and add it to your system PATH so it can be executed from any directory. Ensure the command works by opening Command Prompt and running:

    ipmitool -V

If the command is not recognized, add the ipmitool installation folder to your Windows PATH environment variable.

### Step 3: Clone or Download the Repository

Navigate to where you want to install the application and clone the repository or download the files.

    git clone https://github.com/dev-luigi/IPMI-FanPilot.git
    cd IPMI-FanPilot

### Step 4: Install Project Dependencies

Install all required Node.js packages listed in package.json:

    npm install

This will create a node_modules folder containing Express.js and all other dependencies.

---

## Configuration

Create a file named credentials.json in the root directory (same folder as server.js) with your IPMI credentials:

    {
      "ip": "192.168.x.x",
      "username": "root",
      "password": "calvin"
    }

Alternatively, use the web interface to save credentials by entering them in the Connection Settings section and clicking the green "Save" button. Credentials are automatically encrypted with AES-256 encryption.

---

## Running the Application

### Using the Start Script (Windows - Recommended)

Simply double-click the start.bat file. The script will automatically:
- Request administrator privileges
- Install dependencies if needed
- Start the Node.js server
- Display any errors if they occur

    start.bat

The batch file will remain open and show output, making it easy to diagnose any issues.

### Using Command Prompt or PowerShell

Navigate to the application folder and run:

    node server.js

The server will start on port 3000. Open your browser and go to:

    http://localhost:3000

---

## Usage

1. Open the application in your web browser at http://localhost:3000
2. Enter your server IPMI credentials:
   - IP iDRAC: The IP address of your server management interface
   - Username: IPMI username (usually 'root')
   - Password: IPMI password
3. Click the green "Save" button to store credentials locally (encrypted)
4. Use the dial to adjust fan speed from 0-100%
5. Click "Confirm" to apply manual speed settings
6. Click "Auto Mode" to let the server control fans automatically
7. View command history at the bottom to verify execution
8. Click the red "Clear" button to delete saved credentials

---

## Project Structure

    IPMI-FanPilot/
    ├── server.js              Main Node.js application
    ├── package.json           Project dependencies
    ├── start.bat              Windows startup script
    ├── credentials.json       Saved credentials (created after first save, encrypted)
    ├── public/
    │   └── index.html         Web interface
    ├── README.md              This file
    └── LICENSE                MIT or Apache-2.0 license

---

## Available Endpoints

The application provides the following API endpoints:

- POST /api/execute - Execute IPMI fan commands (manual or auto mode)
- POST /api/credentials/save - Save connection credentials (encrypted)
- GET /api/credentials/load - Load saved credentials (decrypted)
- DELETE /api/credentials/clear - Delete saved credentials
- GET /api/health - Server health check

---

## Security Features

- Credentials are encrypted using AES-256-CBC encryption
- No plain text credentials stored on disk
- Unique IV (Initialization Vector) for each encryption operation
- Input validation to prevent IPMI command injection
- IPMI commands are executed through PowerShell for better security

---

## Troubleshooting

### Application won't start

- Ensure Node.js is installed: `node --version`
- Verify npm is installed: `npm --version`
- Check that ipmitool is in PATH: `ipmitool -V`
- Run start.bat as administrator
- Check Windows Firewall settings
- Verify port 3000 is not in use: `netstat -ano | findstr :3000`

### Credentials won't save

- Ensure the application has write permissions in the folder
- Verify all three fields (IP, username, password) are filled
- Check browser console for error messages (F12)
- Verify disk space is available

### IPMI commands fail

- Verify server IPMI is enabled and network accessible
- Test connectivity: `ping 192.168.x.x` (replace with your IPMI IP)
- Verify credentials are correct
- Check server logs for IPMI errors
- Ensure ipmitool supports your server model

### Port 3000 already in use

Find and kill the process using port 3000:

    netstat -ano | findstr :3000
    taskkill /PID <PID> /F

Or change the PORT variable in server.js.

---

## Supported Servers

This application works with any server that supports IPMI 2.0 including:

- Dell PowerEdge (all models with iDRAC)
- Supermicro (all models with IPMI BMC)
- HP ProLiant (with ILO)
- Lenovo ThinkSystem (with XCC)
- IBM System X (with IMM)

Ensure IPMI is enabled and accessible on your network.

---

## Features

- Web-based dashboard with intuitive fan speed dial
- Manual fan speed control (0-100%)
- Automatic mode (server manages fan speed)
- Preset speed buttons (20%, 30%, 50%, 70%, 100%)
- Secure credential storage (AES-256 encryption)
- Save/load/clear credentials
- Command history log
- Real-time status messages
- Responsive design for desktop and tablet
- Error handling with clear messages
- Administrator privilege detection

---

## Future Enhancements

Potential features for future releases:

- Multi-server management
- Temperature monitoring and graphs
- Scheduled fan control
- Email notifications
- User authentication
- API key management
- Mobile app

---

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

To contribute:
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

---

## Author

Luigi Tanzillo  
GitHub: https://github.com/dev-luigi  
Portfolio: https://luigi-tanzillo.42web.io  

---

## License

This project is licensed under the MIT License or Apache License 2.0. See the LICENSE file for details.

---

## Disclaimer

This tool is provided as-is for managing IPMI-enabled servers. Use at your own risk. Always test in a non-production environment first. Improper fan control can damage hardware or void warranties. The author is not responsible for any damage caused by misuse of this application.

---

## Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing documentation
- Review server logs for errors