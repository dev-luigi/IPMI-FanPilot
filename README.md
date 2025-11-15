# Dell R720 IPMI Fan Control

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

    git clone https://github.com/dev-luigi/dell-r720-fan-control.git
    cd dell-r720-fan-control

### Step 4: Install Project Dependencies

Install all required Node.js packages listed in package.json:

    npm install

This will create a node_modules folder containing Express.js and all other dependencies.

---

## Configuration

Create a file named credenziali.json in the root directory (same folder as server.js) with your IPMI credentials:

    {
      "ip": "192.168.x.x",
      "username": "root",
      "password": "calvin"
    }

Alternatively, use the web interface to save credentials by entering them in the Connection Settings section and clicking the green "Save" button.

---

## Running the Application

### Using the Batch File (Windows)

Simply double-click the avvia.bat file. The script will automatically:
- Request administrator privileges
- Install dependencies if needed
- Start the Node.js server
- Open the web interface

    avvia.bat

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
3. Click the green "Save" button to store credentials locally
4. Use the dial to adjust fan speed from 0-100%
5. Click "Confirm" to apply manual speed settings
6. Click "Auto Mode" to let the server control fans automatically
7. View command history at the bottom to verify execution

---

## Project Structure

    dell-r720-fan-control/
    ├── server.js              Main Node.js application
    ├── package.json           Project dependencies
    ├── avvia.bat             Windows startup script
    ├── credenziali.json      Saved credentials (created after first save)
    ├── public/
    │   └── index.html        Web interface
    └── README.md             This file

---

## Available Endpoints

The application provides the following API endpoints:

- POST /api/execute - Execute IPMI fan commands
- POST /api/credentials/save - Save connection credentials
- GET /api/credentials/load - Load saved credentials
- DELETE /api/credentials/clear - Delete saved credentials
- GET /api/health - Server health check

---

## Troubleshooting

If the application doesn't start:
- Ensure Node.js is installed: node --version
- Verify npm is installed: npm --version
- Check that ipmitool is in PATH: ipmitool -V
- Run avvia.bat as administrator
- Check Windows Firewall settings

If credentials won't save:
- Ensure the application has write permissions in the folder
- Verify all three fields (IP, username, password) are filled
- Check browser console for error messages

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

## Author

Luigi Tanzillo
GitHub: https://github.com/dev-luigi

---

## License

MIT License