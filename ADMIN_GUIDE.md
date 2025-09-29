# Classification Commander - Administrator Guide

## Overview

Classification Commander provides secure control over digital signage displays showing classification banners in conference rooms and secure areas. The system supports RS232 serial and TCP/IP network-connected displays.

**Key Feature**: Uses only Python standard library - NO external dependencies required (except optional pyserial for RS232 support).

## User Roles

### Administrator
- **Full system control**: Add, edit, delete displays
- **User management**: Configure authentication credentials via web interface (development) or environment variables (production)
- **System monitoring**: View audit logs and classification change logs
- **Access to Admin Guide**: Built-in documentation viewer
- **Configuration management**: Manage display settings, images, and connection parameters

### Operator
- **Classification control only**: Change classification levels on existing displays
- **View status**: Monitor current display states
- **No administrative access**: Cannot modify system configuration, manage displays, or access admin features

## Admin Configuration Interface

Administrators have access to a dedicated admin configuration page (gear icon in top-right) with three tabs:

### 1. User Management Tab (Development Mode Only)
- **Web-based credential editing** for admin and operator accounts
- Change usernames and passwords through a simple form interface
- Automatically generates secure password hashes
- Changes saved to `credentials.json` file
- **Note**: Only available when `FLASK_ENV=development` is set

### 2. System Logs Tab
- **Real-time log viewer** for system monitoring
- View `audit.log` (authentication attempts, system events)
- View `classification_audit.log` (classification changes, display commands)
- Shows last 500 lines of each log file
- Refresh button to reload latest entries

### 3. Admin Guide Tab
- **Built-in documentation viewer** displaying this guide
- No need to access external files
- Always available reference material

## Authentication Management

### Development Mode (Recommended for Testing)

#### Method 1: Web-Based User Management
1. Set environment variable: `FLASK_ENV=development`
2. Log in as admin (default: username `admin`, password `admin`)
3. Click the gear icon (⚙️) in the top-right corner
4. Navigate to the **User Management** tab
5. Edit usernames and passwords for both admin and operator roles
6. Click **Update** to save changes
7. Changes are stored in `credentials.json` and take effect immediately

#### Method 2: Direct credentials.json File
Create or edit `credentials.json` in the application directory:
```json
{
  "admin": {
    "username": "admin",
    "password_hash": "pbkdf2_sha256:100000:salt:hash"
  },
  "operator": {
    "username": "operator",
    "password_hash": "pbkdf2_sha256:100000:salt:hash"
  }
}
```

**Default Development Credentials:**
- **Admin**: username `admin`, password `admin`
- **Operator**: username `operator`, password `operator`

⚠️ **Security Warning**: Development credentials are only active when `FLASK_ENV=development` is set.

### Production Deployment (Required for Production)

For production environments, credentials MUST be managed through secure environment variables. The web-based user management is **disabled** in production mode.

#### Required Environment Variables:
```bash
SECRET_KEY=your_secure_random_key_here
ADMIN_USERNAME=your_admin_username
ADMIN_PASSWORD_HASH=pbkdf2_sha256:100000:salt:hash
OPERATOR_USERNAME=your_operator_username  
OPERATOR_PASSWORD_HASH=pbkdf2_sha256:100000:salt:hash
```

#### Step 1: Generate Secure Password Hashes

**Generate hashes via command line:**
```bash
python -c "
from main import hash_password
print('Admin hash:', hash_password('your_secure_admin_password'))
print('Operator hash:', hash_password('your_secure_operator_password'))
"
```

**Or use the built-in API (admin access required):**
```bash
curl -X POST http://your-server:5000/api/generate-hash \
  -H "Content-Type: application/json" \
  -d '{"password": "your_secure_password"}'
```
⚠️ **Production Warning**: Disable or secure the `/api/generate-hash` endpoint in production

#### Step 2: Set Environment Variables

**Priority Order (credentials loading):**
1. Environment variables (always takes precedence)
2. `credentials.json` file (development mode only)
3. Default development credentials (development mode only)

**On Linux/Unix systems:**
```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD_HASH="pbkdf2_sha256:100000:generated_salt:generated_hash"
export OPERATOR_USERNAME="operator"
export OPERATOR_PASSWORD_HASH="pbkdf2_sha256:100000:generated_salt:generated_hash"
```

**On Windows systems:**
```cmd
set SECRET_KEY=your_generated_secret_key
set ADMIN_USERNAME=admin
set ADMIN_PASSWORD_HASH=pbkdf2_sha256:100000:generated_salt:generated_hash
set OPERATOR_USERNAME=operator
set OPERATOR_PASSWORD_HASH=pbkdf2_sha256:100000:generated_salt:generated_hash
```

**For systemd services**, create `/etc/systemd/system/classification-commander.service`:
```ini
[Unit]
Description=Classification Commander
After=network.target

[Service]
Type=simple
User=banneruser
WorkingDirectory=/opt/classification-commander
Environment=SECRET_KEY=your_secure_key
Environment=ADMIN_USERNAME=admin
Environment=ADMIN_PASSWORD_HASH=pbkdf2_sha256:100000:salt:hash
Environment=OPERATOR_USERNAME=operator
Environment=OPERATOR_PASSWORD_HASH=pbkdf2_sha256:100000:salt:hash
ExecStart=/usr/bin/python3 main.py
Restart=always

[Install]
WantedBy=multi-user.target
```

#### Step 3: Restart Application
```bash
# If using systemd
sudo systemctl restart classification-commander

# If running directly
# Stop current process and restart with environment variables set
```

## Display Management

### Adding a Display
1. Log in as administrator
2. Click the **+** (Add Display) button
3. Configure display settings:
   - **Display Name**: Unique identifier (e.g., "Conference Room A")
   - **Connection Type**: RS232 or TCP/IP
   - **Connection Details**: COM port or IP address
   - **Protocol**: Display manufacturer/model
4. Upload an optional room image for visual identification
5. Click **Add Display** to save

### Editing a Display
1. Click the pencil icon on the display card
2. Modify settings as needed
3. Save changes

### Deleting a Display
1. Click the trash icon on the display card
2. Confirm deletion

### Changing Classification Levels
**Both admin and operator users can:**
1. Select the desired classification level (radio buttons on display card)
2. System automatically sends command to display
3. Status updates in real-time

**Available Classifications:**
- Unclassified
- Classified
- Secret
- Top Secret

## Adding Additional Users

### Current System (2-User Model)
The current system supports exactly two users:
- One administrator account
- One operator account

### Expanding User Support

To add more users, modify the `get_credentials()` function in `main.py`:

```python
def get_credentials():
    # Example: Add support for multiple operators
    users = {}
    
    # Admin user
    admin_user = os.environ.get('ADMIN_USERNAME')
    admin_hash = os.environ.get('ADMIN_PASSWORD_HASH')
    if admin_user and admin_hash:
        users[admin_user] = {'password_hash': admin_hash, 'role': 'admin'}
    
    # Operator users (example: 3 operators)
    for i in range(1, 4):  # operators 1, 2, 3
        op_user = os.environ.get(f'OPERATOR_{i}_USERNAME')
        op_hash = os.environ.get(f'OPERATOR_{i}_PASSWORD_HASH')
        if op_user and op_hash:
            users[op_user] = {'password_hash': op_hash, 'role': 'operator'}
    
    return users
```

Then set additional environment variables:
```bash
export OPERATOR_1_USERNAME="operator1"
export OPERATOR_1_PASSWORD_HASH="pbkdf2_sha256:100000:salt:hash"
export OPERATOR_2_USERNAME="operator2"
export OPERATOR_2_PASSWORD_HASH="pbkdf2_sha256:100000:salt:hash"
```

## Security Best Practices

### Password Requirements
- **Minimum 12 characters**
- **Mix of uppercase, lowercase, numbers, symbols**
- **Unique per user**
- **Regular rotation (every 90 days recommended)**

### System Security
- **Never commit credentials to version control**
- **Use secure environment variable management**
- **Regular security audits via classification_audit.log**
- **Monitor failed login attempts in audit.log**
- **Use HTTPS in production**
- **Secure cookie flags**: HttpOnly, Secure, SameSite
- **Session Management**: Regular session invalidation and timeout
- **Disable development features**: Remove web-based user management and hash generation API in production

### NIST SP 800-53 IA-5(7) Compliance
✅ **No embedded static authenticators in source code**  
✅ **Environment-based credential management for production**  
✅ **Strong password hashing (PBKDF2-SHA256, 100,000 iterations)**  
✅ **Production enforcement of secure credentials**  
✅ **Development mode clearly separated with appropriate warnings**

## Configuration Files

### config.json
Stores display configurations, connection settings, and current classification states.
```json
{
  "displays": [
    {
      "name": "Conference Room A",
      "type": "rs232",
      "port": "/dev/ttyUSB0",
      "protocol": "samsung",
      "current_classification": "Unclassified",
      "image": "path/to/room/image.png"
    }
  ]
}
```

### credentials.json (Development Only)
Stores user credentials for development mode. **Never used in production.**
```json
{
  "admin": {
    "username": "admin",
    "password_hash": "pbkdf2_sha256:100000:salt:hash"
  },
  "operator": {
    "username": "operator",
    "password_hash": "pbkdf2_sha256:100000:salt:hash"
  }
}
```

## Troubleshooting

### Common Issues

**"FATAL: SECRET_KEY environment variable required"**
- Set `FLASK_ENV=development` for dev mode
- Or provide all required environment variables for production

**"Missing required authentication environment variables"**
- Ensure all variables are set: `SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD_HASH`, `OPERATOR_USERNAME`, `OPERATOR_PASSWORD_HASH`
- In production, environment variables are mandatory

**"User management only available in development mode"**
- Web-based user management is disabled in production
- Use environment variables for production credential management

**"Login fails with correct credentials"**
- Verify password hash format: `pbkdf2_sha256:100000:salt:hash`
- Check for extra spaces/characters in environment variables
- Regenerate hash if needed
- Check `credentials.json` in development mode

**"Admin functions not visible"**
- Confirm login with admin role account
- Check session data and role assignment
- Verify gear icon appears in top-right corner (admin only)

**Display not responding to commands**
- Verify connection settings (COM port or IP address)
- Check display protocol matches manufacturer
- Review `classification_audit.log` for command details
- Test connection using admin interface

### Log Files
- **Application logs**: `audit.log` - Authentication attempts, errors, system events
- **Classification changes**: `classification_audit.log` - All classification commands and display responses
- **System startup**: Console output showing mode (development/production) and configuration status

### Viewing Logs
1. Log in as administrator
2. Click gear icon (⚙️) to open admin configuration
3. Navigate to **System Logs** tab
4. Select log type (Audit or Classification)
5. Click **Refresh** to reload latest entries

## Support and Maintenance

### Regular Tasks
1. **Review audit logs** monthly for security monitoring
2. **Update passwords** quarterly following security policy
3. **Verify display connections** weekly to ensure proper operation
4. **Check system logs** daily for errors or issues
5. **Test failover procedures** annually
6. **Backup configuration files** regularly (`config.json`, `credentials.json` if used)

### System Updates
When updating the system:
1. **Backup configuration files** (`config.json`, `credentials.json`)
2. **Test in development environment** with `FLASK_ENV=development`
3. **Verify all displays respond correctly** after update
4. **Review logs** for any errors or warnings
5. **Update documentation** as needed

### File Structure
```
classification-commander/
├── main.py                      # Main application
├── config.json                  # Display configurations
├── credentials.json             # Development credentials (optional)
├── audit.log                    # System audit log
├── classification_audit.log     # Classification change log
├── ADMIN_GUIDE.md              # This guide
├── templates/
│   ├── index.html              # Main control interface
│   ├── login.html              # Login page
│   └── admin_config.html       # Admin configuration page
└── static/
    ├── background.png          # Login background
    ├── icons/                  # UI icons
    └── uploads/                # Uploaded room images

```

---

**For technical support or security questions, contact your system administrator.**
