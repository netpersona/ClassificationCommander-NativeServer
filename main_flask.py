#!/usr/bin/env python3
"""
Classification Commander
Controls multiple displays to show classification banners (Unclassified, Secret, Top Secret)
"""

import os
import json
import socket
import serial
import logging
import hashlib
import secrets
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, send_from_directory
from werkzeug.utils import secure_filename
from pathlib import Path

# Configure logging first (needed for authentication checks)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('audit.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# NIST SP 800-53 IA-5(7) Compliance: No embedded static authenticators
# SECRET_KEY must be provided via environment variable
secret_key = os.environ.get('SECRET_KEY')
flask_env = os.environ.get('FLASK_ENV', 'production').lower()

if not secret_key:
    if flask_env == 'development' or flask_env == 'dev':
        # Generate secure random key for development only
        import secrets
        secret_key = secrets.token_hex(32)
        logger.warning("Using generated SECRET_KEY for development - set SECRET_KEY environment variable for production")
    else:
        logger.error("FATAL: SECRET_KEY environment variable required for production")
        logger.error("Set FLASK_ENV=development for development mode")
        exit(1)

app.secret_key = secret_key

# Configure upload settings
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
Path(UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# NIST SP 800-53 IA-5(7) Compliance: No embedded static authenticators
# Credentials must be provided via environment variables
def get_credentials():
    """
    Load credentials from environment variables to comply with NIST SP 800-53 IA-5(7)
    In development mode, also checks credentials.json for web-managed credentials.
    
    Priority order:
    1. Environment variables (always takes precedence)
    2. credentials.json (development mode only)
    3. Default dev credentials (development mode only)
    
    Required environment variables:
    - ADMIN_USERNAME: Administrator username
    - ADMIN_PASSWORD_HASH: PBKDF2-SHA256 hash (format: pbkdf2_sha256:100000:salt:hash)
    - OPERATOR_USERNAME: Operator username  
    - OPERATOR_PASSWORD_HASH: PBKDF2-SHA256 hash (format: pbkdf2_sha256:100000:salt:hash)
    """
    # Check if in production mode
    flask_env = os.environ.get('FLASK_ENV', 'production').lower()
    is_production = flask_env not in ['development', 'dev']
    
    # First, check environment variables
    admin_user = os.environ.get('ADMIN_USERNAME')
    admin_hash = os.environ.get('ADMIN_PASSWORD_HASH')
    operator_user = os.environ.get('OPERATOR_USERNAME')
    operator_hash = os.environ.get('OPERATOR_PASSWORD_HASH')
    
    # If all environment variables are set, use them
    if all([admin_user, admin_hash, operator_user, operator_hash]):
        return {
            'admin': {
                'username': admin_user,
                'password_hash': admin_hash,
                'role': 'admin'
            },
            'operator': {
                'username': operator_user,
                'password_hash': operator_hash,
                'role': 'operator'
            }
        }
    
    # In production, require environment variables
    if is_production:
        logger.error("FATAL: Missing required authentication environment variables in production")
        logger.error("Required: ADMIN_USERNAME, ADMIN_PASSWORD_HASH, OPERATOR_USERNAME, OPERATOR_PASSWORD_HASH")
        exit(1)
    
    # Development mode: check credentials.json
    creds_file = 'credentials.json'
    if os.path.exists(creds_file):
        try:
            with open(creds_file, 'r') as f:
                creds = json.load(f)
            
            # Use credentials from file, filling in with env vars if available
            result = {}
            for role in ['admin', 'operator']:
                if role in creds:
                    result[role] = {
                        'username': creds[role].get('username', role),
                        'password_hash': creds[role].get('password_hash', ''),
                        'role': role
                    }
                else:
                    result[role] = {
                        'username': role,
                        'password_hash': hash_password(role),
                        'role': role
                    }
            
            return result
        except Exception as e:
            logger.error(f"Error loading credentials.json: {e}")
    
    # Development fallback with secure generated hashes
    logger.warning("Missing authentication environment variables - using development defaults")
    dev_admin_hash = hash_password('admin')
    dev_operator_hash = hash_password('operator')
    return {
        'admin': {
            'username': 'admin',
            'password_hash': dev_admin_hash,
            'role': 'admin'
        },
        'operator': {
            'username': 'operator', 
            'password_hash': dev_operator_hash,
            'role': 'operator'
        }
    }

def hash_password(password):
    """Create secure PBKDF2-SHA256 hash of password with salt"""
    import base64
    salt = secrets.token_bytes(32)
    # Use PBKDF2 with 100,000 iterations (recommended for 2024)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    # Store as base64 for compatibility: salt:hash
    salt_b64 = base64.b64encode(salt).decode('ascii')
    hash_b64 = base64.b64encode(password_hash).decode('ascii')
    return f"pbkdf2_sha256:100000:{salt_b64}:{hash_b64}"

def verify_password(password, stored_hash):
    """Verify password against PBKDF2 stored hash"""
    try:
        import base64
        
        if stored_hash.startswith('pbkdf2_sha256:'):
            # Modern PBKDF2 format
            parts = stored_hash.split(':')
            if len(parts) != 4:
                return False
            
            iterations = int(parts[1])
            salt = base64.b64decode(parts[2])
            stored_key = base64.b64decode(parts[3])
            
            # Compute hash with same salt and iterations
            computed_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
            return secrets.compare_digest(stored_key, computed_key)
            
        elif ':' in stored_hash:
            # Legacy salted SHA-256 (for transition only)
            logger.warning("Using legacy password hash format - update to PBKDF2")
            salt, hash_value = stored_hash.split(':', 1)
            password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            return password_hash == hash_value
        else:
            # Reject unsalted hashes
            logger.error("Unsalted password hash rejected for security")
            return False
            
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

# Classification options
CLASSIFICATIONS = ['Unclassified', 'Classified', 'Secret', 'TopSecret']

# Display vendor command formats
DISPLAY_VENDORS = {
    'nec': {
        'name': 'NEC',
        'required_params': ['monitor_id', 'input_source'],
        'param_labels': {
            'monitor_id': 'Monitor ID (1-100)',
            'input_source': 'Input Source'
        },
        'param_options': {
            'input_source': ['HDMI1', 'HDMI2', 'DVI', 'VGA', 'USB', 'MEMORY']
        },
        'rs232': {
            'show_image': lambda filename, params: f"\x02{params['monitor_id']:02d}INPUT_SELECT:MEMORY:{filename}\x03\r\n".encode('ascii'),
            'power_on': lambda params: f"\x02{params['monitor_id']:02d}POWER:ON\x03\r\n".encode('ascii'),
            'power_off': lambda params: f"\x02{params['monitor_id']:02d}POWER:OFF\x03\r\n".encode('ascii'),
            'response_ok': b'OK\r\n',
            'response_error': b'ERROR\r\n'
        },
        'tcp': {
            'show_image': lambda filename, params: f"MONITOR_{params['monitor_id']:02d}_MEMORY:{filename}\n".encode('utf-8'),
            'port': 7142,
            'response_ok': 'OK',
            'response_error': 'ERROR'
        }
    },
    'lg': {
        'name': 'LG',
        'required_params': ['set_id', 'input_source'],
        'param_labels': {
            'set_id': 'Set ID (01-99)',
            'input_source': 'Input Source'
        },
        'param_options': {
            'input_source': ['HDMI1', 'HDMI2', 'DVI', 'RGB', 'AV', 'USB']
        },
        'rs232': {
            'show_image': lambda filename, params: f"mc {params['set_id']:02d} {filename.replace('.png', '')}\r".encode('ascii'),
            'power_on': lambda params: f"ka {params['set_id']:02d} 01\r".encode('ascii'),
            'power_off': lambda params: f"ka {params['set_id']:02d} 00\r".encode('ascii'),
            'response_ok': lambda params: f"a {params['set_id']:02d} OK\r".encode('ascii'),
            'response_error': lambda params: f"a {params['set_id']:02d} NG\r".encode('ascii')
        },
        'tcp': {
            'show_image': lambda filename, params: f"mc {params['set_id']:02d} {filename.replace('.png', '')}\r".encode('utf-8'),
            'port': 9761,
            'response_ok': 'OK',
            'response_error': 'NG'
        }
    },
    'extron': {
        'name': 'Extron',
        'required_params': ['input_number', 'output_number'],
        'param_labels': {
            'input_number': 'Input Number (1-16)',
            'output_number': 'Output Number (1-8)'
        },
        'param_options': {},
        'rs232': {
            'show_image': lambda filename, params: f"{params['input_number']}*{params['output_number']}%{filename}$\r".encode('ascii'),
            'power_on': lambda params: f"{params['output_number']}*1!\r".encode('ascii'),
            'power_off': lambda params: f"{params['output_number']}*0!\r".encode('ascii'),
            'response_ok': b'1*1\r\n',
            'response_error': b'E01\r\n'
        },
        'tcp': {
            'show_image': lambda filename, params: f"{params['input_number']}*{params['output_number']}%{filename}$\r".encode('utf-8'),
            'port': 23,
            'response_ok': '1*1',
            'response_error': 'E01'
        }
    },
    'crestron': {
        'name': 'Crestron',
        'required_params': ['device_id', 'join_number'],
        'param_labels': {
            'device_id': 'Device ID (1-255)',
            'join_number': 'Join Number (1-65535)'
        },
        'param_options': {},
        'rs232': {
            'show_image': lambda filename, params: f"DEVICE_{params['device_id']}_JOIN_{params['join_number']}_DISPLAY:{filename}\r\n".encode('ascii'),
            'power_on': lambda params: f"DEVICE_{params['device_id']}_POWER:ON\r\n".encode('ascii'),
            'power_off': lambda params: f"DEVICE_{params['device_id']}_POWER:OFF\r\n".encode('ascii'),
            'response_ok': b'OK\r\n',
            'response_error': b'ERR\r\n'
        },
        'tcp': {
            'show_image': lambda filename, params: f"DEVICE_{params['device_id']}_JOIN_{params['join_number']}_DISPLAY:{filename}\r\n".encode('utf-8'),
            'port': 41794,
            'response_ok': 'OK',
            'response_error': 'ERR'
        }
    },
    'planar': {
        'name': 'Planar',
        'required_params': ['display_address', 'memory_bank'],
        'param_labels': {
            'display_address': 'Display Address (0-255)',
            'memory_bank': 'Memory Bank (A-Z)'
        },
        'param_options': {
            'memory_bank': ['A', 'B', 'C', 'D', 'E', 'F']
        },
        'rs232': {
            'show_image': lambda filename, params: f"@{params['display_address']:03d}_BANK_{params['memory_bank']}_IMAGE:{filename}\r".encode('ascii'),
            'power_on': lambda params: f"@{params['display_address']:03d}_POWER_ON\r".encode('ascii'),
            'power_off': lambda params: f"@{params['display_address']:03d}_POWER_OFF\r".encode('ascii'),
            'response_ok': b'@OK\r',
            'response_error': b'@ERROR\r'
        },
        'tcp': {
            'show_image': lambda filename, params: f"@{params['display_address']:03d}_BANK_{params['memory_bank']}_IMAGE:{filename}\r".encode('utf-8'),
            'port': 5000,
            'response_ok': '@OK',
            'response_error': '@ERROR'
        }
    },
    'samsung': {
        'name': 'Samsung',
        'required_params': ['display_id', 'input_source'],
        'param_labels': {
            'display_id': 'Display ID (0-254)',
            'input_source': 'Input Source'
        },
        'param_options': {
            'input_source': ['HDMI1', 'HDMI2', 'HDMI3', 'DVI', 'PC', 'AV', 'USB']
        },
        'rs232': {
            'show_image': lambda filename, params: f"\x08\x22{params['display_id']:02X}{filename[:4].encode().hex()}\x03".encode('utf-8'),
            'power_on': lambda params: f"\x08\x22{params['display_id']:02X}\x00\x00\x01\x2B".encode('utf-8'),
            'power_off': lambda params: f"\x08\x22{params['display_id']:02X}\x00\x00\x00\x2A".encode('utf-8'),
            'response_ok': b'\x03\x0C\xFF',
            'response_error': b'\x03\x0C\x00'
        },
        'tcp': {
            'show_image': lambda filename, params: f"DISPLAY_{params['display_id']}_IMAGE:{filename}\n".encode('utf-8'),
            'port': 1515,
            'response_ok': 'ACK',
            'response_error': 'NAK'
        }
    },
    'sony': {
        'name': 'Sony',
        'required_params': ['community', 'memory_preset'],
        'param_labels': {
            'community': 'Community (SNMP-like)',
            'memory_preset': 'Memory Preset (1-10)'
        },
        'param_options': {},
        'rs232': {
            'show_image': lambda filename, params: f"C{params['community']}_P{params['memory_preset']}_SI:{filename}\r\n".encode('ascii'),
            'power_on': lambda params: f"C{params['community']}_PO:1\r\n".encode('ascii'),
            'power_off': lambda params: f"C{params['community']}_PO:0\r\n".encode('ascii'),
            'response_ok': b'OK\r\n',
            'response_error': b'ER\r\n'
        },
        'tcp': {
            'show_image': lambda filename, params: f"C{params['community']}_P{params['memory_preset']}_SI:{filename}\r\n".encode('utf-8'),
            'port': 20060,
            'response_ok': 'OK',
            'response_error': 'ER'
        }
    },
    'generic': {
        'name': 'Generic',
        'required_params': [],
        'param_labels': {},
        'param_options': {},
        'rs232': {
            'show_image': lambda filename, params=None: f"SHOW {filename}\n".encode('utf-8'),
            'power_on': lambda params=None: b'POWER ON\n',
            'power_off': lambda params=None: b'POWER OFF\n',
            'response_ok': b'OK\n',
            'response_error': b'ERROR\n'
        },
        'tcp': {
            'show_image': lambda filename, params=None: f"SHOW {filename}\n".encode('utf-8'),
            'port': 5000,
            'response_ok': 'OK',
            'response_error': 'ERROR'
        }
    }
}

def load_config():
    """Load display configuration from JSON file"""
    try:
        with open('config.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # Return default configuration if file doesn't exist
        default_config = {
            "displays": [
                {
                    "name": "Room 1",
                    "protocol": "rs232",
                    "address": "/dev/ttyUSB0",
                    "baudrate": 9600,
                    "image_map": {
                        "Unclassified": "unclass.png",
                        "Classified": "classified.png",
                        "Secret": "secret.png",
                        "TopSecret": "ts.png"
                    }
                },
                {
                    "name": "Room 2", 
                    "protocol": "tcp",
                    "address": "10.0.0.22:5000",
                    "image_map": {
                        "Unclassified": "unclass.png",
                        "Classified": "classified.png",
                        "Secret": "secret.png",
                        "TopSecret": "ts.png"
                    }
                }
            ]
        }
        save_config(default_config)
        return default_config
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        return {"displays": []}

def save_config(config):
    """Save display configuration to JSON file"""
    try:
        with open('config.json', 'w') as f:
            json.dump(config, f, indent=2)
        logger.info("Configuration saved successfully")
    except Exception as e:
        logger.error(f"Error saving config: {e}")

def load_status():
    """Load display status from JSON file"""
    try:
        with open('status.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # Return default status if file doesn't exist
        config = load_config()
        default_status = {}
        for display in config.get('displays', []):
            default_status[display['name']] = {
                'classification': 'Unclassified',
                'image': display['image_map'].get('Unclassified', 'unclass.png'),
                'last_updated': datetime.now().isoformat()
            }
        save_status(default_status)
        return default_status
    except Exception as e:
        logger.error(f"Error loading status: {e}")
        return {}

def save_status(status):
    """Save display status to JSON file"""
    try:
        with open('status.json', 'w') as f:
            json.dump(status, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving status: {e}")

def update_display_status(display_name, classification, image_filename):
    """Update status for a specific display"""
    status = load_status()
    status[display_name] = {
        'classification': classification,
        'image': image_filename,
        'last_updated': datetime.now().isoformat()
    }
    save_status(status)
    logger.info(f"Updated status for {display_name}: {classification}")

def log_classification_change(user, room, classification):
    """Log classification changes for audit purposes"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    audit_entry = f"{timestamp} - {user} set {room} → {classification}"
    
    logger.info(audit_entry)
    
    # Also write to dedicated audit file
    try:
        with open('classification_audit.log', 'a') as f:
            f.write(audit_entry + '\n')
    except Exception as e:
        logger.error(f"Error writing to audit log: {e}")

def send_command_rs232(address, baudrate, image_filename, brand='generic', brand_params=None):
    """
    Send vendor-specific command to display via RS-232 serial connection
    """
    try:
        if brand not in DISPLAY_VENDORS:
            return False, f"Unsupported display brand: {brand}"
        
        vendor_config = DISPLAY_VENDORS[brand]['rs232']
        
        # Generate command with brand-specific parameters
        if brand_params:
            command = vendor_config['show_image'](image_filename, brand_params)
        else:
            command = vendor_config['show_image'](image_filename)
        
        with serial.Serial(address, baudrate, timeout=5) as ser:
            ser.write(command)
            logger.info(f"RS-232 command sent to {brand.upper()} display at {address}: {command}")
            
            # Read and validate response
            try:
                response = ser.read(20)  # Read up to 20 bytes
                expected_ok = vendor_config.get('response_ok', b'OK')
                expected_error = vendor_config.get('response_error', b'ERROR')
                
                # Handle brand-specific response patterns
                if callable(expected_ok) and brand_params:
                    expected_ok = expected_ok(brand_params)
                if callable(expected_error) and brand_params:
                    expected_error = expected_error(brand_params)
                
                if expected_ok in response:
                    return True, f"Command acknowledged by {brand.upper()} display"
                elif expected_error in response:
                    return False, f"{brand.upper()} display reported error: {response.decode('utf-8', errors='ignore')}"
                elif response:
                    return True, f"Response received: {response.decode('utf-8', errors='ignore')}"
                else:
                    return True, "Command sent (no response received)"
                    
            except Exception as read_error:
                logger.warning(f"Could not read response from {brand} display: {read_error}")
                return True, "Command sent (response read failed)"
            
    except serial.SerialException as e:
        error_msg = f"Serial communication error: {e}"
        logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"RS-232 error: {e}"
        logger.error(error_msg)
        return False, error_msg

def send_command_tcp(address, image_filename, brand='generic', brand_params=None):
    """
    Send vendor-specific command to display via TCP socket connection
    """
    try:
        if brand not in DISPLAY_VENDORS:
            return False, f"Unsupported display brand: {brand}"
        
        vendor_config = DISPLAY_VENDORS[brand]['tcp']
        
        # Parse address (format: "ip:port" or just "ip")
        if ':' in address:
            ip, port = address.split(':')
            port = int(port)
        else:
            ip = address
            port = vendor_config.get('port', 5000)  # Use vendor default port
        
        # Generate command with brand-specific parameters
        if brand_params:
            command = vendor_config['show_image'](image_filename, brand_params)
        else:
            command = vendor_config['show_image'](image_filename)
        
        # TCP socket connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)
            sock.connect((ip, port))
            sock.send(command)
            logger.info(f"TCP command sent to {brand.upper()} display at {ip}:{port}: {command}")
            
            # Read and validate response
            try:
                response = sock.recv(1024)  # Read up to 1024 bytes
                expected_ok = vendor_config.get('response_ok', 'OK')
                expected_error = vendor_config.get('response_error', 'ERROR')
                
                response_str = response.decode('utf-8', errors='ignore')
                
                if expected_ok in response_str:
                    return True, f"Command acknowledged by {brand.upper()} display"
                elif expected_error in response_str:
                    return False, f"{brand.upper()} display reported error: {response_str}"
                elif response:
                    return True, f"Response received: {response_str}"
                else:
                    return True, "Command sent (no response received)"
                    
            except Exception as read_error:
                logger.warning(f"Could not read response from {brand} display: {read_error}")
                return True, "Command sent (response read failed)"
            
    except socket.error as e:
        error_msg = f"TCP connection error: {e}"
        logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"TCP error: {e}"
        logger.error(error_msg)
        return False, error_msg

def send_command(display, classification):
    """
    Main command dispatch function - routes to appropriate protocol handler
    """
    try:
        # Get the image filename for this classification
        if classification not in display.get('image_map', {}):
            return False, f"No image mapping found for classification: {classification}"
        
        image_filename = display['image_map'][classification]
        protocol = display.get('protocol', '').lower()
        address = display.get('address', '')
        
        if not address:
            return False, "No address configured for display"
        
        # Get brand information
        brand = display.get('brand', 'generic')
        brand_params = display.get('brand_params', {})
        
        if protocol == 'rs232':
            baudrate = display.get('baudrate', 9600)
            return send_command_rs232(address, baudrate, image_filename, brand, brand_params)
        elif protocol == 'tcp':
            return send_command_tcp(address, image_filename, brand, brand_params)
        else:
            return False, f"Unsupported protocol: {protocol}"
            
    except Exception as e:
        error_msg = f"Command dispatch error: {e}"
        logger.error(error_msg)
        return False, error_msg

def login_required(f):
    """Decorator to require login for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin privileges for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        
        user_role = session.get('role')
        if user_role != 'admin':
            if request.is_json:
                return jsonify({'success': False, 'message': 'Admin privileges required'}), 403
            else:
                flash('Admin privileges required', 'error')
                return redirect(url_for('index'))
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user authentication - NIST SP 800-53 IA-5(7) compliant"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        credentials = get_credentials()
        
        # Check against both admin and operator accounts
        authenticated = False
        user_role = None
        
        for role, user_data in credentials.items():
            if user_data['username'] == username:
                if verify_password(password, user_data['password_hash']):
                    authenticated = True
                    user_role = user_data['role']
                    session['username'] = username
                    session['role'] = user_role
                    logger.info(f"User {username} ({user_role}) logged in successfully")
                    return redirect(url_for('index'))
                break
        
        if not authenticated:
            logger.warning(f"Failed login attempt for username: {username}")
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Handle user logout"""
    username = session.get('username', 'unknown')
    session.clear()
    logger.info(f"User {username} logged out")
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Main control interface"""
    config = load_config()
    status = load_status()
    displays = config.get('displays', [])
    
    # Combine display config with current status
    display_data = []
    for i, display in enumerate(displays):
        display_status = status.get(display['name'], {
            'classification': 'Unclassified',
            'image': display['image_map'].get('Unclassified', 'unclass.png'),
            'last_updated': datetime.now().isoformat()
        })
        
        display_info = {
            'index': i + 1,
            'name': display['name'],
            'protocol': display['protocol'],
            'address': display['address'],
            'image_map': display['image_map'],
            'current_classification': display_status['classification'],
            'current_image': display_status['image'],
            'classifications': list(display['image_map'].keys()),
            'last_updated': display_status.get('last_updated', '')
        }
        display_data.append(display_info)
    
    return render_template('index.html', 
                         displays=display_data,
                         username=session.get('username', ''),
                         user_role=session.get('role', 'operator'))

@app.route('/api/send-command', methods=['POST'])
@login_required
def api_send_command():
    """API endpoint to send classification command to display"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        display_name = data.get('display_name', '').strip()
        classification = data.get('classification', '').strip()
        
        if not display_name or not classification:
            return jsonify({'success': False, 'message': 'Display name and classification are required'}), 400
        
        # Find the display configuration first to check custom classifications
        config = load_config()
        
        # Find the specific display
        display_config = None
        for display in config['displays']:
            if display['name'] == display_name:
                display_config = display
                break
        
        if not display_config:
            return jsonify({'success': False, 'message': f'Display "{display_name}" not found'}), 404
        
        # Check if classification is valid (either in global list or in this display's image_map)
        valid_classifications = CLASSIFICATIONS + list(display_config.get('image_map', {}).keys())
        if classification not in valid_classifications:
            return jsonify({'success': False, 'message': f'Invalid classification: {classification}'}), 400
        # Send the command
        success, message = send_command(display_config, classification)
        
        if success:
            # Update display status and log the classification change
            image_filename = display_config['image_map'][classification]
            update_display_status(display_name, classification, image_filename)
            log_classification_change(session['username'], display_name, classification)
            
            return jsonify({
                'success': True, 
                'message': f'{display_name} set to {classification}',
                'details': message
            })
        else:
            return jsonify({'success': False, 'message': message}), 500
        
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/config')
@login_required
def api_get_config():
    """Get current configuration"""
    config = load_config()
    return jsonify(config)

@app.route('/api/vendors')
@login_required
def api_get_vendors():
    """Get display vendor information"""
    vendors = {}
    for brand_id, brand_info in DISPLAY_VENDORS.items():
        vendors[brand_id] = {
            'name': brand_info['name'],
            'required_params': brand_info['required_params'],
            'param_labels': brand_info['param_labels'],
            'param_options': brand_info['param_options']
        }
    return jsonify(vendors)


@app.route('/api/config', methods=['POST'])
@login_required
def api_save_config():
    """Save configuration changes"""
    try:
        config_data = request.get_json()
        
        if not config_data or 'displays' not in config_data:
            return jsonify({'success': False, 'message': 'Invalid configuration data'}), 400
        
        # Validate configuration
        for display in config_data['displays']:
            required_fields = ['name', 'protocol', 'address', 'image_map']
            for field in required_fields:
                if field not in display:
                    return jsonify({'success': False, 'message': f'Missing field: {field}'}), 400
        
        save_config(config_data)
        log_classification_change(session['username'], 'SYSTEM', 'Configuration Updated')
        
        return jsonify({'success': True, 'message': 'Configuration saved successfully'})
        
    except Exception as e:
        logger.error(f"Config save error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/status')
@login_required
def api_get_status():
    """Get current status of all displays"""
    try:
        config = load_config()
        status = load_status()
        
        displays_status = []
        for display in config.get('displays', []):
            display_status = status.get(display['name'], {
                'classification': 'Unclassified',
                'image': display['image_map'].get('Unclassified', 'unclass.png'),
                'last_updated': datetime.now().isoformat()
            })
            
            displays_status.append({
                'name': display['name'],
                'current_classification': display_status['classification'],
                'current_image': display_status['image'],
                'last_updated': display_status.get('last_updated', ''),
                'available_classifications': list(display['image_map'].keys())
            })
        
        return jsonify({'displays': displays_status})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/displays/add', methods=['POST'])
@admin_required
def api_add_display():
    """Add a new display to the configuration"""
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        brand = data.get('brand', '').strip()
        protocol = data.get('protocol', '').lower()
        address = data.get('address', '').strip()
        baudrate = data.get('baudrate', 9600)
        brand_params = data.get('brand_params', {})
        
        if not name or not brand or not protocol or not address:
            return jsonify({'success': False, 'message': 'Name, brand, protocol, and address are required'}), 400
        
        if protocol not in ['rs232', 'tcp']:
            return jsonify({'success': False, 'message': 'Protocol must be rs232 or tcp'}), 400
        
        if brand not in DISPLAY_VENDORS:
            return jsonify({'success': False, 'message': f'Unsupported display brand: {brand}'}), 400
        
        # Validate required brand parameters
        required_params = DISPLAY_VENDORS[brand]['required_params']
        for param in required_params:
            if param not in brand_params or not brand_params[param]:
                param_label = DISPLAY_VENDORS[brand]['param_labels'].get(param, param)
                return jsonify({'success': False, 'message': f'Missing required parameter: {param_label}'}), 400
        
        # Load current config
        config = load_config()
        
        # Check if display name already exists
        for display in config.get('displays', []):
            if display['name'] == name:
                return jsonify({'success': False, 'message': f'Display with name "{name}" already exists'}), 400
        
        # Create new display configuration
        new_display = {
            'name': name,
            'brand': brand,
            'protocol': protocol,
            'address': address,
            'brand_params': brand_params,
            'image_map': {
                'Unclassified': 'unclass.png',
                'Classified': 'classified.png',
                'Secret': 'secret.png',
                'TopSecret': 'ts.png'
            }
        }
        
        if protocol == 'rs232':
            new_display['baudrate'] = int(baudrate)
        
        # Add to config
        config.setdefault('displays', []).append(new_display)
        save_config(config)
        
        # Initialize status for new display
        status = load_status()
        status[name] = {
            'classification': 'Unclassified',
            'image': 'unclass.png',
            'last_updated': datetime.now().isoformat()
        }
        save_status(status)
        
        log_classification_change(session['username'], 'SYSTEM', f'Added new {brand.upper()} display: {name} with params: {brand_params}')
        
        return jsonify({'success': True, 'message': f'Display "{name}" added successfully'})
        
    except Exception as e:
        logger.error(f"Add display error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/displays/<display_name>/images', methods=['POST'])
@admin_required
def api_upload_image(display_name):
    """Upload a new image for a specific display"""
    try:
        # Check if display exists
        config = load_config()
        display = None
        for d in config.get('displays', []):
            if d['name'] == display_name:
                display = d
                break
        
        if not display:
            return jsonify({'success': False, 'message': f'Display "{display_name}" not found'}), 404
        
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file uploaded'}), 400
        
        file = request.files['file']
        label = request.form.get('label', '').strip()
        
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        if not label:
            return jsonify({'success': False, 'message': 'Label is required'}), 400
        
        if file and file.filename and allowed_file(file.filename):
            # Create display-specific upload directory
            display_slug = secure_filename(display_name.replace(' ', '_').lower())
            display_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], display_slug)
            Path(display_upload_dir).mkdir(parents=True, exist_ok=True)
            
            # Save file with secure filename
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            saved_filename = f"{timestamp}_{filename}"
            file_path = os.path.join(display_upload_dir, saved_filename)
            file.save(file_path)
            
            # Update display's image map
            relative_path = f"uploads/{display_slug}/{saved_filename}"
            display['image_map'][label] = relative_path
            save_config(config)
            
            log_classification_change(session['username'], display_name, f'Added image: {label}')
            
            return jsonify({
                'success': True, 
                'message': f'Image uploaded for {display_name}',
                'label': label,
                'filename': relative_path
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid file type. Allowed: png, jpg, jpeg, gif, bmp'}), 400
            
    except Exception as e:
        logger.error(f"Image upload error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/static/uploads/<path:filename>')
def uploaded_file(filename):
    """Serve uploaded files"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/displays/<display_name>', methods=['PUT'])
@admin_required
def api_edit_display(display_name):
    """Edit an existing display's properties"""
    try:
        data = request.get_json()
        new_name = data.get('name', '').strip()
        protocol = data.get('protocol', '').lower()
        address = data.get('address', '').strip()
        baudrate = data.get('baudrate', 9600)
        
        if not new_name or not protocol or not address:
            return jsonify({'success': False, 'message': 'Name, protocol, and address are required'}), 400
        
        if protocol not in ['rs232', 'tcp']:
            return jsonify({'success': False, 'message': 'Protocol must be rs232 or tcp'}), 400
        
        # Load current config
        config = load_config()
        
        # Find the display to edit
        display_found = False
        for i, display in enumerate(config.get('displays', [])):
            if display['name'] == display_name:
                display_found = True
                
                # Check if new name conflicts with existing displays (but not itself)
                if new_name != display_name:
                    for other_display in config['displays']:
                        if other_display['name'] == new_name:
                            return jsonify({'success': False, 'message': f'Display with name "{new_name}" already exists'}), 400
                
                # Update display properties
                old_image_map = display.get('image_map', {})
                config['displays'][i] = {
                    'name': new_name,
                    'protocol': protocol,
                    'address': address,
                    'image_map': old_image_map  # Preserve existing image mappings
                }
                
                if protocol == 'rs232':
                    config['displays'][i]['baudrate'] = int(baudrate)
                
                break
        
        if not display_found:
            return jsonify({'success': False, 'message': f'Display "{display_name}" not found'}), 404
        
        # Save updated config
        save_config(config)
        
        # Update status if display name changed
        if new_name != display_name:
            status = load_status()
            if display_name in status:
                status[new_name] = status.pop(display_name)
                save_status(status)
        
        log_classification_change(session['username'], 'SYSTEM', f'Edited display: {display_name} → {new_name}')
        
        return jsonify({'success': True, 'message': f'Display "{new_name}" updated successfully'})
        
    except Exception as e:
        logger.error(f"Edit display error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/displays/<display_name>', methods=['DELETE'])
@admin_required
def api_delete_display(display_name):
    """Delete an existing display"""
    try:
        # Load current config
        config = load_config()
        
        # Find and remove the display
        display_found = False
        for i, display in enumerate(config.get('displays', [])):
            if display['name'] == display_name:
                display_found = True
                config['displays'].pop(i)
                break
        
        if not display_found:
            return jsonify({'success': False, 'message': f'Display "{display_name}" not found'}), 404
        
        # Save updated config
        save_config(config)
        
        # Remove from status
        status = load_status()
        if display_name in status:
            del status[display_name]
            save_status(status)
        
        log_classification_change(session['username'], 'SYSTEM', f'Deleted display: {display_name}')
        
        return jsonify({'success': True, 'message': f'Display "{display_name}" deleted successfully'})
        
    except Exception as e:
        logger.error(f"Delete display error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/generate-hash', methods=['POST'])
@admin_required
def api_generate_hash():
    """Generate PBKDF2-SHA256 password hash (admin only)"""
    try:
        data = request.get_json()
        password = data.get('password', '').strip()
        
        if not password:
            return jsonify({'success': False, 'message': 'Password required'}), 400
        
        password_hash = hash_password(password)
        logger.info(f"Password hash generated by {session.get('username')}")
        
        return jsonify({
            'success': True, 
            'hash': password_hash,
            'format': 'pbkdf2_sha256:100000:salt:hash'
        })
        
    except Exception as e:
        logger.error(f"Hash generation error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/test-connection', methods=['POST'])
@login_required
def api_test_connection():
    """Test connection to a display"""
    try:
        data = request.get_json()
        protocol = data.get('protocol', '').lower()
        address = data.get('address', '')
        baudrate = data.get('baudrate', 9600)
        
        if protocol == 'rs232':
            # Test RS-232 connection
            try:
                with serial.Serial(address, baudrate, timeout=2) as ser:
                    return jsonify({'success': True, 'message': f'RS-232 connection successful to {address}'})
            except Exception as e:
                return jsonify({'success': False, 'message': f'RS-232 connection failed: {e}'})
                
        elif protocol == 'tcp':
            # Test TCP connection
            try:
                if ':' in address:
                    ip, port = address.split(':')
                    port = int(port)
                else:
                    ip = address
                    port = 5000
                
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(5)
                    sock.connect((ip, port))
                    return jsonify({'success': True, 'message': f'TCP connection successful to {ip}:{port}'})
            except Exception as e:
                return jsonify({'success': False, 'message': f'TCP connection failed: {e}'})
        else:
            return jsonify({'success': False, 'message': f'Unsupported protocol: {protocol}'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin-config')
@admin_required
def admin_config_page():
    """Admin configuration page"""
    credentials = get_credentials()
    admin_data = credentials.get('admin', {})
    operator_data = credentials.get('operator', {})
    
    return render_template('admin_config.html', 
                         username=session.get('username'),
                         admin_username=admin_data.get('username', 'admin'),
                         operator_username=operator_data.get('username', 'operator'))

@app.route('/api/generate-secret-key', methods=['POST'])
@admin_required
def api_generate_secret_key():
    """Generate a secure random secret key (admin only)"""
    try:
        import secrets
        secret_key = secrets.token_hex(32)
        logger.info(f"Secret key generated by {session.get('username')}")
        
        return jsonify({
            'success': True,
            'secret_key': secret_key
        })
    except Exception as e:
        logger.error(f"Secret key generation error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/logs/<log_type>')
@admin_required
def api_get_logs(log_type):
    """Get system logs (admin only)"""
    try:
        if log_type == 'audit':
            log_file = 'audit.log'
        elif log_type == 'classification':
            log_file = 'classification_audit.log'
        else:
            return jsonify({'success': False, 'message': 'Invalid log type'}), 400
        
        # Check if log file exists
        if not os.path.exists(log_file):
            return jsonify({'success': True, 'content': f'No {log_type} log entries yet.'})
        
        # Read last 500 lines of log file
        with open(log_file, 'r') as f:
            lines = f.readlines()
            # Get last 500 lines
            content = ''.join(lines[-500:])
        
        return jsonify({'success': True, 'content': content})
        
    except Exception as e:
        logger.error(f"Log retrieval error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/users/<role>', methods=['PUT'])
@admin_required
def api_update_user(role):
    """Update user credentials (admin only, development mode)"""
    try:
        # Only allow in development mode
        if os.environ.get('FLASK_ENV') != 'development':
            return jsonify({
                'success': False, 
                'message': 'User management only available in development mode. Use environment variables in production.'
            }), 403
        
        if role not in ['admin', 'operator']:
            return jsonify({'success': False, 'message': 'Invalid role'}), 400
        
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        if not username:
            return jsonify({'success': False, 'message': 'Username required'}), 400
        
        # Load or create credentials file
        creds_file = 'credentials.json'
        if os.path.exists(creds_file):
            with open(creds_file, 'r') as f:
                creds = json.load(f)
        else:
            creds = {}
        
        # Update username
        if role not in creds:
            creds[role] = {}
        
        creds[role]['username'] = username
        
        # Update password if provided
        if password:
            creds[role]['password_hash'] = hash_password(password)
        
        # Save credentials
        with open(creds_file, 'w') as f:
            json.dump(creds, f, indent=2)
        
        logger.info(f"User credentials updated for {role} by {session.get('username')}")
        
        return jsonify({
            'success': True,
            'message': f'{role.capitalize()} credentials updated successfully'
        })
        
    except Exception as e:
        logger.error(f"User update error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin-guide')
@admin_required
def api_get_admin_guide():
    """Get admin guide content as HTML (admin only)"""
    try:
        guide_file = 'ADMIN_GUIDE.md'
        
        if not os.path.exists(guide_file):
            return jsonify({'success': False, 'message': 'Admin guide not found'}), 404
        
        with open(guide_file, 'r') as f:
            markdown_content = f.read()
        
        # Convert markdown to HTML (simple conversion)
        import re
        html_content = markdown_content
        
        # Convert headers
        html_content = re.sub(r'^### (.*?)$', r'<h3>\1</h3>', html_content, flags=re.MULTILINE)
        html_content = re.sub(r'^## (.*?)$', r'<h2>\1</h2>', html_content, flags=re.MULTILINE)
        html_content = re.sub(r'^# (.*?)$', r'<h1>\1</h1>', html_content, flags=re.MULTILINE)
        
        # Convert code blocks
        html_content = re.sub(r'```(\w+)?\n(.*?)```', r'<pre><code>\2</code></pre>', html_content, flags=re.DOTALL)
        
        # Convert inline code
        html_content = re.sub(r'`([^`]+)`', r'<code>\1</code>', html_content)
        
        # Convert bold
        html_content = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html_content)
        
        # Convert lists
        html_content = re.sub(r'^\- (.*?)$', r'<li>\1</li>', html_content, flags=re.MULTILINE)
        html_content = re.sub(r'((?:<li>.*?</li>\n?)+)', r'<ul>\1</ul>', html_content, flags=re.DOTALL)
        
        # Convert paragraphs
        lines = html_content.split('\n')
        in_list = False
        in_pre = False
        result = []
        for line in lines:
            if '<pre>' in line:
                in_pre = True
            if '</pre>' in line:
                in_pre = False
            if '<ul>' in line or '<ol>' in line:
                in_list = True
            if '</ul>' in line or '</ol>' in line:
                in_list = False
            
            if line.strip() and not line.startswith('<') and not in_list and not in_pre:
                result.append(f'<p>{line}</p>')
            else:
                result.append(line)
        
        html_content = '\n'.join(result)
        
        return jsonify({'success': True, 'content': html_content})
        
    except Exception as e:
        logger.error(f"Admin guide retrieval error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == '__main__':
    # Create initial config if it doesn't exist
    load_config()
    
    # Print startup information
    print("\n" + "="*50)
    print("CLASSIFICATION COMMANDER")
    print("="*50)
    print("AUTHENTICATION: NIST SP 800-53 IA-5(7) COMPLIANT")
    print("No embedded static authenticators")
    print("")
    
    flask_env = os.environ.get('FLASK_ENV', 'production').lower()
    if flask_env in ['development', 'dev']:
        print("DEVELOPMENT MODE ACTIVE")
        print("Required environment variables for production:")
        print("  SECRET_KEY")
        print("  ADMIN_USERNAME, ADMIN_PASSWORD_HASH")
        print("  OPERATOR_USERNAME, OPERATOR_PASSWORD_HASH")
        print("")
        print("Use hash_password() function to generate secure hashes")
    else:
        print("PRODUCTION MODE: All credentials loaded from environment")
        
    print("="*50)
    
    # Start the Flask development server
    app.run(host='0.0.0.0', port=5000, debug=True)