#!/usr/bin/env python3
"""
Classification Commander - Native Python Implementation
Controls multiple displays to show classification banners (Unclassified, Secret, Top Secret)
Uses only Python standard library - NO external dependencies required
"""

import os
import json
import socket
import logging
import hashlib
import secrets
import urllib.parse
import urllib.request
import mimetypes
import io
import re
from datetime import datetime, timedelta
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie

# Try to import serial for RS232 support (optional)
try:
    import serial
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False
    logging.warning("pyserial not available - RS232 support disabled. Install with: pip install pyserial")

# Configure upload settings
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
Path(UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('audit.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Session management
SECRET_KEY = os.environ.get('SECRET_KEY')
flask_env = os.environ.get('FLASK_ENV', 'production').lower()

if not SECRET_KEY:
    if flask_env in ['development', 'dev']:
        SECRET_KEY = secrets.token_hex(32)
        logger.warning("Using generated SECRET_KEY for development - set SECRET_KEY environment variable for production")
    else:
        logger.error("FATAL: SECRET_KEY environment variable required for production")
        logger.error("Set FLASK_ENV=development for development mode")
        exit(1)

sessions = {}  # In-memory session storage: {session_id: {username, role, created, last_accessed}}

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
            'baudrate': 9600,
            'show_image': lambda filename, params: f"\x02{int(params.get('monitor_id', 1)):02d}INPUT_SELECT:MEMORY:{filename}\x03\r\n".encode('ascii'),
        },
        'tcp': {
            'port': 7142,
            'show_image': lambda filename, params: f"MONITOR_{int(params.get('monitor_id', 1)):02d}_MEMORY:{filename}\n".encode('utf-8'),
        }
    },
    'samsung': {
        'name': 'Samsung',
        'required_params': ['display_id'],
        'param_labels': {
            'display_id': 'Display ID (0-99)'
        },
        'rs232': {
            'baudrate': 9600,
            'show_image': lambda filename, params: f"DISPLAY_ID={int(params.get('display_id', 0)):02d}:PICTURE:{filename}\n".encode('utf-8'),
        },
        'tcp': {
            'port': 1515,
            'show_image': lambda filename, params: f"DISPLAY_ID={int(params.get('display_id', 0)):02d}:PICTURE:{filename}\n".encode('utf-8'),
        }
    },
    'lg': {
        'name': 'LG',
        'required_params': ['set_id'],
        'param_labels': {
            'set_id': 'Set ID (1-99)'
        },
        'rs232': {
            'baudrate': 9600,
            'show_image': lambda filename, params: f"ka {int(params.get('set_id', 1)):02d} {filename}\r".encode('ascii'),
        },
        'tcp': {
            'port': 9761,
            'show_image': lambda filename, params: f"ka {int(params.get('set_id', 1)):02d} {filename}\r".encode('ascii'),
        }
    },
    'generic': {
        'name': 'Generic',
        'required_params': [],
        'rs232': {
            'baudrate': 9600,
            'show_image': lambda filename, params: f"SHOW:{filename}\n".encode('utf-8'),
        },
        'tcp': {
            'port': 5000,
            'show_image': lambda filename, params: f"SHOW:{filename}\n".encode('utf-8'),
        }
    }
}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_credentials():
    """
    Load credentials from environment variables to comply with NIST SP 800-53 IA-5(7)
    In development mode, also checks credentials.json for web-managed credentials.
    
    Priority order:
    1. Environment variables (always takes precedence)
    2. credentials.json (development mode only)
    3. Default dev credentials (development mode only)
    """
    is_production = flask_env not in ['development', 'dev']
    
    # Check environment variables
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
    
    # Development fallback
    logger.warning("Missing authentication environment variables - using development defaults")
    return {
        'admin': {
            'username': 'admin',
            'password_hash': hash_password('admin'),
            'role': 'admin'
        },
        'operator': {
            'username': 'operator', 
            'password_hash': hash_password('operator'),
            'role': 'operator'
        }
    }

def hash_password(password):
    """Create secure PBKDF2-SHA256 hash of password with salt"""
    import base64
    salt = secrets.token_bytes(32)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    salt_b64 = base64.b64encode(salt).decode('ascii')
    hash_b64 = base64.b64encode(password_hash).decode('ascii')
    return f"pbkdf2_sha256:100000:{salt_b64}:{hash_b64}"

def verify_password(password, stored_hash):
    """Verify password against PBKDF2 stored hash"""
    try:
        import base64
        
        if stored_hash.startswith('pbkdf2_sha256:'):
            parts = stored_hash.split(':')
            if len(parts) != 4:
                return False
            
            iterations = int(parts[1])
            salt = base64.b64decode(parts[2])
            stored_key = base64.b64decode(parts[3])
            
            computed_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
            return secrets.compare_digest(stored_key, computed_key)
            
        elif ':' in stored_hash:
            logger.warning("Using legacy password hash format - update to PBKDF2")
            salt, hash_value = stored_hash.split(':', 1)
            password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            return password_hash == hash_value
        else:
            logger.error("Unsalted password hash rejected for security")
            return False
            
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

def generate_session_id():
    """Generate a secure session ID"""
    return secrets.token_urlsafe(32)

def create_session(username, role):
    """Create a new session for authenticated user"""
    session_id = generate_session_id()
    sessions[session_id] = {
        'username': username,
        'role': role,
        'created': datetime.now(),
        'last_accessed': datetime.now()
    }
    return session_id

def get_session(session_id):
    """Get session data if valid"""
    if session_id in sessions:
        session = sessions[session_id]
        # Check if session expired (24 hour timeout)
        if datetime.now() - session['last_accessed'] > timedelta(hours=24):
            del sessions[session_id]
            return None
        session['last_accessed'] = datetime.now()
        return session
    return None

def destroy_session(session_id):
    """Remove session"""
    if session_id in sessions:
        del sessions[session_id]

def load_config():
    """Load configuration from file"""
    config_file = 'config.json'
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return {'displays': []}
    return {'displays': []}

def save_config(config):
    """Save configuration to file"""
    config_file = 'config.json'
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving config: {e}")
        return False

def load_status():
    """Load display status from file"""
    status_file = 'status.json'
    if os.path.exists(status_file):
        try:
            with open(status_file, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_status(status):
    """Save display status to file"""
    status_file = 'status.json'
    try:
        with open(status_file, 'w') as f:
            json.dump(status, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving status: {e}")

def send_command_rs232(port, baudrate, image_filename, brand, brand_params):
    """Send command to RS232 display"""
    if not HAS_SERIAL:
        return False, "RS232 support not available (pyserial not installed)"
    
    try:
        vendor_config = DISPLAY_VENDORS.get(brand, DISPLAY_VENDORS['generic'])
        command = vendor_config['rs232']['show_image'](image_filename, brand_params)
        
        with serial.Serial(port, baudrate, timeout=2) as ser:
            ser.write(command)
            response = ser.read(100)
            
        logger.info(f"RS232 command sent to {port}: {command}")
        return True, "Command sent successfully"
    except Exception as e:
        error_msg = f"RS232 error: {e}"
        logger.error(error_msg)
        return False, error_msg

def send_command_tcp(address, image_filename, brand, brand_params):
    """Send command to TCP/IP display"""
    try:
        vendor_config = DISPLAY_VENDORS.get(brand, DISPLAY_VENDORS['generic'])
        command = vendor_config['tcp']['show_image'](image_filename, brand_params)
        
        # Parse address (format: host:port or just host)
        if ':' in address:
            host, port_str = address.rsplit(':', 1)
            port = int(port_str)
        else:
            host = address
            port = vendor_config['tcp'].get('port', 5000)
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect((host, port))
            sock.sendall(command)
            response = sock.recv(1024)
        
        logger.info(f"TCP command sent to {host}:{port}: {command}")
        return True, "Command sent successfully"
    except Exception as e:
        error_msg = f"TCP error: {e}"
        logger.error(error_msg)
        return False, error_msg

def dispatch_command(display_name, classification):
    """Dispatch classification command to display"""
    try:
        config = load_config()
        display = next((d for d in config['displays'] if d['name'] == display_name), None)
        
        if not display:
            return False, "Display not found"
        
        image_map = display.get('image_map', {})
        if classification not in image_map:
            return False, f"No image mapped for classification: {classification}"
        
        image_filename = image_map[classification]
        protocol = display.get('protocol', '').lower()
        address = display.get('address', '')
        
        if not address:
            return False, "No address configured for display"
        
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

def render_template(template_name, **context):
    """Simple template rendering"""
    template_path = Path('templates') / template_name
    if not template_path.exists():
        return f"Template not found: {template_name}"
    
    with open(template_path, 'r', encoding='utf-8') as f:
        template = f.read()
    
    # Simple Jinja2-like template replacement
    for key, value in context.items():
        # Handle boolean checks like {% if user_role == 'admin' %}
        if key == 'user_role' and value:
            template = re.sub(r'{%\s*if\s+user_role\s*==\s*[\'"]admin[\'"]\s*%}(.*?){%\s*endif\s*%}',
                            r'\1' if value == 'admin' else '', template, flags=re.DOTALL)
        
        # Handle variable replacement
        template = template.replace('{{ ' + key + ' }}', str(value) if value is not None else '')
        
        # Handle loops {% for display in displays %}
        if key == 'displays' and isinstance(value, list):
            loop_pattern = r'{%\s*for\s+display\s+in\s+displays\s*%}(.*?){%\s*endfor\s*%}'
            match = re.search(loop_pattern, template, re.DOTALL)
            if match:
                loop_template = match.group(1)
                loop_result = []
                for display in value:
                    loop_item = loop_template
                    for dk, dv in display.items():
                        if isinstance(dv, dict):
                            for sub_k, sub_v in dv.items():
                                loop_item = loop_item.replace(f'{{{{ display.{dk}.{sub_k} }}}}', str(sub_v))
                        elif isinstance(dv, list):
                            # Handle lists in displays
                            if dk == 'classifications':
                                class_pattern = r'{%\s*for\s+classification\s+in\s+display\.classifications\s*%}(.*?){%\s*endfor\s*%}'
                                class_match = re.search(class_pattern, loop_item, re.DOTALL)
                                if class_match:
                                    class_template = class_match.group(1)
                                    class_result = []
                                    for classification in dv:
                                        class_item = class_template.replace('{{ classification }}', classification)
                                        class_item = class_item.replace('{{ display.current_classification }}', display.get('current_classification', ''))
                                        class_item = class_item.replace('{{ display.name|replace(\' \', \'_\') }}', display['name'].replace(' ', '_'))
                                        class_result.append(class_item)
                                    loop_item = re.sub(class_pattern, ''.join(class_result), loop_item, flags=re.DOTALL)
                        else:
                            loop_item = loop_item.replace(f'{{{{ display.{dk} }}}}', str(dv))
                    
                    # Handle filters and conditionals
                    loop_item = loop_item.replace('{{ display.name|replace(\' \', \'_\') }}', display['name'].replace(' ', '_'))
                    loop_item = re.sub(r'{{.*?display\.current_classification\.lower\(\)\.replace\(.*?\).*?}}',
                                      display.get('current_classification', '').lower().replace(' ', '-'), loop_item)
                    
                    loop_result.append(loop_item)
                
                template = re.sub(loop_pattern, ''.join(loop_result), template, flags=re.DOTALL)
    
    # Clean up any remaining template syntax
    template = re.sub(r'{%.*?%}', '', template)
    template = re.sub(r'{{.*?}}', '', template)
    
    return template

class ClassificationHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Classification Commander"""
    
    def log_message(self, format, *args):
        """Override to use our logger"""
        logger.info("%s - - [%s] %s" % (self.address_string(), self.log_date_time_string(), format % args))
    
    def get_session_id(self):
        """Extract session ID from cookies"""
        cookie_header = self.headers.get('Cookie')
        if cookie_header:
            cookie = SimpleCookie()
            cookie.load(cookie_header)
            if 'session_id' in cookie:
                return cookie['session_id'].value
        return None
    
    def set_session_cookie(self, session_id):
        """Set session cookie with security flags"""
        cookie = SimpleCookie()
        cookie['session_id'] = session_id
        cookie['session_id']['path'] = '/'
        cookie['session_id']['httponly'] = True
        cookie['session_id']['max-age'] = 86400  # 24 hours
        cookie['session_id']['samesite'] = 'Lax'
        # Note: 'secure' flag should be set when using HTTPS in production
        # cookie['session_id']['secure'] = True
        return cookie['session_id'].OutputString()
    
    def require_auth(self):
        """Check if user is authenticated"""
        session_id = self.get_session_id()
        if session_id:
            session = get_session(session_id)
            if session:
                return session
        return None
    
    def require_admin(self):
        """Check if user is admin"""
        session = self.require_auth()
        if session and session.get('role') == 'admin':
            return session
        return None
    
    def send_json_response(self, data, status=200):
        """Send JSON response"""
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))
    
    def send_html_response(self, html, status=200):
        """Send HTML response"""
        self.send_response(status)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))
    
    def send_redirect(self, location):
        """Send redirect response"""
        self.send_response(302)
        self.send_header('Location', location)
        self.end_headers()
    
    def serve_static_file(self, path):
        """Serve static file"""
        try:
            file_path = Path(path.lstrip('/'))
            if not file_path.exists() or not file_path.is_file():
                self.send_response(404)
                self.end_headers()
                return
            
            content_type, _ = mimetypes.guess_type(str(file_path))
            if content_type is None:
                content_type = 'application/octet-stream'
            
            self.send_response(200)
            self.send_header('Content-type', content_type)
            self.send_header('Content-Length', str(file_path.stat().st_size))
            self.end_headers()
            
            with open(file_path, 'rb') as f:
                self.wfile.write(f.read())
        except Exception as e:
            logger.error(f"Error serving static file {path}: {e}")
            self.send_response(500)
            self.end_headers()
    
    def parse_post_data(self):
        """Parse POST data (form or JSON)"""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            return {}
        
        post_data = self.rfile.read(content_length)
        content_type = self.headers.get('Content-Type', '')
        
        if 'application/json' in content_type:
            return json.loads(post_data.decode('utf-8'))
        elif 'application/x-www-form-urlencoded' in content_type:
            params = urllib.parse.parse_qs(post_data.decode('utf-8'))
            return {k: v[0] if len(v) == 1 else v for k, v in params.items()}
        elif 'multipart/form-data' in content_type:
            return self.parse_multipart(post_data, content_type)
        else:
            return {}
    
    def parse_multipart(self, post_data, content_type):
        """Parse multipart/form-data"""
        # Extract boundary
        boundary = content_type.split('boundary=')[1].encode('utf-8')
        parts = post_data.split(b'--' + boundary)
        
        result = {}
        files = {}
        
        for part in parts[1:-1]:  # Skip first and last (empty) parts
            if not part or part == b'--\r\n' or part == b'\r\n':
                continue
            
            # Split headers and content
            header_end = part.find(b'\r\n\r\n')
            if header_end == -1:
                continue
            
            headers = part[:header_end].decode('utf-8')
            content = part[header_end + 4:-2]  # Remove \r\n at end
            
            # Parse Content-Disposition header
            disp_match = re.search(r'Content-Disposition: form-data; name="([^"]+)"', headers)
            if not disp_match:
                continue
            
            field_name = disp_match.group(1)
            
            # Check if it's a file
            filename_match = re.search(r'filename="([^"]+)"', headers)
            if filename_match:
                filename = filename_match.group(1)
                files[field_name] = {'filename': filename, 'content': content}
            else:
                result[field_name] = content.decode('utf-8')
        
        result['_files'] = files
        return result
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        # Root - redirect to login or main page
        if path == '/':
            session = self.require_auth()
            if session:
                config = load_config()
                status = load_status()
                
                # Merge config and status
                displays = []
                for display in config.get('displays', []):
                    display_status = status.get(display['name'], {})
                    display_data = display.copy()
                    display_data['current_classification'] = display_status.get('classification', 'Unclassified')
                    display_data['last_update'] = display_status.get('timestamp', 'Never')
                    display_data['classifications'] = CLASSIFICATIONS
                    displays.append(display_data)
                
                html = render_template('index.html',
                                     username=session['username'],
                                     user_role=session['role'],
                                     displays=displays)
                self.send_html_response(html)
            else:
                self.send_redirect('/login')
        
        # Login page
        elif path == '/login':
            html = render_template('login.html')
            self.send_html_response(html)
        
        # Logout
        elif path == '/logout':
            session_id = self.get_session_id()
            if session_id:
                destroy_session(session_id)
            self.send_redirect('/login')
        
        # Admin config page
        elif path == '/admin-config':
            session = self.require_admin()
            if not session:
                self.send_redirect('/login')
                return
            
            credentials = get_credentials()
            admin_data = credentials.get('admin', {})
            operator_data = credentials.get('operator', {})
            
            html = render_template('admin_config.html',
                                 username=session['username'],
                                 admin_username=admin_data.get('username', 'admin'),
                                 operator_username=operator_data.get('username', 'operator'))
            self.send_html_response(html)
        
        # API: Get config
        elif path == '/api/config':
            session = self.require_auth()
            if not session:
                self.send_json_response({'success': False, 'message': 'Authentication required'}, 401)
                return
            
            config = load_config()
            self.send_json_response(config)
        
        # API: Get vendors
        elif path == '/api/vendors':
            session = self.require_auth()
            if not session:
                self.send_json_response({'success': False, 'message': 'Authentication required'}, 401)
                return
            
            self.send_json_response({'vendors': DISPLAY_VENDORS})
        
        # API: Get status
        elif path == '/api/status':
            session = self.require_auth()
            if not session:
                self.send_json_response({'success': False, 'message': 'Authentication required'}, 401)
                return
            
            config = load_config()
            status = load_status()
            
            displays = []
            for display in config.get('displays', []):
                display_status = status.get(display['name'], {})
                displays.append({
                    'name': display['name'],
                    'current_classification': display_status.get('classification', 'Unclassified'),
                    'last_update': display_status.get('timestamp', 'Never')
                })
            
            self.send_json_response({'displays': displays})
        
        # API: Get logs
        elif path.startswith('/api/logs/'):
            session = self.require_admin()
            if not session:
                self.send_json_response({'success': False, 'message': 'Admin privileges required'}, 403)
                return
            
            log_type = path.split('/')[-1]
            if log_type == 'audit':
                log_file = 'audit.log'
            elif log_type == 'classification':
                log_file = 'classification_audit.log'
            else:
                self.send_json_response({'success': False, 'message': 'Invalid log type'}, 400)
                return
            
            if not os.path.exists(log_file):
                self.send_json_response({'success': True, 'content': f'No {log_type} log entries yet.'})
                return
            
            with open(log_file, 'r') as f:
                lines = f.readlines()
                content = ''.join(lines[-500:])
            
            self.send_json_response({'success': True, 'content': content})
        
        # API: Get admin guide
        elif path == '/api/admin-guide':
            session = self.require_admin()
            if not session:
                self.send_json_response({'success': False, 'message': 'Admin privileges required'}, 403)
                return
            
            guide_file = 'ADMIN_GUIDE.md'
            if not os.path.exists(guide_file):
                self.send_json_response({'success': False, 'message': 'Admin guide not found'}, 404)
                return
            
            with open(guide_file, 'r') as f:
                markdown_content = f.read()
            
            # Simple markdown to HTML conversion
            html_content = markdown_content
            html_content = re.sub(r'^### (.*?)$', r'<h3>\1</h3>', html_content, flags=re.MULTILINE)
            html_content = re.sub(r'^## (.*?)$', r'<h2>\1</h2>', html_content, flags=re.MULTILINE)
            html_content = re.sub(r'^# (.*?)$', r'<h1>\1</h1>', html_content, flags=re.MULTILINE)
            html_content = re.sub(r'```(\w+)?\n(.*?)```', r'<pre><code>\2</code></pre>', html_content, flags=re.DOTALL)
            html_content = re.sub(r'`([^`]+)`', r'<code>\1</code>', html_content)
            html_content = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html_content)
            html_content = re.sub(r'^\- (.*?)$', r'<li>\1</li>', html_content, flags=re.MULTILINE)
            html_content = re.sub(r'((?:<li>.*?</li>\n?)+)', r'<ul>\1</ul>', html_content, flags=re.DOTALL)
            
            self.send_json_response({'success': True, 'content': html_content})
        
        # Static files
        elif path.startswith('/static/'):
            self.serve_static_file(path)
        
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'404 Not Found')
    
    def do_POST(self):
        """Handle POST requests"""
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        # Login
        if path == '/login':
            data = self.parse_post_data()
            username = data.get('username', '')
            password = data.get('password', '')
            # Handle list values from form data
            if isinstance(username, list):
                username = username[0] if username else ''
            if isinstance(password, list):
                password = password[0] if password else ''
            username = username.strip()
            password = password.strip()
            
            credentials = get_credentials()
            authenticated = False
            user_role = None
            
            for role, user_data in credentials.items():
                if user_data['username'] == username:
                    if verify_password(password, user_data['password_hash']):
                        authenticated = True
                        user_role = role
                        break
            
            if authenticated:
                session_id = create_session(username, user_role)
                logger.info(f"Successful login: {username} (role: {user_role})")
                
                self.send_response(302)
                self.send_header('Location', '/')
                self.send_header('Set-Cookie', self.set_session_cookie(session_id))
                self.end_headers()
            else:
                logger.warning(f"Failed login attempt: {username}")
                html = render_template('login.html')
                self.send_html_response(html)
        
        # API: Send command
        elif path == '/api/send-command':
            session = self.require_auth()
            if not session:
                self.send_json_response({'success': False, 'message': 'Authentication required'}, 401)
                return
            
            data = self.parse_post_data()
            display_name = data.get('display_name', '')
            classification = data.get('classification', '')
            # Handle list values from form data
            if isinstance(display_name, list):
                display_name = display_name[0] if display_name else ''
            if isinstance(classification, list):
                classification = classification[0] if classification else ''
            
            if not display_name or not classification:
                self.send_json_response({'success': False, 'message': 'Missing required parameters'}, 400)
                return
            
            success, message = dispatch_command(display_name, classification)
            
            if success:
                # Update status
                status = load_status()
                status[display_name] = {
                    'classification': classification,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'user': session['username']
                }
                save_status(status)
                
                # Log to classification audit
                with open('classification_audit.log', 'a') as f:
                    f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {session['username']} - {display_name} - {classification}\n")
            
            self.send_json_response({'success': success, 'message': message})
        
        # API: Add display
        elif path == '/api/displays/add':
            session = self.require_admin()
            if not session:
                self.send_json_response({'success': False, 'message': 'Admin privileges required'}, 403)
                return
            
            data = self.parse_post_data()
            config = load_config()
            
            # Extract values handling possible lists
            name = data.get('name', '')
            protocol = data.get('protocol', 'tcp')
            address = data.get('address', '')
            brand = data.get('brand', 'generic')
            brand_params_str = data.get('brand_params', '{}')
            baudrate = data.get('baudrate', '9600')
            
            if isinstance(name, list):
                name = name[0] if name else ''
            if isinstance(protocol, list):
                protocol = protocol[0] if protocol else 'tcp'
            if isinstance(address, list):
                address = address[0] if address else ''
            if isinstance(brand, list):
                brand = brand[0] if brand else 'generic'
            if isinstance(brand_params_str, list):
                brand_params_str = brand_params_str[0] if brand_params_str else '{}'
            if isinstance(baudrate, list):
                baudrate = baudrate[0] if baudrate else '9600'
            
            # Create new display
            try:
                brand_params_parsed = json.loads(brand_params_str)
            except (json.JSONDecodeError, ValueError):
                self.send_json_response({'success': False, 'message': 'Invalid brand_params JSON'}, 400)
                return
            
            new_display = {
                'name': name,
                'protocol': protocol,
                'address': address,
                'brand': brand,
                'brand_params': brand_params_parsed,
                'image_map': {
                    'Unclassified': 'default_unclass.png',
                    'Classified': 'default_classified.png',
                    'Secret': 'default_secret.png',
                    'TopSecret': 'default_topsecret.png'
                }
            }
            
            if new_display['protocol'] == 'rs232':
                new_display['baudrate'] = int(baudrate)
            
            config['displays'].append(new_display)
            save_config(config)
            
            logger.info(f"Display added: {new_display['name']} by {session['username']}")
            self.send_json_response({'success': True, 'message': 'Display added successfully'})
        
        # API: Upload image
        elif path.startswith('/api/displays/') and '/images' in path:
            session = self.require_admin()
            if not session:
                self.send_json_response({'success': False, 'message': 'Admin privileges required'}, 403)
                return
            
            display_name = urllib.parse.unquote(path.split('/')[3])
            data = self.parse_post_data()
            files = data.get('_files', {})
            
            if not files or 'image' not in files:
                self.send_json_response({'success': False, 'message': 'No image file provided'}, 400)
                return
            
            file_data = files.get('image', {})
            filename = file_data.get('filename', '')
            
            if not allowed_file(filename):
                self.send_json_response({'success': False, 'message': 'Invalid file type'}, 400)
                return
            
            # Save file
            upload_dir = Path(UPLOAD_FOLDER) / display_name.replace(' ', '_')
            upload_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_filename = f"{timestamp}_{filename}"
            file_path = upload_dir / safe_filename
            
            content = file_data.get('content', b'')
            if isinstance(content, str):
                content = content.encode('utf-8')
            
            with open(file_path, 'wb') as f:
                f.write(content)
            
            relative_path = f"static/uploads/{display_name.replace(' ', '_')}/{safe_filename}"
            
            logger.info(f"Image uploaded: {relative_path} by {session['username']}")
            self.send_json_response({'success': True, 'image_path': relative_path})
        
        # API: Update display
        elif path.startswith('/api/displays/') and path.count('/') == 3:
            session = self.require_admin()
            if not session:
                self.send_json_response({'success': False, 'message': 'Admin privileges required'}, 403)
                return
            
            display_name = urllib.parse.unquote(path.split('/')[-1])
            data = self.parse_post_data()
            config = load_config()
            
            display = next((d for d in config['displays'] if d['name'] == display_name), None)
            if not display:
                self.send_json_response({'success': False, 'message': 'Display not found'}, 404)
                return
            
            # Update display properties (handle list values)
            if 'address' in data:
                address = data['address']
                display['address'] = address[0] if isinstance(address, list) else address
            if 'protocol' in data:
                protocol = data['protocol']
                display['protocol'] = protocol[0] if isinstance(protocol, list) else protocol
            if 'brand' in data:
                brand = data['brand']
                display['brand'] = brand[0] if isinstance(brand, list) else brand
            if 'brand_params' in data:
                bp = data['brand_params']
                bp_str = bp[0] if isinstance(bp, list) else bp
                try:
                    display['brand_params'] = json.loads(bp_str) if isinstance(bp_str, str) else bp_str
                except (json.JSONDecodeError, ValueError):
                    self.send_json_response({'success': False, 'message': 'Invalid brand_params JSON'}, 400)
                    return
            if 'image_map' in data:
                im = data['image_map']
                im_str = im[0] if isinstance(im, list) else im
                try:
                    display['image_map'] = json.loads(im_str) if isinstance(im_str, str) else im_str
                except (json.JSONDecodeError, ValueError):
                    self.send_json_response({'success': False, 'message': 'Invalid image_map JSON'}, 400)
                    return
            if 'baudrate' in data:
                br = data['baudrate']
                br_val = br[0] if isinstance(br, list) else br
                display['baudrate'] = int(br_val)
            
            save_config(config)
            logger.info(f"Display updated: {display_name} by {session['username']}")
            self.send_json_response({'success': True, 'message': 'Display updated successfully'})
        
        # API: Test connection
        elif path == '/api/test-connection':
            session = self.require_auth()
            if not session:
                self.send_json_response({'success': False, 'message': 'Authentication required'}, 401)
                return
            
            data = self.parse_post_data()
            protocol = data.get('protocol', '')
            address = data.get('address', '')
            brand = data.get('brand', 'generic')
            brand_params_str = data.get('brand_params', '{}')
            baudrate_str = data.get('baudrate', '9600')
            
            # Handle list values
            if isinstance(protocol, list):
                protocol = protocol[0] if protocol else ''
            if isinstance(address, list):
                address = address[0] if address else ''
            if isinstance(brand, list):
                brand = brand[0] if brand else 'generic'
            if isinstance(brand_params_str, list):
                brand_params_str = brand_params_str[0] if brand_params_str else '{}'
            if isinstance(baudrate_str, list):
                baudrate_str = baudrate_str[0] if baudrate_str else '9600'
            
            protocol = protocol.lower()
            try:
                brand_params = json.loads(brand_params_str)
            except (json.JSONDecodeError, ValueError):
                self.send_json_response({'success': False, 'message': 'Invalid brand_params JSON'}, 400)
                return
            
            if protocol == 'rs232':
                baudrate = int(baudrate_str)
                success, message = send_command_rs232(address, baudrate, 'test.png', brand, brand_params)
            elif protocol == 'tcp':
                success, message = send_command_tcp(address, 'test.png', brand, brand_params)
            else:
                success, message = False, "Invalid protocol"
            
            self.send_json_response({'success': success, 'message': message})
        
        # API: Generate hash
        elif path == '/api/generate-hash':
            session = self.require_admin()
            if not session:
                self.send_json_response({'success': False, 'message': 'Admin privileges required'}, 403)
                return
            
            data = self.parse_post_data()
            password = data.get('password', '')
            
            if not password:
                self.send_json_response({'success': False, 'message': 'Password required'}, 400)
                return
            
            password_hash = hash_password(password)
            self.send_json_response({'success': True, 'hash': password_hash})
        
        # API: Generate secret key
        elif path == '/api/generate-secret-key':
            session = self.require_admin()
            if not session:
                self.send_json_response({'success': False, 'message': 'Admin privileges required'}, 403)
                return
            
            secret_key = secrets.token_hex(32)
            self.send_json_response({'success': True, 'secret_key': secret_key})
        
        # API: Update user
        elif path.startswith('/api/users/'):
            session = self.require_admin()
            if not session:
                self.send_json_response({'success': False, 'message': 'Admin privileges required'}, 403)
                return
            
            if os.environ.get('FLASK_ENV') != 'development':
                self.send_json_response({
                    'success': False,
                    'message': 'User management only available in development mode. Use environment variables in production.'
                }, 403)
                return
            
            role = path.split('/')[-1]
            if role not in ['admin', 'operator']:
                self.send_json_response({'success': False, 'message': 'Invalid role'}, 400)
                return
            
            data = self.parse_post_data()
            username = data.get('username', '')
            password = data.get('password', '')
            
            # Handle list values
            if isinstance(username, list):
                username = username[0] if username else ''
            if isinstance(password, list):
                password = password[0] if password else ''
            
            username = username.strip()
            password = password.strip()
            
            if not username:
                self.send_json_response({'success': False, 'message': 'Username required'}, 400)
                return
            
            # Load or create credentials file
            creds_file = 'credentials.json'
            if os.path.exists(creds_file):
                with open(creds_file, 'r') as f:
                    creds = json.load(f)
            else:
                creds = {}
            
            if role not in creds:
                creds[role] = {}
            
            creds[role]['username'] = username
            
            if password:
                creds[role]['password_hash'] = hash_password(password)
            
            with open(creds_file, 'w') as f:
                json.dump(creds, f, indent=2)
            
            logger.info(f"User credentials updated for {role} by {session['username']}")
            self.send_json_response({
                'success': True,
                'message': f'{role.capitalize()} credentials updated successfully'
            })
        
        # API: Config save (admin only)
        elif path == '/api/config' and self.command == 'POST':
            session = self.require_admin()
            if not session:
                self.send_json_response({'success': False, 'message': 'Admin privileges required'}, 403)
                return
            
            data = self.parse_post_data()
            if save_config(data):
                self.send_json_response({'success': True, 'message': 'Configuration saved successfully'})
            else:
                self.send_json_response({'success': False, 'message': 'Failed to save configuration'}, 500)
        
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'404 Not Found')
    
    def do_PUT(self):
        """Handle PUT requests (treated as POST)"""
        self.do_POST()
    
    def do_DELETE(self):
        """Handle DELETE requests"""
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        # API: Delete display
        if path.startswith('/api/displays/') and path.count('/') == 3:
            session = self.require_admin()
            if not session:
                self.send_json_response({'success': False, 'message': 'Admin privileges required'}, 403)
                return
            
            display_name = urllib.parse.unquote(path.split('/')[-1])
            config = load_config()
            
            original_length = len(config['displays'])
            config['displays'] = [d for d in config['displays'] if d['name'] != display_name]
            
            if len(config['displays']) < original_length:
                save_config(config)
                logger.info(f"Display deleted: {display_name} by {session['username']}")
                self.send_json_response({'success': True, 'message': 'Display deleted successfully'})
            else:
                self.send_json_response({'success': False, 'message': 'Display not found'}, 404)
        else:
            self.send_response(404)
            self.end_headers()

def run_server(host='0.0.0.0', port=5000):
    """Run the HTTP server"""
    # Create initial config if it doesn't exist
    load_config()
    
    # Print startup information
    print("\n" + "="*50)
    print("CLASSIFICATION COMMANDER")
    print("="*50)
    print("AUTHENTICATION: NIST SP 800-53 IA-5(7) COMPLIANT")
    print("No embedded static authenticators")
    print("Native Python Implementation - No external dependencies")
    print("")
    
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
    print(f"\nServer starting on http://{host}:{port}")
    print("Press CTRL+C to quit\n")
    
    server = HTTPServer((host, port), ClassificationHandler)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        server.shutdown()

if __name__ == '__main__':
    run_server()
