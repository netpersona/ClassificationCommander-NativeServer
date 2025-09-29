# Classification Commander

## Overview

A web-based classification banner control system designed for conference rooms and secure facilities. The application controls multiple displays via RS232 and TCP protocols to show classification banners (Unclassified, Classified, Secret, Top Secret). Features include web-based control interface, NIST SP 800-53 IA-5(7) compliant authentication, and role-based access control.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Multi-page Structure**: Separate HTML templates for main control interface (`index.html`), login (`login.html`), and admin configuration (`admin_config.html`)
- **Pure JavaScript**: Vanilla JavaScript for dynamic updates and AJAX calls
- **Responsive Design**: CSS-based responsive layout with classification banner preview cards
- **Icon-based Navigation**: Minimalist header with gear icon (admin config) and logout icon

### Backend Architecture
- **Native Python HTTP Server**: Uses only Python standard library (`http.server` module) - NO external dependencies
- **Session Management**: Secure cookie-based session handling with SECRET_KEY environment variable
- **Authentication System**: NIST SP 800-53 IA-5(7) compliant authentication
- **Role-Based Access Control**: Admin and operator roles with different permissions
- **Display Protocol Handlers**: RS232 and TCP/IP communication for display control

### Configuration Management
- **JSON-based Configuration**: Central `config.json` file storing display configurations
- **Credentials Management**: `credentials.json` for development, environment variables for production
- **Display Management**: Support for multiple displays with individual settings
- **Per-Display Settings**: Individual connection settings (RS232/TCP), images, and classifications

### Authentication & Security
- **NIST SP 800-53 IA-5(7) Compliance**: No embedded static authenticators
- **Environment Variable Secrets**: SECRET_KEY and credentials via environment variables in production
- **Development Mode**: credentials.json for easy development, with warnings for production use
- **Role-Based Access**: Admin users can manage users and configurations, operators can only control displays
- **Audit Logging**: All authentication attempts and configuration changes logged

### Display Management
- **Multi-Protocol Support**: RS232 serial and TCP/IP network connections
- **Classification Levels**: Unclassified, Classified, Secret, Top Secret
- **Real-time Updates**: AJAX-based status refresh without page reload
- **Image Upload**: Custom images per display for room identification
- **Manual Control**: Web-based interface for immediate classification changes

### Admin Features
- **User Management**: Web-based credential editing (development mode)
- **System Logs**: Real-time viewer for audit.log and classification_audit.log
- **Admin Guide**: Built-in documentation viewer
- **Configuration Interface**: Three-tab admin panel for all administrative functions

## External Dependencies

### Runtime Environment
- **Python 3.8+**: Uses only Python standard library modules - NO external packages required
- **File System Access**: Read/write access for configuration and log files
- **Serial Communication**: pyserial for RS232 display control (optional - can be installed if needed)
- **Network Sockets**: TCP/IP communication for network displays (built-in)

### Display Hardware
- **RS232 Serial Displays**: Direct serial connection via COM ports
- **TCP/IP Network Displays**: Network-connected displays with command protocol
- **Classification Banner Systems**: Compatible display systems that accept classification commands

### Browser Compatibility
- **Modern Web Browsers**: Requires ES6+ support for JavaScript
- **AJAX Support**: XMLHttpRequest for dynamic updates
- **CSS3**: Modern CSS features for styling and animations
