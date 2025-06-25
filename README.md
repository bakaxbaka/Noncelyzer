# Noncelyzer
This is a web-based Bitcoin vulnerability analyzer that examines Bitcoin addresses for cryptographic vulnerabilities, specifically focusing on nonce reuse and message hash reuse attacks that could potentially expose private keys. The application is built with Flask and provides a user-friendly interface for analyzing Bitcoin transactions.
System Architecture

The application follows a traditional three-tier web architecture:
Frontend

    Framework: HTML templates with Bootstrap 5 (dark theme)
    Styling: Custom CSS with gradient backgrounds and modern UI components
    JavaScript: Vanilla JavaScript for form validation, progress monitoring, and user interactions
    UI Components: Responsive design with cards, progress bars, and alerts

Backend

    Framework: Flask (Python web framework)
    WSGI Server: Gunicorn for production deployment
    Session Management: Flask sessions with configurable secret key
    Middleware: ProxyFix for proper header handling behind proxies

Core Analysis Engine

    Bitcoin Analyzer: Custom cryptographic analysis module (bitcoin_analyzer.py)
    Crypto Utilities: Low-level cryptographic functions (crypto_utils.py)
    API Integration: Blockstream.info API for fetching Bitcoin transaction data

Key Components
1. Web Application (app.py)

    Purpose: Main Flask application with route handlers
    Key Routes:
        / - Main page with address input form
        /analyze - POST endpoint for analyzing Bitcoin addresses
    Features: Error handling, flash messages, form validation

2. Bitcoin Analyzer (bitcoin_analyzer.py)

    Purpose: Core analysis engine for detecting vulnerabilities
    Key Functions:
        Address validation
        Transaction fetching from Blockstream API
        Progress tracking for long-running analyses
    Vulnerability Detection: Identifies nonce reuse and message hash reuse patterns

3. Cryptographic Utilities (crypto_utils.py)

    Purpose: Low-level cryptographic operations
    Key Functions:
        Modular inverse computation using extended Euclidean algorithm
        Bitcoin address format validation (Legacy, SegWit, Bech32)
        SECP256K1 curve operations
    Security: Handles cryptographic edge cases and validation

4. Frontend Assets

    Templates: Jinja2 templates for HTML rendering
    Static Files: CSS for styling and JavaScript for interactivity
    Progress Monitoring: Real-time progress updates during analysis

Data Flow

    User Input: User enters Bitcoin address through web form
    Validation: Address format validation on both frontend and backend
    Transaction Fetching: API calls to Blockstream.info to retrieve transaction history
    Cryptographic Analysis:
        Parse transaction signatures
        Extract r, s, z values from ECDSA signatures
        Compare signature patterns across transactions
        Detect vulnerability patterns (nonce reuse, hash reuse)
    Results Display: Present findings in structured format with vulnerability details

External Dependencies
APIs

    Blockstream.info API: Primary source for Bitcoin blockchain data
        Rate limited requests with 100ms delays
        Pagination support for addresses with many transactions
        RESTful JSON API

Python Packages

    Flask 3.1.1: Web framework
    Requests 2.32.4: HTTP client for API calls
    Base58 2.1.1: Bitcoin address encoding/decoding
    Gunicorn 23.0.0: WSGI HTTP server
    Werkzeug 3.1.3: WSGI utilities and development server

Frontend Libraries

    Bootstrap 5: UI framework with dark theme
    Font Awesome 6.0: Icon library
    Custom CSS: Application-specific styling

Deployment Strategy
Environment

    Platform: Replit with Nix package management
    Python Version: 3.11
    System Packages: OpenSSL, PostgreSQL (available but not currently used)

Configuration

    Development: Flask development server with auto-reload
    Production: Gunicorn with autoscale deployment target
    Port Binding: 0.0.0.0:5000 with port reuse enabled
    Process Management: Parallel workflow execution

Security Considerations

    Session secret key configuration via environment variable
    Input validation and sanitization
    Rate limiting for external API calls
    Error handling to prevent information disclosure

Changelog

Changelog:
- June 24, 2025. Initial setup
- June 24, 2025. Enhanced nonce reuse detection using pcaversaccio/ecdsa-nonce-reuse-attack algorithm
  - Added ecdsa library dependency for optimized cryptographic operations
  - Implemented robust private key recovery with improved mathematical precision
  - Added technical details display in vulnerability reports
  - Enhanced confidence scoring for recovered keys
  - Improved error handling and edge case detection
- June 24, 2025. Integrated comprehensive ECDSA nonce reuse attack methodology
  - Implemented two-step recovery: nonce extraction then private key derivation
  - Added mathematical verification of recovered private keys
  - Enhanced UI with detailed ECDSA technical information display
  - Added nonce recovery using k = (s1-s2)^-1 * (z1-z2) formula
  - Improved educational content with step-by-step attack explanation
  - Added verification status indicators for recovered keys

User Preferences

Preferred communication style: Simple, everyday language.
