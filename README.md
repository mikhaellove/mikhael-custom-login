# Mikhael's Custom Secure Auth

![Version](https://img.shields.io/badge/version-2.0.1-blue.svg)
![WordPress](https://img.shields.io/badge/WordPress-5.0%2B-brightgreen.svg)
![License](https://img.shields.io/badge/license-GPL--2.0%2B-orange.svg)

A privacy-first, security-hardened authentication plugin for WordPress that I built for my NSFW content site. It's completely free and open-source because I believe good security shouldn't be locked behind paywalls.

## Why I Built This

After testing dozens of authentication plugins for my adult content site, I realized they all fell short in one critical area: user privacy. Most plugins leak whether a username or email exists through timing attacks, error messages, or REST API endpoints. This makes it trivial for stalkers or bad actors to enumerate users.

I needed something better. So I built it. 

## Core Philosophy

**Privacy First**: Every design decision prioritizes user anonymity and protection against enumeration attacks.

**Security by Default**: HMAC tokens, rate limiting, honeypots, and configurable lockouts work out of the box.

**Zero Enumeration**: Generic error messages, consistent timing, and blocked REST endpoints prevent user discovery.

**Developer Friendly**: Clean code, extensive inline documentation, and logical file structure make customization straightforward.

## Key Features

### Security Hardening

**Zero-Enumeration Authentication**
- Generic error messages that never reveal if a user exists
- Consistent response timing regardless of account status
- Password recovery that always returns "email sent if account exists"
- Username policy violations return the same error as existing accounts

**The 403 Gauntlet** (Multi-Layer Request Validation)
- HMAC-based CSRF tokens (not WordPress nonces)
- Timed token expiration (configurable, default 30 minutes)
- HTTP Referer validation
- IP-based rate limiting with configurable thresholds
- Honeypot fields for bot detection
- Google reCAPTCHA v3 integration
- Security event logging for forensics

**REST API Security**
- Block user enumeration endpoints (`/wp/v2/users`)
- Require authentication for all REST API access
- Namespace whitelisting for public endpoints
- Real-time blocked request logging (last 20 attempts)
- XML-RPC blocking with standard 404 response

**Rate Limiting & Lockouts**
- Configurable max failed attempts (default: 5)
- Configurable lockout duration (default: 1 hour)
- IP-based tracking with Cloudflare support
- Automatic IP release after lockout expires

### Form Builder & Customization

**Visual Grid-Based Form Builder**
- Drag-and-drop interface for registration forms
- Configurable field widths (33%, 50%, 100%)
- Required/optional field toggle
- Custom placeholder text
- Field reordering without code
- Password confirmation with strength indicator
- Privacy warning customization

**Custom Email Templates**
- HTML email support
- Template variables: `{user_name}`, `{site_name}`, `{set_password_url}`, `{user_email}`
- Separate templates for activation and password recovery
- Custom subject lines

**Username Policy Enforcement**
- Reserved words list (admin, root, moderator, etc.)
- Strict content blocking (substring match for offensive terms)
- Isolated content blocking (word boundary match)
- Configurable boundary matching for reserved words
- Fun username generator with 2.6M+ combinations
- Privacy-focused random usernames (e.g., "digital_goblin429")

### Registration Flows

**Hybrid Registration System**

*Flow A1: Password Provided*
- User registers with password
- Account activated immediately
- Auto-login after registration (optional)
- Redirect to configured page

*Flow A2: Email Activation*
- User registers without password
- Receives activation email with unique key
- Sets password upon activation
- 24-hour key expiration

*Flow B: Standard Login*
- Checks for pending activation
- Prevents login until account activated
- Rate limiting on failed attempts

*Flow C: Password Recovery*
- Always returns generic success message
- Sends email only if account exists
- Uses WordPress core `retrieve_password()` with custom templates

*Flow D: Password Reset/Activation*
- Single endpoint for both reset and activation
- Validates WordPress reset keys or custom activation keys
- Auto-login after reset (optional)
- Configurable redirect behavior

### User Experience

**Password Management**
- Strength indicator (weak/medium/strong)
- Show/hide password toggle
- Minimum 8 characters enforced
- Confirmation field validation

**Smart Redirects**
- Configurable post-login redirect
- Logout redirect to custom login page
- Transient-based logout confirmation message

**Integration Features**
- Tracks last login time (displayed in user table)
- Custom user columns in admin panel
- Works with governance logging (NSFW restrictions plugin)
- Compatible with `[nsfw_tos_interceptor]` shortcode

## Installation

### Standard Installation

1. Download or clone this repository
2. Upload to `/wp-content/plugins/mikhael-custom-login/`
3. Activate through WordPress admin
4. Navigate to **Settings > Secure Auth**

### Quick Setup

1. **Create Pages**: Login, Register, Forgot Password, Reset Password
2. **Add Shortcodes** to each page (see below)
3. **Map Pages** in Settings > Secure Auth > Page Mapping
4. **Configure Security** in Settings > Secure Auth > Security
5. **Build Form** in Settings > Secure Auth > Registration Grid Builder

## Shortcodes

```
[auth_login]           - Login form
[auth_register]        - Registration form (uses Grid Builder config)
[auth_lost_password]   - Password recovery form
[auth_set_password]    - Password reset/activation form
[auth_button]          - Dynamic auth button (login/logout/register links)
```

## Configuration Guide

### Page Mapping

Navigate to **Settings > Secure Auth > Page Mapping & Logic**

**Required Pages:**
- Login Page (add `[auth_login]`)
- Registration Page (add `[auth_register]`)
- Lost Password Page (add `[auth_lost_password]`)
- Set Password Page (add `[auth_set_password]`)

**Additional Settings:**
- Redirect after login (dropdown selector)
- Token expiry duration (default: 30 minutes)
- Auto-login after password reset (checkbox)

### Security Settings

Navigate to **Settings > Secure Auth > Security**

**Basic Security:**
- Honeypot Protection (enabled by default)
- Max Failed Attempts (default: 5)
- Lockout Duration (default: 1 hour)

**reCAPTCHA v3:**
- Site Key (from Google reCAPTCHA admin)
- Secret Key (from Google reCAPTCHA admin)

**REST API Security:**
- Disable User Enumeration (recommended: enabled)
- Block XML-RPC (prevents brute force and pingback DDoS)
- Require Authentication (blocks unauthenticated REST access)
- Whitelisted Namespaces (comma-separated, supports tags)
- Recent Blocked Attempts Log (last 20 blocked routes with timestamps and IPs)

### Registration Grid Builder

Navigate to **Settings > Secure Auth > Registration Grid Builder**

**Available Fields:**
- Username (with optional fun generator)
- Email
- Password (with confirmation and strength indicator)
- First Name
- Last Name

**Configuration:**
- Drag to reorder fields
- Toggle required/optional
- Set field width (33%, 50%, 100%)
- Add placeholder text
- Enable/disable fun username generator
- Customize privacy warning message

### Username Policy

Navigate to **Settings > Secure Auth > Username Policy**

**Reserved Words** (tag-based input):
- System reserved: admin, administrator, root, system, moderator
- Prevent impersonation of staff or system accounts
- Optional word boundary matching

**Restricted Words - Strict Block** (substring match):
- Offensive content that should never appear
- Blocks if word appears anywhere in username
- Case-insensitive matching

**Restricted Words - Isolated Block** (word boundary match):
- Context-dependent words (ass, dick, sex)
- Blocks only when word stands alone
- More lenient than strict blocking

**Error Handling:**
- Generic violation message: "Username contains content that goes against my guidelines"
- Prevents attackers from testing content filter rules
- Consistent error format with other registration failures

### Email Templates

Navigate to **Settings > Secure Auth > Email Templates**

**Activation Email:**
```
Subject: Activate Your Account - {site_name}
Body: <p>Hello {user_name},</p>
      <p>Click below to activate your account:</p>
      <p><a href="{set_password_url}">Activate Account</a></p>
```

**Recovery Email:**
```
Subject: Reset Your Password - {site_name}
Body: <p>Hello {user_name},</p>
      <p>Click below to reset your password:</p>
      <p><a href="{set_password_url}">Reset Password</a></p>
```

**Available Variables:**
- `{user_name}` - Username
- `{user_email}` - Email address
- `{site_name}` - WordPress site title
- `{set_password_url}` - Activation or reset link (includes key and login)

## Technical Details

### Security Architecture

**HMAC Token System:**
- Generated with `AUTH_KEY` constant from `wp-config.php`
- Combined with IP address and timestamp
- Validated using `hash_equals()` for timing-attack resistance
- Automatic expiration enforcement

**IP Detection Hierarchy:**
1. Cloudflare: `HTTP_CF_CONNECTING_IP`
2. Proxy: `HTTP_X_FORWARDED_FOR` (first IP in list)
3. Direct: `REMOTE_ADDR`

**Security Event Logging:**
- Stores last 1000 security events
- Event types: blocked_ip, invalid_referer, invalid_token, honeypot_triggered
- Includes timestamp, IP, user agent, and event-specific data
- Critical events logged to PHP error_log

**REST API Blocking:**
- Logs blocked routes with timestamp, full route path, and IP
- Displays last 20 blocked attempts in admin UI
- Helps debug plugin conflicts and identify attack patterns
- Auto-maintains log size (max 20 entries)

### Username Generation Algorithm

**Fun Username Format:** `{Prefix}_{Suffix}{100-999}`

**Prefix Categories:**
- Tech/AI: Digital, Cyber, Neural, Quantum, etc.
- Mood/Personality: Unapologetic, Sassy, Chaotic, etc.
- Aesthetic/Texture: Velvet, Neon, Chrome, etc.
- Absurd/Internet: Wobbly, Moist, Haunted, etc.

**Suffix Categories:**
- Hardware/Tech: Clanker, GPU, Node, Server, etc.
- Art/Abstract: Gaze, Void, Shadow, Echo, etc.
- Creatures: Goblin, Gremlin, Dragon, etc.
- Random Objects: Toast, Potato, Cactus, etc.

**Collision Avoidance:**
- Generates until unique username found
- Checks `username_exists()` before returning
- 2.6M+ possible combinations
- Lowercase output for consistency

### Database Structure

**Settings Storage:**
- Option name: `csa_settings`
- Structured array with sections: security, grid_builder, page_mapping, emails, username_policy, global_config
- Autoload: false (manual loading for performance)

**Security Logs:**
- Option name: `csa_security_logs`
- Array of log entries (max 1000)
- Fields: timestamp, event_type, ip_address, user_agent, data
- Autoload: false

**Blocked Namespaces Log:**
- Option name: `csa_blocked_namespaces_log`
- Array of blocked REST API attempts (max 20)
- Fields: timestamp, route, ip
- Autoload: false

**User Meta:**
- `csa_activation_pending` - Boolean flag
- `csa_activation_key` - 20-character random key
- `csa_activation_key_expiry` - Unix timestamp (24 hours from creation)
- `csa_last_login` - Unix timestamp (updated via `set_auth_cookie` hook)

## Use Cases

### NSFW Content Sites

**Why I Built This:**
I run an adult content site where user privacy is paramount. Standard login plugins leak user information through various attack vectors.

**Recommended Settings:**
- Enable all zero-enumeration features
- Use email activation flow (disable auto-login after registration)
- Enable fun username generator
- Add privacy warning about anonymous usernames
- Enable strict content filtering in username policy
- Require REST API authentication
- Block XML-RPC endpoint

**Result:**
Users can register and access content while maintaining complete anonymity. Stalkers and harassment attempts are significantly reduced.

### Membership Sites

**Ideal For:**
- Online courses
- Premium content
- Community forums
- Subscription services

**Recommended Settings:**
- Use hybrid registration (password optional)
- Custom email templates with branding
- Reserved words for premium usernames
- Redirect after login to welcome page
- Enable reCAPTCHA for bot protection

### Privacy-Focused Platforms

**Ideal For:**
- Whistleblower platforms
- Anonymous forums
- Mental health communities
- Any platform where user privacy matters

**Recommended Settings:**
- Maximum security hardening
- Force fun username generator
- Disable all enumeration endpoints
- Require email activation
- Monitor security logs regularly

## Compatibility

**WordPress:** 5.0+ (tested up to 6.4+)

**PHP:** 7.4+ (8.0+ recommended)

**Server Requirements:**
- Support for WordPress REST API
- Ability to modify HTTP headers
- PHP functions: `hash_hmac`, `wp_remote_post`, `json_decode`

**Tested Environments:**
- Cloudflare proxy (automatic IP detection)
- Nginx + PHP-FPM
- Apache + mod_php
- Various shared hosting providers

**Theme Compatibility:**
- Divi
- Elementor
- Astra
- GeneratePress
- Any standards-compliant WordPress theme

**Known Integrations:**
- **mikhael-nsfw-restrictions**: Governance logging for authentication events
- **mikhael-shadow-mode**: Respects shadow mode event logging filters
- WordPress core authentication hooks

**Known Conflicts:**
- None reported

## Troubleshooting

### Authentication Issues

**Blank screen or white page:**
- Check PHP error logs
- Disable other plugins to isolate conflict
- Verify PHP version meets requirements

**Token validation failing:**
- Verify REST API is accessible: `yoursite.com/wp-json/custom-secure-auth/v1/get-token`
- Check browser console for JavaScript errors
- Confirm `AUTH_KEY` exists in `wp-config.php`
- Clear browser cache and cookies

**Users not receiving emails:**
- Test WordPress email functionality
- Install SMTP plugin (WP Mail SMTP recommended)
- Check spam folders
- Verify email template syntax
- Check server email logs

### Rate Limiting Issues

**Legitimate users getting locked out:**
- Increase max failed attempts (try 10 instead of 5)
- Reduce lockout duration (try 15 minutes instead of 1 hour)
- Check if Cloudflare or proxy is causing IP conflicts
- Review security logs for patterns

**Attacks bypassing rate limiting:**
- Verify IP detection is working correctly
- Check for distributed attacks from multiple IPs
- Consider implementing additional security measures
- Review blocked namespaces log for patterns

### REST API Issues

**Plugin features not working:**
- Check "Recent Blocked Attempts" log in Security settings
- Add required namespaces to whitelist
- Temporarily disable "Require Authentication" to test
- Verify namespace format (lowercase, no `/wp-json/` prefix)

**Performance concerns:**
- REST API blocking has minimal performance impact
- Logging is capped at 20 entries
- Consider disabling verbose logging in production

### Form Display Issues

**Form looks unstyled:**
- Plugin uses minimal styling by design
- Add custom CSS in your theme
- Use Button CSS Classes field to match theme styles
- Check for theme CSS conflicts

**Fields not appearing:**
- Verify Grid Builder configuration is saved
- Check JavaScript console for errors
- Clear WordPress object cache if using caching plugin
- Rebuild form in Grid Builder

## Security Best Practices

### Essential Recommendations

**1. Use HTTPS**
SSL/TLS is non-negotiable for authentication. Password transmission over HTTP is a critical security vulnerability. Use Let's Encrypt for free certificates.

**2. Enable reCAPTCHA**
Bot attacks are constant and relentless. Google reCAPTCHA v3 is invisible to users and highly effective. Get free API keys from Google.

**3. Monitor Security Logs**
Check the blocked namespaces log regularly. Sudden spikes in blocked attempts may indicate an active attack.

**4. Configure Appropriate Rate Limits**
- Public sites: 5 attempts, 1-hour lockout
- Internal systems: 3 attempts, 24-hour lockout
- High-traffic sites: 10 attempts, 30-minute lockout

**5. Use Email Activation**
For high-security sites, disable auto-login after registration and require email activation. This adds friction but significantly improves security.

**6. Keep WordPress Updated**
Outdated WordPress installations are the #1 security risk. Enable automatic updates for minor releases.

**7. Regular Database Backups**
Authentication changes affect user access. Maintain daily backups before making configuration changes.

### Advanced Security

**Username Policy Configuration:**
- Start with strict blocking for obvious offensive terms
- Add reserved words relevant to your site (staff, vip, premium)
- Monitor registration attempts to identify new patterns
- Update policies based on actual abuse patterns

**REST API Hardening:**
- Enable "Require Authentication" only after testing all site functionality
- Whitelist namespaces conservatively (only what's necessary)
- Review blocked attempts log weekly to catch false positives
- Block XML-RPC unless specifically needed for Jetpack or mobile app

**Token Expiry Strategy:**
- 30 minutes is safe for most sites
- Reduce to 10 minutes for high-security environments
- Increase to 60 minutes if users commonly pause during registration
- Balance security with user experience

## Performance Considerations

**Database Queries:**
- Settings loaded once per page load
- Security logs write on events only (not on every request)
- User meta queries use WordPress object cache when available

**REST API Impact:**
- Token generation: < 1ms overhead
- Token validation: < 2ms overhead
- Rate limit check: < 1ms overhead (transient-based)

**Recommended Caching:**
- Use object caching (Redis/Memcached) for high-traffic sites
- Exclude authentication pages from page caching
- Exclude REST API endpoints from CDN caching

## Development & Customization

### File Structure

```
mikhael-custom-login/
├── mikhael-custom-login.php       # Main plugin file, hooks initialization
├── README.md                       # This file
├── includes/
│   ├── class-admin-settings.php   # Admin UI, settings pages, form builder
│   ├── class-rest-handler.php     # REST endpoints, 403 gauntlet, authentication flows
│   ├── class-email-manager.php    # Email templates, WordPress mail filters
│   ├── class-shortcodes.php       # Shortcode rendering, form HTML generation
│   ├── class-user-columns.php     # Admin user table customization, last login
│   └── class-profile-editor.php   # Future: User profile management
├── assets/
│   ├── css/
│   │   ├── admin-style.css        # Admin panel styling
│   │   └── frontend-style.css     # Form styling (minimal by design)
│   └── js/
│       ├── admin-script.js        # Grid builder, tag input, UI interactions
│       └── frontend-script.js     # Token handling, form validation, AJAX
```

### Hooks & Filters

**Actions:**
- `set_auth_cookie` - Tracks last login time
- `rest_api_init` - Registers REST endpoints
- `wp_login_failed` - Increments failed attempt counter (if NSFW plugin active)

**Filters:**
- `rest_authentication_errors` - Enforces REST API authentication
- `rest_endpoints` - Removes user enumeration endpoints
- `xmlrpc_enabled` - Blocks XML-RPC when configured
- `logout_redirect` - Redirects to custom login page
- `retrieve_password_message` - Customizes password reset email (via email manager)
- `wp_mail` - Applies email templates (via email manager)

### Extending Functionality

**Custom Registration Fields:**
Edit `class-shortcodes.php` and add fields to the Grid Builder configuration. Fields are stored as serialized array in plugin settings.

**Custom Validation:**
Hook into `csa_before_registration` action (if added) or modify `handle_registration()` in `class-rest-handler.php`.

**Custom Email Templates:**
Edit via Settings > Secure Auth > Email Templates or programmatically filter template content before sending.

**Security Event Logging:**
Call `$this->log_security_event($event_type, $ip, $data)` from within REST handler methods.

## Changelog

### Version 2.0.1 (Current)

**Added:**
- XML-RPC blocking with standard 404 response
- REST API blocked request logging (last 20 attempts)
- Endpoint tracking in governance logs for failed login attempts
- Login Endpoint Analysis audit (NSFW restrictions plugin integration)

**Security:**
- Enhanced user enumeration protection
- Improved error message consistency
- Added security event logging to blocked REST API attempts

**Bug Fixes:**
- Fixed missing login attempt endpoint logging
- Restored REST API blocking log functionality

### Version 2.0.0

**Major Rewrite:**
- Complete security overhaul with zero-enumeration architecture
- HMAC-based token system replacing WordPress nonces
- Grid-based form builder for registration
- Username policy system with multiple filtering tiers
- Hybrid registration flows (with/without password)

**Breaking Changes:**
- Settings structure completely reorganized
- Old shortcode parameters no longer supported
- Custom templates require migration

## License

**GNU General Public License v2.0 or later**

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

## Support & Contributions

**Bug Reports:** Open an issue on GitHub with detailed reproduction steps.

**Feature Requests:** Check existing issues first, then open a new request with clear use case description.

**Security Issues:** Email directly (don't open public issues for security vulnerabilities).

**Pull Requests:** Welcome! Please follow WordPress coding standards and include tests when applicable.

## Credits

**Author:** Mikhael Love

**Contributors:**
- Claude (Anthropic) - Architecture, code review, documentation
- WordPress Community - Core functionality and best practices

**Inspiration:**
- Too many overpriced authentication plugins
- Lack of privacy-focused solutions in the WordPress ecosystem
- Real-world security requirements from running an NSFW content site

**Built With:**
- WordPress REST API
- WordPress Settings API
- Vanilla JavaScript (no jQuery dependency)
- PHP 7.4+ features

---

**This plugin is completely free and always will be.** I built it because I needed it, and I'm sharing it because the WordPress community has given me so much over the years. If you find it useful, consider contributing to the WordPress project or helping others in the community.

Made with care and attention to security by Mikhael Love.
