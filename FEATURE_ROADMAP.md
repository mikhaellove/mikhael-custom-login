# Mikhael's Custom Secure Auth - Feature Roadmap

**Plugin Version:** 2.0.1
**Last Updated:** 2026-02-08

---

## 📋 Table of Contents

- [Current Features](#current-features)
- [Missing Features](#missing-features)
- [Feature Comparison Summary](#feature-comparison-summary)
- [Recommended Implementation Phases](#recommended-implementation-phases)
- [Competitive Advantages](#competitive-advantages)

---

## ✅ Current Features

### **Authentication & User Management**
- ✅ Custom login form via shortcode `[auth_login]`
- ✅ Custom registration form via shortcode `[auth_register]`
- ✅ Password recovery via shortcode `[auth_lost_password]`
- ✅ Password reset/activation via shortcode `[auth_set_password]`
- ✅ Email-based account activation (Flow A2)
- ✅ Hybrid registration (with/without password)
- ✅ Auto-login after registration (Flow A1)
- ✅ Auto-login after password reset (configurable)
- ✅ Custom redirect after login (page selector)
- ✅ Fun username generator

### **Security Features**
- ✅ HMAC token-based CSRF protection
- ✅ IP-based rate limiting (max failed attempts configurable)
- ✅ Temporary IP lockout (configurable duration)
- ✅ Honeypot spam protection
- ✅ Google reCAPTCHA v3 integration
- ✅ Referer validation
- ✅ Username policy enforcement (reserved words, restricted content)
- ✅ REST API authentication requirement (configurable)
- ✅ User enumeration prevention (registration, password recovery, REST API)
- ✅ Security event logging
- ✅ Token expiry configuration

### **Customization**
- ✅ Grid-based registration form builder
- ✅ Custom email templates (activation, recovery)
- ✅ Page mapping (login, register, lost password, set password)
- ✅ Button CSS class customization
- ✅ Username privacy warning message
- ✅ Password strength indicator
- ✅ Password visibility toggle (show/hide)

### **Admin Features**
- ✅ Settings UI with tabbed interface
- ✅ Page mapping configuration
- ✅ Security settings (403 Vault)
- ✅ Grid builder for registration fields
- ✅ Username policy management (tiered filtering)
- ✅ Email template editor
- ✅ Shortcode documentation
- ✅ Blocked namespace logging

---

## ❌ Missing Features (Industry Standard Gaps)

### **🔴 HIGH PRIORITY - Security**

#### 1. Two-Factor Authentication (2FA)
- Email-based OTP
- Authenticator app (TOTP) support
- Backup codes
- Per-user 2FA toggle
- **Why important:** Industry standard for secure sites, especially for NSFW/membership content

#### 2. Session Management
- Force logout on all devices
- Concurrent session limits
- Session timeout configuration
- Active sessions viewer
- **Why important:** Protects users from unauthorized access

#### 3. Login Security Enhancements
- Login attempt notification emails
- New device/location email alerts
- Temporary login freeze after suspicious activity
- **Why important:** User awareness and proactive security

#### 4. Admin-Specific Security
- Admin bar login link redirection (noted as pending)
- Hide wp-login.php URL (custom login slug)
- Disable wp-admin access for non-admins
- **Why important:** Reduces attack surface

---

### **🟡 MEDIUM PRIORITY - Authentication**

#### 5. Social Login (OAuth)
- Google Sign-In
- Facebook Login
- Twitter/X Login
- Discord Login (especially relevant for NSFW communities)
- **Why important:** 20% higher conversion rates, reduces friction

#### 6. Passwordless Authentication
- Magic link via email (one-time login links)
- WebAuthn/Passkeys (Face ID, Touch ID, Windows Hello)
- **Why important:** Modern UX, eliminates password fatigue

#### 7. Profile Management Shortcodes
- `[auth_profile]` - User profile editor
- `[auth_change_password]` - Standalone password change
- `[auth_delete_account]` - Account deletion (GDPR compliance)
- **Why important:** Complete user lifecycle management

#### 8. Login History & Activity Log
- User-facing login history (date, IP, device, location)
- Failed login attempts visible to users
- Export login history
- **Why important:** Transparency and user trust

---

### **🟢 LOW PRIORITY - User Experience**

#### 9. Remember Me Functionality
- "Remember me" checkbox on login
- Configurable remember duration
- **Why important:** Convenience without compromising security

#### 10. Login Redirects (Advanced)
- Role-based redirect rules (subscriber → profile, admin → dashboard)
- First-login redirect (e.g., onboarding page)
- Logout redirect configuration
- **Why important:** Tailored user journeys

#### 11. AJAX Form Handling Improvements
- Live username availability checker (without enumeration)
- Real-time password strength with requirements list
- Inline validation with specific field errors
- **Why important:** Better UX, reduces form abandonment

#### 12. Login Widget/Block
- Gutenberg block for login form
- Widget for sidebars
- **Why important:** Flexibility in placement

#### 13. Custom Login Page Styling
- Visual customizer (logo, colors, background)
- CSS customizer with live preview
- Pre-built templates
- **Why important:** Brand consistency

#### 14. Email Enhancements
- Email verification before account activation
- Welcome email after first login
- Email change verification (for profile updates)
- HTML email template designer
- **Why important:** Professional communication

---

### **🔵 NICE-TO-HAVE - Advanced**

#### 15. Registration Moderation
- Admin approval required before activation
- Pending users management dashboard
- Auto-approve based on rules (e.g., email domain whitelist)
- **Why important:** Quality control for membership sites

#### 16. Geolocation & Device Tracking
- Block logins from specific countries
- Device fingerprinting
- Login location on map (admin view)
- **Why important:** Advanced security for high-risk sites

#### 17. Login Form Variations
- Modal/popup login form
- Inline login form (no page redirect)
- Conditional display (show login to logged-out users only)
- **Why important:** Design flexibility

#### 18. WooCommerce Integration
- Replace WooCommerce login/registration
- Checkout registration integration
- **Why important:** E-commerce compatibility

#### 19. Compliance Features
- GDPR consent checkbox on registration
- Terms of Service acceptance logging (already have TOS interceptor)
- Privacy policy acknowledgment
- Data export/deletion hooks
- **Why important:** Legal compliance

#### 20. Developer Features
- REST API endpoints for external apps
- Webhooks for auth events
- Custom field hooks for third-party plugins
- **Why important:** Extensibility for advanced users

---

## 📊 Feature Comparison Summary

| Category | Current Features | Missing Features | Coverage |
|----------|------------------|------------------|----------|
| **Authentication** | 10 | 6 | 62% |
| **Security** | 11 | 4 | 73% |
| **Customization** | 9 | 5 | 64% |
| **User Experience** | 4 | 8 | 33% |
| **Admin/Management** | 8 | 3 | 73% |
| **Compliance** | 1 | 3 | 25% |
| **Total** | **43** | **29** | **60%** |

---

## 🎯 Recommended Implementation Phases

### **Phase 1: Security Hardening** (v2.1.0)
**Priority:** Critical
**Timeline:** Q1 2026

1. **Two-Factor Authentication (2FA)** - Email-based OTP as MVP
   - Add OTP generation and validation
   - Per-user 2FA settings
   - Backup codes system

2. **Session Management**
   - Force logout on all devices
   - Concurrent session limits
   - Active sessions viewer

3. **Admin Bar Login Redirection** (already identified as pending)
   - Remove function from added-security plugin
   - Add to mikhael-custom-login

4. **Login Notification Emails**
   - New device detection
   - Location-based alerts
   - Configurable notification preferences

---

### **Phase 2: Modern Authentication** (v2.2.0)
**Priority:** High
**Timeline:** Q2 2026

5. **Social Login (OAuth)**
   - Google Sign-In integration
   - Discord Login (NSFW community relevance)
   - Facebook Login (optional)

6. **Magic Link Passwordless Authentication**
   - One-time login link generation
   - Email delivery system
   - Link expiry configuration

7. **Profile Management Shortcodes**
   - `[auth_profile]` - Profile editor
   - `[auth_change_password]` - Password change form
   - `[auth_delete_account]` - Account deletion with confirmation

---

### **Phase 3: User Experience Enhancement** (v2.3.0)
**Priority:** Medium
**Timeline:** Q3 2026

8. **Remember Me Functionality**
   - Persistent login checkbox
   - Configurable duration (7, 14, 30 days)
   - Secure cookie implementation

9. **Role-Based Redirects**
   - Redirect rules by user role
   - First-login redirect
   - Logout redirect configuration

10. **Login History Viewer**
    - User-facing login history table
    - Failed attempt log
    - Export to CSV

11. **AJAX Validation Improvements**
    - Real-time password strength with requirements
    - Inline field validation
    - Better error messaging

---

### **Phase 4: Premium Features** (v3.0.0)
**Priority:** Low
**Timeline:** Q4 2026

12. **WebAuthn/Passkeys**
    - Face ID, Touch ID, Windows Hello support
    - Hardware security key support
    - Fallback authentication methods

13. **Registration Moderation**
    - Admin approval workflow
    - Pending users dashboard
    - Auto-approve rules

14. **Geolocation Blocking**
    - Country-based access control
    - IP-to-location mapping
    - Whitelist/blacklist management

15. **Visual Login Page Customizer**
    - Logo upload
    - Color scheme picker
    - Background customization
    - Live preview

---

## 💡 Competitive Advantages

Your plugin already has several features that set it apart from competitors:

### **Unique Features**
- ✨ **Hybrid registration flows** (with/without password) - Not found in most plugins
- ✨ **Multi-tier username filtering** (reserved, strict, isolated) - Advanced content moderation
- ✨ **Grid-based form builder** - More flexible than standard form templates
- ✨ **Anti-enumeration by design** - Privacy-first approach from the ground up
- ✨ **Fun username generator** - User-friendly and unique
- ✨ **NSFW-focused** - Complements NSFW Restrictions plugin for niche market

### **Security-First Design**
- Zero-enumeration authentication flows
- HMAC-based CSRF protection (more robust than nonces alone)
- Comprehensive security event logging
- Username policy enforcement with tiered filtering

### **Developer-Friendly**
- Clean, modular architecture
- WordPress coding standards compliant
- RESTful API design
- Extensive inline documentation

---

## 🚀 Next Steps

### **Immediate Focus (v2.1.0)**
1. **Two-Factor Authentication (2FA)** - Email-based OTP
   - Most requested security feature
   - Relatively straightforward implementation
   - High perceived value

2. **Session Management**
   - Critical for user security
   - Prevents unauthorized access
   - Complements 2FA

3. **Login Notification Emails**
   - Low implementation effort
   - High user appreciation
   - Builds trust

### **Research & Planning**
- OAuth provider comparison (Google, Discord, Facebook APIs)
- WebAuthn implementation strategies
- GDPR compliance requirements for user data

### **Community Feedback**
- Survey users on desired features
- Monitor WordPress plugin repository feedback
- Track competitor feature releases

---

## 📝 Notes

- This roadmap is based on industry research conducted in February 2026
- Features are prioritized based on security impact, user demand, and implementation complexity
- Timeline estimates are subject to change based on development resources
- Open-source release planned after Phase 1 completion

---

**Maintained by:** Mikhael Love
**Contributors:** Claude (AI Assistant)
**Last Review:** 2026-02-08
