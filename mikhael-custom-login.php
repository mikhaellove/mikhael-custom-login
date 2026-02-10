<?php
/**
 * Plugin Name: Mikhael's Custom Secure Auth
 * Description: A secure, modular authentication system with custom login, registration, password reset, grid-based form builder, frontend profile editor, and advanced security features.
 * Version: 2.1.0
 * Author: Mikhael Love
 * Text Domain: custom-secure-auth
 * Domain Path: /languages
 * License: GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 *
 * @package Custom_Secure_Auth
 * @version 2.1.0
 * @since 1.0.0
 *
 * PLUGIN ARCHITECTURE OVERVIEW
 * ============================
 * This plugin implements a multi-layered security-first authentication system
 * designed to prevent user enumeration, brute force attacks, and unauthorized access.
 *
 * Core Components:
 * ----------------
 * 1. REST Handler (class-rest-handler.php)
 *    - Implements "The 403 Gauntlet" - 5-layer security validation
 *    - Handles registration, login, password recovery, and password setting
 *    - Manages HMAC-based CSRF tokens (not WordPress nonces)
 *    - Zero-enumeration error messaging
 *
 * 2. Admin Settings (class-admin-settings.php)
 *    - Multi-tab settings interface
 *    - Grid-based form builder for registration forms
 *    - Username policy management
 *    - Role-based session expiration control (v2.1.0+)
 *    - Email template customization
 *
 * 3. Email Manager (class-email-manager.php)
 *    - Custom HTML email templates
 *    - Admin registration notifications (v2.1.0+)
 *    - Activation and password recovery emails
 *    - Template variable replacement system
 *
 * 4. Shortcodes (class-shortcodes.php)
 *    - Frontend form rendering
 *    - Dynamic field generation from grid builder config
 *    - Auth button (login/logout/register)
 *
 * 5. Profile Editor (class-profile-editor.php)
 *    - Frontend user profile management
 *    - Custom avatar system
 *    - Multi-language support with GTranslate integration
 *    - Email change confirmation flow
 *
 * 6. User Columns (class-user-columns.php)
 *    - Custom admin user table columns
 *    - Last login tracking
 *
 * Security Features:
 * ------------------
 * - HMAC-based tokens using AUTH_KEY from wp-config.php
 * - IP-based rate limiting with Cloudflare support
 * - Honeypot fields for bot detection
 * - Google reCAPTCHA v3 integration
 * - REST API authentication requirements
 * - XML-RPC blocking
 * - User enumeration prevention
 * - Role-based session expiration (v2.1.0+)
 *
 * Integration Points:
 * -------------------
 * - mikhail-content-restrictions: Governance logging for auth events
 * - mikhail-shadow-mode: Respects shadow mode event logging filters
 * - GTranslate: Automatic language switching based on user preference
 *
 * @see README.md for detailed documentation
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('CSA_VERSION', '2.1.0');
define('CSA_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('CSA_PLUGIN_URL', plugin_dir_url(__FILE__));
define('CSA_PLUGIN_BASENAME', plugin_basename(__FILE__));
define('CSA_SETTINGS_SLUG', 'csa_plugin_settings');

/**
 * Autoloader for plugin classes
 */
spl_autoload_register(function ($class) {
    $prefix = 'CSA_';
    $base_dir = CSA_PLUGIN_DIR . 'includes/';

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relative_class = substr($class, $len);
    $file = $base_dir . 'class-' . str_replace('_', '-', strtolower($relative_class)) . '.php';

    if (file_exists($file)) {
        require $file;
    }
});

/**
 * Main Plugin Class
 */
class Custom_Secure_Auth {

    private static $instance = null;

    public static function instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->init_hooks();
    }

    /**
     * Initialize WordPress hooks
     *
     * Registers all WordPress actions and filters used by the plugin.
     * Hook priorities are carefully chosen to ensure proper execution order.
     */
    private function init_hooks() {
        // Translation support
        add_action('init', array($this, 'load_textdomain'));

        // Asset loading
        add_action('wp_enqueue_scripts', array($this, 'enqueue_frontend_assets'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_assets'));

        // REST API initialization
        add_action('rest_api_init', array($this, 'register_rest_routes'));

        // Component initialization (runs after all plugins loaded)
        add_action('plugins_loaded', array($this, 'init_components'));

        // Login Tracking
        // Using set_auth_cookie instead of wp_login to catch both:
        // 1. Standard WordPress logins
        // 2. REST API logins (wp_set_auth_cookie calls this hook)
        // Priority 10, accepts 5 parameters
        add_action('set_auth_cookie', array('CSA_User_Columns', 'track_user_login'), 10, 5);

        // REST API Security Filters
        // These filters implement zero-enumeration and access control
        add_filter('rest_authentication_errors', array($this, 'restrict_rest_api_access'));
        add_filter('rest_endpoints', array($this, 'disable_user_enumeration_endpoint'));

        // XML-RPC Security
        // Blocks XML-RPC entirely to prevent brute force and pingback DDoS attacks
        add_filter('xmlrpc_enabled', array($this, 'block_xmlrpc_access'));

        // Logout Behavior
        // Redirects users to custom login page and sets logout message transient
        add_filter('logout_redirect', array($this, 'custom_logout_redirect'), 10, 3);

        // Session Management (v2.1.0+)
        // Implements role-based session expiration with configurable durations
        // This overrides both standard and "Remember Me" cookie expiration
        add_filter('auth_cookie_expiration', array($this, 'custom_session_expiration'), 10, 3);

        // Plugin Lifecycle Hooks
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
    }

    /**
     * Initialize plugin components
     */
    public function init_components() {
        // Initialize admin settings
        if (is_admin()) {
            new CSA_Admin_Settings();
        }

        // Initialize shortcodes
        new CSA_Shortcodes();

        // Initialize email manager
        new CSA_Email_Manager();

        // Initialize user columns (admin only, requires manage_options capability)
        CSA_User_Columns::instance();

        // Initialize profile editor
        new CSA_Profile_Editor();
    }

    /**
     * Register REST API routes
     */
    public function register_rest_routes() {
        $rest_handler = new CSA_Rest_Handler();
        $rest_handler->register_routes();
    }

    /**
     * Load plugin textdomain for translations
     */
    public function load_textdomain() {
        load_plugin_textdomain('custom-secure-auth', false, dirname(CSA_PLUGIN_BASENAME) . '/languages');
    }

    /**
     * Enqueue frontend assets
     */
    public function enqueue_frontend_assets() {
        wp_enqueue_style(
            'csa-styles',
            CSA_PLUGIN_URL . 'assets/styles.css',
            array(),
            CSA_VERSION
        );

        wp_enqueue_script(
            'csa-scripts',
            CSA_PLUGIN_URL . 'assets/scripts.js',
            array('jquery'),
            CSA_VERSION,
            true
        );

        // Localize script with REST API data
        wp_localize_script('csa-scripts', 'csaData', array(
            'restUrl' => rest_url('custom-secure-auth/v1'),
            'nonce' => wp_create_nonce('wp_rest'),
            'siteUrl' => get_site_url(),
        ));
    }

    /**
     * Enqueue admin assets
     */
    public function enqueue_admin_assets($hook) {
        // Only load on our settings page
        if (strpos($hook, 'custom-secure-auth') === false) {
            return;
        }

        wp_enqueue_style('wp-color-picker');
        wp_enqueue_script('jquery-ui-sortable');

        wp_enqueue_style(
            'csa-admin-styles',
            CSA_PLUGIN_URL . 'assets/admin-styles.css',
            array('wp-color-picker'),
            CSA_VERSION
        );

        wp_enqueue_script(
            'csa-admin-scripts',
            CSA_PLUGIN_URL . 'assets/admin-scripts.js',
            array('jquery', 'wp-color-picker', 'jquery-ui-sortable'),
            CSA_VERSION,
            true
        );

        // Localize script with Grid Builder data
        $settings = get_option(CSA_SETTINGS_SLUG, array());
        $grid_fields = isset($settings['grid_builder']['registration']) ? $settings['grid_builder']['registration'] : array();

        wp_localize_script('csa-admin-scripts', 'csaGridBuilder', array(
            'fieldIndex' => !empty($grid_fields) ? count($grid_fields) : 0,
            'presets' => array(
                'username' => array(
                    'id' => 'user_login',
                    'label' => __('Username', 'custom-secure-auth'),
                    'placeholder' => __('Enter your username', 'custom-secure-auth'),
                    'type' => 'text',
                    'width' => '50%',
                    'required' => true
                ),
                'email' => array(
                    'id' => 'user_email',
                    'label' => __('Email Address', 'custom-secure-auth'),
                    'placeholder' => __('your.email@example.com', 'custom-secure-auth'),
                    'type' => 'email',
                    'width' => '50%',
                    'required' => true
                ),
                'password' => array(
                    'id' => 'user_pass',
                    'label' => __('Password', 'custom-secure-auth'),
                    'placeholder' => __('Create a strong password', 'custom-secure-auth'),
                    'type' => 'password',
                    'width' => '50%',
                    'required' => true
                ),
                'first_name' => array(
                    'id' => 'first_name',
                    'label' => __('First Name', 'custom-secure-auth'),
                    'placeholder' => __('Your first name', 'custom-secure-auth'),
                    'type' => 'wp_first_name',
                    'width' => '50%',
                    'required' => false
                ),
                'last_name' => array(
                    'id' => 'last_name',
                    'label' => __('Last Name', 'custom-secure-auth'),
                    'placeholder' => __('Your last name', 'custom-secure-auth'),
                    'type' => 'wp_last_name',
                    'width' => '50%',
                    'required' => false
                ),
                'phone' => array(
                    'id' => 'phone_number',
                    'label' => __('Phone Number', 'custom-secure-auth'),
                    'placeholder' => __('(555) 123-4567', 'custom-secure-auth'),
                    'type' => 'usermeta',
                    'width' => '50%',
                    'required' => false
                )
            ),
            'i18n' => array(
                'confirmRemove' => __('Are you sure you want to remove this field?', 'custom-secure-auth'),
                'helpTexts' => array(
                    'text' => __('Regular text input (for username, etc.)', 'custom-secure-auth'),
                    'email' => __('Validates email format automatically', 'custom-secure-auth'),
                    'password' => __('Masked input for secure passwords', 'custom-secure-auth'),
                    'checkbox' => __('Yes/No or agreement checkbox', 'custom-secure-auth'),
                    'wp_first_name' => __('Saves to WordPress user profile', 'custom-secure-auth'),
                    'wp_last_name' => __('Saves to WordPress user profile', 'custom-secure-auth'),
                    'usermeta' => __('Custom data (phone, company, etc.)', 'custom-secure-auth')
                )
            )
        ));
    }

    /**
     * Plugin activation
     */
    public function activate() {
        // Set default options if not exist
        if (!get_option(CSA_SETTINGS_SLUG)) {
            $defaults = array(
                'page_mapping' => array(
                    'login_page' => 0,
                    'register_page' => 0,
                    'lost_password_page' => 0,
                    'set_password_page' => 0,
                ),
                'global_config' => array(
                    'token_expiry' => 30,
                    'redirect_after_login' => home_url(),
                    'button_css_classes' => 'btn btn-primary',
                ),
                'security' => array(
                    'honeypot_enabled' => true,
                    'max_failed_attempts' => 5,
                    'lockout_duration' => 1,
                    'recaptcha_site_key' => '',
                    'recaptcha_secret_key' => '',
                ),
                'grid_builder' => array(),
                'emails' => array(
                    'activation_subject' => 'Activate Your Account - {site_name}',
                    'activation_template' => '<p>Hello {user_name},</p><p>Please click the link below to activate your account:</p><p><a href="{set_password_url}">Activate Account</a></p>',
                    'recovery_subject' => 'Reset Your Password - {site_name}',
                    'recovery_template' => '<p>Hello {user_name},</p><p>Please click the link below to reset your password:</p><p><a href="{set_password_url}">Reset Password</a></p>',
                ),
            );
            add_option(CSA_SETTINGS_SLUG, $defaults);
        }

        flush_rewrite_rules();
    }

    /**
     * Plugin deactivation
     */
    public function deactivate() {
        flush_rewrite_rules();
    }

    /**
     * Restrict REST API access based on settings
     *
     * @param WP_Error|null|bool $result
     * @return WP_Error|null|bool
     */
    public function restrict_rest_api_access($result) {
        // If already an error, pass it through
        if (is_wp_error($result)) {
            return $result;
        }

        // Get settings
        $settings = get_option(CSA_SETTINGS_SLUG, array());
        $security = isset($settings['security']) ? $settings['security'] : array();
        $require_auth = isset($security['rest_api_authentication_required']) && $security['rest_api_authentication_required'];

        // If authentication not required, allow access
        if (!$require_auth) {
            return $result;
        }

        // If user is logged in, allow access
        if (is_user_logged_in()) {
            return $result;
        }

        // Check if current namespace is whitelisted
        $current_route = $_SERVER['REQUEST_URI'] ?? '';
        $whitelisted_namespaces = isset($security['rest_api_whitelisted_namespaces'])
            ? $security['rest_api_whitelisted_namespaces']
            : array('custom-secure-auth');

        // Ensure it's an array
        if (!is_array($whitelisted_namespaces)) {
            $whitelisted_namespaces = array_map('trim', explode(',', $whitelisted_namespaces));
        }

        // Check if route matches any whitelisted namespace
        foreach ($whitelisted_namespaces as $namespace) {
            if (strpos($current_route, '/wp-json/' . $namespace) !== false) {
                return $result;
            }
        }

        // Log the blocked attempt for debugging
        $this->log_blocked_rest_api_attempt($current_route);

        // Block access with 404 to hide security setting
        return new WP_Error(
            'rest_no_route',
            __('No route was found matching the URL and request method.', 'custom-secure-auth'),
            array('status' => 404)
        );
    }

    /**
     * Log blocked REST API attempt for debugging
     *
     * @param string $route The blocked route
     */
    private function log_blocked_rest_api_attempt($route) {
        // Get user IP address
        $ip = $this->get_user_ip();

        // Create log entry
        $log_entry = array(
            'timestamp' => current_time('Y-m-d H:i:s'),
            'route' => $route,
            'ip' => $ip,
        );

        // Get existing log
        $blocked_log = get_option('csa_blocked_namespaces_log', array());

        // Add new entry at the beginning
        array_unshift($blocked_log, $log_entry);

        // Keep only last 20 entries
        $blocked_log = array_slice($blocked_log, 0, 20);

        // Save updated log
        update_option('csa_blocked_namespaces_log', $blocked_log, false);
    }

    /**
     * Get user IP address
     *
     * @return string IP address
     */
    private function get_user_ip() {
        // Check for Cloudflare
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return sanitize_text_field($_SERVER['HTTP_CF_CONNECTING_IP']);
        }

        // Check for proxy
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip_list = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            return sanitize_text_field(trim($ip_list[0]));
        }

        // Default to REMOTE_ADDR
        return !empty($_SERVER['REMOTE_ADDR']) ? sanitize_text_field($_SERVER['REMOTE_ADDR']) : '0.0.0.0';
    }

    /**
     * Disable user enumeration endpoint
     *
     * @param array $endpoints
     * @return array
     */
    public function disable_user_enumeration_endpoint($endpoints) {
        // Get settings
        $settings = get_option(CSA_SETTINGS_SLUG, array());
        $security = isset($settings['security']) ? $settings['security'] : array();
        $disable_enumeration = isset($security['disable_user_enumeration']) && $security['disable_user_enumeration'];

        // If not enabled, return endpoints unchanged
        if (!$disable_enumeration) {
            return $endpoints;
        }

        // Remove /wp/v2/users endpoint
        if (isset($endpoints['/wp/v2/users'])) {
            unset($endpoints['/wp/v2/users']);
        }
        if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
            unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
        }

        return $endpoints;
    }

    /**
     * Block XML-RPC access based on settings
     *
     * @param bool $enabled Whether XML-RPC is enabled
     * @return bool|void False to block, true to allow, void for 404
     */
    public function block_xmlrpc_access($enabled) {
        // Get settings
        $settings = get_option(CSA_SETTINGS_SLUG, array());
        $security = isset($settings['security']) ? $settings['security'] : array();
        $block_xmlrpc = isset($security['block_xmlrpc']) && $security['block_xmlrpc'];

        // If blocking is not enabled, allow access
        if (!$block_xmlrpc) {
            return $enabled;
        }

        // Return standard 404 response and exit
        status_header(404);
        nocache_headers();
        exit;
    }

    /**
     * Custom logout redirect
     * Redirects to the configured login page if set, otherwise to home page
     *
     * @param string $redirect_to The redirect destination URL
     * @param string $requested_redirect_to The requested redirect destination URL passed as a parameter
     * @param WP_User $user The WP_User object for the user that's logging out
     * @return string The redirect URL
     */
    public function custom_logout_redirect($redirect_to, $requested_redirect_to, $user) {
        $settings = get_option(CSA_SETTINGS_SLUG, array());
        $login_page_id = isset($settings['page_mapping']['login_page']) ? $settings['page_mapping']['login_page'] : 0;

        // Set transient for logout message (60 second expiry)
        set_transient('csa_logout_message', '1', 60);

        // If login page is configured in plugin settings, redirect there
        if ($login_page_id) {
            $logout_redirect = get_permalink($login_page_id);
            if ($logout_redirect) {
                return $logout_redirect;
            }
        }

        // Fallback to home page
        return home_url();
    }

    /**
     * Custom session expiration based on user role
     *
     * Implements role-based session expiration control (v2.1.0+).
     * This filter overrides WordPress default cookie expiration for both
     * standard logins and "Remember Me" logins to enforce security policies.
     *
     * Security Rationale:
     * ------------------
     * - Admins may need shorter sessions for security (e.g., 2 hours)
     * - Subscribers may get longer sessions for convenience (e.g., 7 days)
     * - Enforces minimum 1-hour session to prevent lockout loops
     * - Ignores $remember parameter to ensure consistent policy enforcement
     *
     * Configuration Flow:
     * -------------------
     * 1. Check for role-specific override (first matching role wins)
     * 2. Fall back to global default if no role override
     * 3. Apply minimum 1-hour safety constraint
     * 4. Convert hours to seconds and return
     *
     * @since 2.1.0
     * @param int $expiration Default session expiration in seconds from WordPress
     * @param int $user_id User ID
     * @param bool $remember Whether user clicked "Remember Me" (ignored for consistency)
     * @return int Modified session expiration in seconds
     */
    public function custom_session_expiration($expiration, $user_id, $remember) {
        // Get plugin settings
        $settings = get_option(CSA_SETTINGS_SLUG, array());
        $security = isset($settings['security']) ? $settings['security'] : array();

        // Get global default session length (in hours, default: 48)
        // WordPress default is 2 days for normal, 14 days for "Remember Me"
        $global_default_hours = isset($security['session_expiration_global_default'])
            ? absint($security['session_expiration_global_default'])
            : 48;

        // Get role-specific overrides (array of 'role_slug' => hours)
        $role_overrides = isset($security['session_expiration_role_overrides'])
            ? $security['session_expiration_role_overrides']
            : array();

        // Get user data
        $user = get_userdata($user_id);
        if (!$user) {
            // Safety fallback: if user data unavailable, use original expiration
            return $expiration;
        }

        // Check for role-specific override
        // Priority: First role with an override wins (order matters for multi-role users)
        $custom_hours = null;
        if (!empty($role_overrides) && is_array($role_overrides)) {
            foreach ($user->roles as $role) {
                if (isset($role_overrides[$role]) && absint($role_overrides[$role]) > 0) {
                    $custom_hours = absint($role_overrides[$role]);
                    break; // Use first matching role override
                }
            }
        }

        // If no role-specific override found, use global default
        if ($custom_hours === null) {
            $custom_hours = $global_default_hours;
        }

        // Safety constraint: Minimum 1 hour to prevent lockout loops
        // (Very short sessions could log users out while still filling forms)
        if ($custom_hours < 1) {
            $custom_hours = 1;
        }

        // Convert hours to seconds
        $custom_expiration = $custom_hours * HOUR_IN_SECONDS;

        // IMPORTANT: We ignore the $remember parameter
        // This ensures role-based policies always apply consistently,
        // preventing users from extending sessions beyond admin-defined limits
        return $custom_expiration;
    }
}

/**
 * Initialize the plugin
 */
function custom_secure_auth() {
    return Custom_Secure_Auth::instance();
}

// Fire it up!
custom_secure_auth();
