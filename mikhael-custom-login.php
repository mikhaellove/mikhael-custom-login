<?php
/*
Plugin Name: Mikhael's Custom Secure Auth
Description: A secure, modular authentication system with custom login, registration, password reset, and grid-based form builder with advanced security features.
Version: 2.0.1
Author: Mikhael Love
*/

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('CSA_VERSION', '2.0.1');
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
     */
    private function init_hooks() {
        add_action('init', array($this, 'load_textdomain'));
        add_action('wp_enqueue_scripts', array($this, 'enqueue_frontend_assets'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_assets'));
        add_action('rest_api_init', array($this, 'register_rest_routes'));
        add_action('plugins_loaded', array($this, 'init_components'));

        // REST API Security
        add_filter('rest_authentication_errors', array($this, 'restrict_rest_api_access'));
        add_filter('rest_endpoints', array($this, 'disable_user_enumeration_endpoint'));

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
        // Debug: log the hook value
        error_log('CSA Hook: ' . $hook);

        // Only load on our settings page
        if (strpos($hook, 'custom-secure-auth') === false) {
            error_log('CSA: Hook check failed, not loading assets');
            return;
        }

        error_log('CSA: Loading admin assets');

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

        // Block access with 404 to hide security setting
        return new WP_Error(
            'rest_no_route',
            __('No route was found matching the URL and request method.', 'custom-secure-auth'),
            array('status' => 404)
        );
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
}

/**
 * Initialize the plugin
 */
function custom_secure_auth() {
    return Custom_Secure_Auth::instance();
}

// Fire it up!
custom_secure_auth();
