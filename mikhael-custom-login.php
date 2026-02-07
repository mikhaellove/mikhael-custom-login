<?php
/*
Plugin Name: Mikhael's Custom Secure Auth
Description: A secure, modular authentication system with custom login, registration, password reset, and grid-based form builder with advanced security features.
Version: 2.0.0
Author: Mikhael Love
*/

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('CSA_VERSION', '2.0.0');
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
        if ('settings_page_custom-secure-auth' !== $hook) {
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
}

/**
 * Initialize the plugin
 */
function custom_secure_auth() {
    return Custom_Secure_Auth::instance();
}

// Fire it up!
custom_secure_auth();
