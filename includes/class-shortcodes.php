<?php
/**
 * Shortcodes Class
 *
 * Handles all shortcode registrations and form rendering for Custom Secure Auth.
 * This class is responsible for generating the HTML for all authentication forms
 * and integrating them with the REST API security layer.
 *
 * SHORTCODE ARCHITECTURE
 * ======================
 * All shortcodes follow a consistent pattern:
 * 1. Check if page is properly mapped in settings
 * 2. Load plugin settings and configuration
 * 3. Generate HTML form with proper structure
 * 4. Inject HMAC security token via JavaScript
 * 5. Add honeypot field (if enabled)
 * 6. Handle messages (success/error via transients)
 * 7. Submit to REST API endpoint
 *
 * AVAILABLE SHORTCODES
 * ====================
 *
 * [auth_login]
 * - Displays login form
 * - Fields: username, password, remember me
 * - Submits to: /custom-secure-auth/v1/login
 * - Checks for activation_pending flag
 * - Shows logout success message (if just logged out)
 *
 * [auth_register]
 * - Displays registration form built from Grid Builder config
 * - Dynamically generates fields based on admin settings
 * - Supports: username (with fun generator), email, password, first/last name, custom fields
 * - Submits to: /custom-secure-auth/v1/register
 * - Hybrid system: password optional (triggers activation email if omitted)
 *
 * [auth_lost_password]
 * - Displays password recovery form
 * - Field: username or email
 * - Submits to: /custom-secure-auth/v1/lost-password
 * - Always returns generic success (zero-enumeration)
 *
 * [auth_set_password]
 * - Displays password setting form
 * - Used for both activation AND password reset
 * - Gets key and login from URL parameters
 * - Fields: new password, confirm password
 * - Submits to: /custom-secure-auth/v1/set-password
 * - Shows password strength indicator
 *
 * [auth_button]
 * - Dynamic button that shows different links based on login state
 * - Logged out: Shows "Login" and "Register" links
 * - Logged in: Shows "Logout" link
 * - Uses page mapping from settings
 *
 * TOKEN INJECTION SYSTEM
 * ======================
 * All forms use JavaScript to fetch and inject HMAC tokens before submission:
 *
 * 1. Form loads with placeholder token field
 * 2. JavaScript fetches token from: /custom-secure-auth/v1/get-token
 * 3. Token is HMAC-SHA256(IP + timestamp + AUTH_KEY)
 * 4. Token and timestamp injected into hidden form fields
 * 5. Form submitted with valid token
 * 6. REST handler validates token (checks IP match and expiry)
 *
 * This approach ensures:
 * - Tokens are always fresh (not cached in HTML)
 * - Each token is unique per IP and time
 * - Tokens expire after configured duration (default: 30 minutes)
 * - Cannot be reused across different IPs
 *
 * GRID BUILDER INTEGRATION
 * ========================
 * Registration form uses Grid Builder configuration to dynamically render fields:
 *
 * Field Types Supported:
 * - text: Basic text input (username, custom fields)
 * - email: Email input with HTML5 validation
 * - password: Password input with strength indicator
 * - wp_first_name: WordPress first name (saved to user profile)
 * - wp_last_name: WordPress last name (saved to user profile)
 * - usermeta: Custom user meta (phone, company, etc.)
 *
 * Field Configuration:
 * - Width: 33%, 50%, or 100% (CSS grid)
 * - Required: Boolean flag
 * - Placeholder: Custom placeholder text
 * - Label: Field label
 * - Order: Sortable via drag-and-drop in admin
 *
 * HONEYPOT SYSTEM
 * ===============
 * All forms include a hidden honeypot field (if enabled in settings):
 * - Field name: "csa_website"
 * - Hidden via CSS (display: none)
 * - Bots auto-fill all fields, including hidden ones
 * - Server-side validation rejects if field has any value
 * - Humans never see or interact with this field
 *
 * SECURITY FEATURES
 * =================
 * - All output is escaped with esc_html(), esc_attr(), esc_url()
 * - HMAC tokens instead of WordPress nonces
 * - Honeypot bot detection
 * - Rate limiting via REST handler
 * - Generic error messages (zero-enumeration)
 * - CSRF protection via referer validation
 *
 * @package Custom_Secure_Auth
 * @since 2.0.0
 * @version 2.1.0
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * CSA_Shortcodes Class
 *
 * Manages shortcode registration and form HTML generation.
 * Integrates with REST API handler for secure form submission.
 */
class CSA_Shortcodes {

    /**
     * Plugin settings array
     *
     * Contains all configuration including:
     * - Page mappings
     * - Grid builder configuration
     * - Security settings
     * - Email templates
     *
     * @var array
     */
    private $settings;

    /**
     * Constructor
     *
     * Loads settings and registers all authentication shortcodes.
     */
    public function __construct() {
        $this->settings = $this->get_settings();

        // Register all authentication shortcodes
        add_shortcode('auth_login', array($this, 'render_login_form'));
        add_shortcode('auth_register', array($this, 'render_register_form'));
        add_shortcode('auth_lost_password', array($this, 'render_lost_password_form'));
        add_shortcode('auth_set_password', array($this, 'render_set_password_form'));
        add_shortcode('auth_button', array($this, 'render_auth_button'));
        add_shortcode('auth_continue', array($this, 'render_continue_button'));
    }

    /**
     * Get plugin settings
     *
     * @return array Plugin settings
     */
    private function get_settings() {
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

        $settings = get_option(CSA_SETTINGS_SLUG, $defaults);
        return wp_parse_args($settings, $defaults);
    }

    /**
     * Check if a page is mapped in settings
     *
     * @param string $page_key Page key (login_page, register_page, etc.)
     * @return bool True if page is mapped
     */
    private function is_page_mapped($page_key) {
        $page_id = isset($this->settings['page_mapping'][$page_key]) ? $this->settings['page_mapping'][$page_key] : 0;
        return !empty($page_id) && get_post($page_id) !== null;
    }

    /**
     * Get URL for a mapped page
     *
     * @param string $page_key Page key (login_page, register_page, etc.)
     * @return string|false Page URL or false if not mapped
     */
    private function get_page_url($page_key) {
        if (!$this->is_page_mapped($page_key)) {
            return false;
        }

        $page_id = $this->settings['page_mapping'][$page_key];
        return get_permalink($page_id);
    }

    /**
     * Render form token hidden fields
     *
     * @return string HTML for token fields
     */
    private function render_form_token() {
        ob_start();
        ?>
        <input type="hidden" name="csa_token" class="csa-token" value="">
        <input type="hidden" name="csa_timestamp" class="csa-timestamp" value="">
        <?php
        return ob_get_clean();
    }

    /**
     * Render honeypot field if enabled
     *
     * @return string HTML for honeypot field
     */
    private function render_honeypot() {
        $security = isset($this->settings['security']) ? $this->settings['security'] : array();
        $honeypot_enabled = isset($security['honeypot_enabled']) ? $security['honeypot_enabled'] : true;

        if (!$honeypot_enabled) {
            return '';
        }

        ob_start();
        ?>
        <div style="position: absolute; left: -9999px; width: 1px; height: 1px; overflow: hidden;" aria-hidden="true">
            <label for="csa_website">Website (leave blank)</label>
            <input type="text" name="csa_website" id="csa_website" value="" tabindex="-1" autocomplete="off">
        </div>
        <?php
        return ob_get_clean();
    }

    /**
     * Get button CSS classes
     *
     * @return string Button CSS classes
     */
    private function get_button_classes() {
        $global_config = isset($this->settings['global_config']) ? $this->settings['global_config'] : array();
        return isset($global_config['button_css_classes']) ? esc_attr($global_config['button_css_classes']) : 'btn btn-primary';
    }

    /**
     * Render [auth_login] shortcode
     *
     * Displays standard login form with username, password, remember me checkbox,
     * timed token, and honeypot (if enabled)
     *
     * @param array $atts Shortcode attributes
     * @return string HTML for login form
     */
    public function render_login_form($atts) {
        // Redirect if already logged in
        if (is_user_logged_in()) {
            $redirect_page_id = isset($this->settings['global_config']['redirect_after_login'])
                ? $this->settings['global_config']['redirect_after_login']
                : 0;

            // Get URL from page ID
            if ($redirect_page_id) {
                $redirect_url = get_permalink($redirect_page_id);
                // Fallback to home if page doesn't exist or permalink fails
                if (!$redirect_url) {
                    $redirect_url = home_url();
                }
            } else {
                $redirect_url = home_url();
            }

            // Prevent redirect loop: if redirect URL is the current page, go to home instead
            $current_url = get_permalink();
            if ($current_url && $redirect_url === $current_url) {
                error_log('[CSA Redirect Debug] Prevented redirect loop on login page for logged-in user');
                $redirect_url = home_url();
            }

            wp_safe_redirect($redirect_url);
            exit;
        }

        // Capture HTTP_REFERER for redirect after login
        // Store in session-based transient (using IP + user agent hash for anonymous users)
        if (!empty($_SERVER['HTTP_REFERER'])) {
            $referer = esc_url_raw($_SERVER['HTTP_REFERER']);

            // Only store if referer is from same site
            $referer_host = parse_url($referer, PHP_URL_HOST);
            $site_host = parse_url(home_url(), PHP_URL_HOST);

            if ($referer_host === $site_host) {
                // Create a session identifier for anonymous users
                $session_id = md5($_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);
                $transient_key = 'csa_login_referer_' . $session_id;

                // Store for 10 minutes
                set_transient($transient_key, $referer, 600);
                error_log('[CSA Redirect Debug] Stored referer in transient: ' . $referer);
            }
        }

        // Check for logout message transient
        $logout_message = get_transient('csa_logout_message');
        if ($logout_message) {
            // Delete transient immediately to prevent repeat display
            delete_transient('csa_logout_message');
        }

        ob_start();
        ?>
        <div class="csa-auth-container csa-login-container">
            <?php if ($logout_message): ?>
                <div class="csa-notice csa-notice-success">
                    <p><?php esc_html_e('You have been logged out.', 'custom-secure-auth'); ?></p>
                </div>
            <?php endif; ?>
            <form class="csa-auth-form csa-login-form" id="csa-login-form" method="post">
                <div class="csa-form-messages"></div>

                <div class="csa-form-group">
                    <label for="username"><?php esc_html_e('Username or Email', 'custom-secure-auth'); ?></label>
                    <input
                        type="text"
                        name="username"
                        id="username"
                        class="csa-form-control"
                        required
                        autocomplete="username"
                    >
                </div>

                <div class="csa-form-group">
                    <label for="password"><?php esc_html_e('Password', 'custom-secure-auth'); ?></label>
                    <input
                        type="password"
                        name="password"
                        id="password"
                        class="csa-form-control"
                        required
                        autocomplete="current-password"
                    >
                </div>

                <div class="csa-form-group csa-checkbox-group">
                    <label>
                        <input
                            type="checkbox"
                            name="remember"
                            id="remember"
                            value="true"
                        >
                        <?php esc_html_e('Remember Me', 'custom-secure-auth'); ?>
                    </label>
                </div>

                <?php echo $this->render_form_token(); ?>
                <?php echo $this->render_honeypot(); ?>

                <div class="csa-form-group csa-submit-group">
                    <button
                        type="submit"
                        class="csa-submit-btn <?php echo $this->get_button_classes(); ?>"
                    >
                        <?php esc_html_e('Log In', 'custom-secure-auth'); ?>
                    </button>
                </div>

                <?php if ($this->is_page_mapped('lost_password_page') || $this->is_page_mapped('register_page')): ?>
                <div class="csa-form-links">
                    <?php if ($this->is_page_mapped('lost_password_page')): ?>
                    <a href="<?php echo esc_url($this->get_page_url('lost_password_page')); ?>">
                        <?php esc_html_e('Lost your password?', 'custom-secure-auth'); ?>
                    </a>
                    <?php endif; ?>
                    <?php if ($this->is_page_mapped('register_page')): ?>
                    <a href="<?php echo esc_url($this->get_page_url('register_page')); ?>">
                        <?php esc_html_e('Create an account', 'custom-secure-auth'); ?>
                    </a>
                    <?php endif; ?>
                </div>
                <?php endif; ?>
            </form>
        </div>
        <?php
        return ob_get_clean();
    }

    /**
     * Render [auth_register] shortcode
     *
     * Displays dynamic grid-based registration form based on grid_builder configuration
     *
     * @param array $atts Shortcode attributes
     * @return string HTML for registration form
     */
    public function render_register_form($atts) {
        // Redirect if already logged in
        if (is_user_logged_in()) {
            $redirect_url = isset($this->settings['global_config']['redirect_after_login'])
                ? $this->settings['global_config']['redirect_after_login']
                : home_url();
            wp_safe_redirect($redirect_url);
            exit;
        }

        $grid_fields = isset($this->settings['grid_builder']['fields']) ? $this->settings['grid_builder']['fields'] : array();
        $fun_username_enabled = isset($this->settings['grid_builder']['fun_username_enabled']) ? $this->settings['grid_builder']['fun_username_enabled'] : false;

        // Check if password field exists
        $has_password_field = false;
        foreach ($grid_fields as $field) {
            if (isset($field['type']) && $field['type'] === 'password') {
                $has_password_field = true;
                break;
            }
        }

        ob_start();
        ?>
        <div class="csa-auth-container csa-register-container">
            <form class="csa-auth-form csa-register-form" id="csa-register-form" method="post">
                <div class="csa-form-messages"></div>

                <?php if (!empty($grid_fields)): ?>
                <div class="auth-grid">
                    <?php foreach ($grid_fields as $field): ?>
                        <?php
                        $field_id = isset($field['id']) ? sanitize_key($field['id']) : '';
                        $field_label = isset($field['label']) ? esc_html($field['label']) : '';
                        $field_placeholder = isset($field['placeholder']) ? esc_attr($field['placeholder']) : '';
                        $field_type = isset($field['type']) ? sanitize_key($field['type']) : 'text';
                        $field_width = isset($field['width']) ? $field['width'] : '100%';

                        // Determine if field is required
                        // Non-user-meta fields are required by default, user meta fields respect the admin setting
                        $is_usermeta = ($field_type === 'usermeta');
                        if ($is_usermeta) {
                            // For user meta fields, use the admin's required setting
                            $field_required = isset($field['required']) && $field['required'] ? 'required' : '';
                        } else {
                            // For non-user-meta fields, required by default (can be overridden by admin)
                            $field_required = (!isset($field['required']) || $field['required']) ? 'required' : '';
                        }

                        // Convert width to CSS class
                        $width_class = '';
                        if ($field_width === '33%') {
                            $width_class = 'col-33';
                        } elseif ($field_width === '50%') {
                            $width_class = 'col-50';
                        } else {
                            $width_class = 'col-100';
                        }

                        // Determine input type for HTML
                        $input_type = 'text';
                        $autocomplete = 'off';

                        // Set autocomplete for username field
                        if ($field_id === 'user_login') {
                            $autocomplete = 'username';
                        }

                        switch ($field_type) {
                            case 'email':
                                $input_type = 'email';
                                $autocomplete = 'email';
                                break;
                            case 'password':
                                $input_type = 'password';
                                $autocomplete = 'new-password';
                                break;
                            case 'checkbox':
                                $input_type = 'checkbox';
                                break;
                            case 'usermeta':
                            case 'text':
                            default:
                                $input_type = 'text';
                                break;
                        }
                        ?>

                        <div class="csa-form-group <?php echo esc_attr($width_class); ?>">
                            <?php if ($field_type === 'checkbox'): ?>
                                <label>
                                    <input
                                        type="checkbox"
                                        name="<?php echo esc_attr($field_id); ?>"
                                        id="<?php echo esc_attr($field_id); ?>"
                                        value="1"
                                        <?php echo $field_required; ?>
                                    >
                                    <?php echo $field_label; ?>
                                </label>
                            <?php else: ?>
                                <label for="<?php echo esc_attr($field_id); ?>">
                                    <?php echo $field_label; ?>
                                    <?php if ($field_required): ?>
                                        <span class="csa-required">*</span>
                                    <?php endif; ?>
                                    <?php if ($fun_username_enabled && $field_id === 'user_login'): ?>
                                        <span class="csa-username-refresh" title="<?php esc_attr_e('Generate new username', 'custom-secure-auth'); ?>">↻</span>
                                    <?php endif; ?>
                                </label>
                                <input
                                    type="<?php echo esc_attr($input_type); ?>"
                                    name="<?php echo esc_attr($field_id); ?>"
                                    id="<?php echo esc_attr($field_id); ?>"
                                    class="csa-form-control<?php echo ($fun_username_enabled && $field_id === 'user_login') ? ' csa-fun-username-field' : ''; ?>"
                                    placeholder="<?php echo $field_placeholder; ?>"
                                    autocomplete="<?php echo esc_attr($autocomplete); ?>"
                                    <?php echo ($fun_username_enabled && $field_id === 'user_login') ? 'required' : $field_required; ?>
                                >
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
                <?php else: ?>
                    <div class="csa-notice csa-notice-warning">
                        <p><?php esc_html_e('No registration fields configured. Please configure the registration form in the plugin settings.', 'custom-secure-auth'); ?></p>
                    </div>
                <?php endif; ?>

                <?php echo $this->render_form_token(); ?>
                <?php echo $this->render_honeypot(); ?>

                <?php if (!empty($grid_fields)): ?>
                <div class="csa-form-group csa-submit-group">
                    <button
                        type="submit"
                        class="csa-submit-btn <?php echo $this->get_button_classes(); ?>"
                    >
                        <?php esc_html_e('Register', 'custom-secure-auth'); ?>
                    </button>
                </div>
                <?php endif; ?>

                <?php if ($this->is_page_mapped('login_page')): ?>
                <div class="csa-form-links">
                    <a href="<?php echo esc_url($this->get_page_url('login_page')); ?>">
                        <?php esc_html_e('Already have an account? Log in', 'custom-secure-auth'); ?>
                    </a>
                </div>
                <?php endif; ?>
            </form>
        </div>
        <?php
        return ob_get_clean();
    }

    /**
     * Render [auth_lost_password] shortcode
     *
     * Displays password recovery form with single email/username field
     *
     * @param array $atts Shortcode attributes
     * @return string HTML for lost password form
     */
    public function render_lost_password_form($atts) {
        // Redirect if already logged in
        if (is_user_logged_in()) {
            $redirect_url = isset($this->settings['global_config']['redirect_after_login'])
                ? $this->settings['global_config']['redirect_after_login']
                : home_url();
            wp_safe_redirect($redirect_url);
            exit;
        }

        ob_start();
        ?>
        <div class="csa-auth-container csa-lost-password-container">
            <form class="csa-auth-form csa-lost-password-form" id="csa-lost-password-form" method="post">
                <div class="csa-form-messages"></div>

                <div class="csa-form-description">
                    <p><?php esc_html_e('Enter your username or email address. You will receive a link to create a new password via email.', 'custom-secure-auth'); ?></p>
                </div>

                <div class="csa-form-group">
                    <label for="user_login"><?php esc_html_e('Username or Email Address', 'custom-secure-auth'); ?></label>
                    <input
                        type="text"
                        name="user_login"
                        id="user_login"
                        class="csa-form-control"
                        required
                        autocomplete="username"
                    >
                </div>

                <?php echo $this->render_form_token(); ?>
                <?php echo $this->render_honeypot(); ?>

                <div class="csa-form-group csa-submit-group">
                    <button
                        type="submit"
                        class="csa-submit-btn <?php echo $this->get_button_classes(); ?>"
                    >
                        <?php esc_html_e('Reset Password', 'custom-secure-auth'); ?>
                    </button>
                </div>

                <?php if ($this->is_page_mapped('login_page')): ?>
                <div class="csa-form-links">
                    <a href="<?php echo esc_url($this->get_page_url('login_page')); ?>">
                        <?php esc_html_e('Back to login', 'custom-secure-auth'); ?>
                    </a>
                </div>
                <?php endif; ?>
            </form>
        </div>
        <?php
        return ob_get_clean();
    }

    /**
     * Render [auth_set_password] shortcode
     *
     * Displays set/reset password form with validation for activation or password reset
     * Validates $_GET['key'] and $_GET['login'] via check_password_reset_key()
     *
     * @param array $atts Shortcode attributes
     * @return string HTML for set password form
     */
    public function render_set_password_form($atts) {
        // Redirect if already logged in
        if (is_user_logged_in()) {
            $redirect_url = isset($this->settings['global_config']['redirect_after_login'])
                ? $this->settings['global_config']['redirect_after_login']
                : home_url();
            wp_safe_redirect($redirect_url);
            exit;
        }

        $key = isset($_GET['key']) ? sanitize_text_field($_GET['key']) : '';
        $login = isset($_GET['login']) ? sanitize_user($_GET['login']) : '';
        $action = isset($_GET['action']) ? sanitize_key($_GET['action']) : 'rp';

        // Determine if this is activation or password reset
        $is_activation = ($action === 'activate');

        // Default: show key entry message
        $show_form = false;
        $error_message = '';

        // Validate the key if provided
        if (!empty($key) && !empty($login)) {
            // First try WordPress password reset key
            $user = check_password_reset_key($key, $login);

            if (is_wp_error($user)) {
                // Maybe it's an activation key
                $user_obj = get_user_by('login', $login);

                if ($user_obj) {
                    $activation_key = get_user_meta($user_obj->ID, 'csa_activation_key', true);
                    $activation_expiry = get_user_meta($user_obj->ID, 'csa_activation_key_expiry', true);

                    if ($activation_key === $key && time() <= $activation_expiry) {
                        $show_form = true;
                        $is_activation = true;
                    } else {
                        $error_message = __('This activation link has expired or is invalid.', 'custom-secure-auth');
                    }
                } else {
                    $error_message = __('This password reset link is invalid or has expired.', 'custom-secure-auth');
                }
            } else {
                $show_form = true;
                $is_activation = false;
            }
        } else {
            $error_message = __('Invalid password reset link. Please request a new one.', 'custom-secure-auth');
        }

        ob_start();
        ?>
        <div class="csa-auth-container csa-set-password-container">
            <?php if ($show_form): ?>
                <form class="csa-auth-form csa-set-password-form" id="csa-set-password-form" method="post">
                    <div class="csa-form-messages"></div>

                    <h2 class="csa-form-title">
                        <?php
                        if ($is_activation) {
                            esc_html_e('Set Your Password', 'custom-secure-auth');
                        } else {
                            esc_html_e('Reset Password', 'custom-secure-auth');
                        }
                        ?>
                    </h2>

                    <div class="csa-form-description">
                        <p>
                            <?php
                            if ($is_activation) {
                                esc_html_e('Please choose a password for your account.', 'custom-secure-auth');
                            } else {
                                esc_html_e('Enter your new password below.', 'custom-secure-auth');
                            }
                            ?>
                        </p>
                    </div>

                    <input type="hidden" name="key" value="<?php echo esc_attr($key); ?>">
                    <input type="hidden" name="login" value="<?php echo esc_attr($login); ?>">
                    <input type="hidden" name="action" value="<?php echo esc_attr($action); ?>">

                    <div class="csa-form-group">
                        <label for="password"><?php esc_html_e('New Password', 'custom-secure-auth'); ?></label>
                        <input
                            type="password"
                            name="password"
                            id="password"
                            class="csa-form-control"
                            required
                            minlength="8"
                            autocomplete="new-password"
                        >
                        <small class="csa-form-help">
                            <?php esc_html_e('Password must be at least 8 characters long.', 'custom-secure-auth'); ?>
                        </small>
                    </div>

                    <div class="csa-form-group">
                        <label for="password_confirm"><?php esc_html_e('Confirm Password', 'custom-secure-auth'); ?></label>
                        <input
                            type="password"
                            name="password_confirm"
                            id="password_confirm"
                            class="csa-form-control"
                            required
                            minlength="8"
                            autocomplete="new-password"
                        >
                    </div>

                    <div class="csa-form-group csa-submit-group">
                        <button
                            type="submit"
                            class="csa-submit-btn <?php echo $this->get_button_classes(); ?>"
                        >
                            <?php
                            if ($is_activation) {
                                esc_html_e('Activate Account', 'custom-secure-auth');
                            } else {
                                esc_html_e('Update Password', 'custom-secure-auth');
                            }
                            ?>
                        </button>
                    </div>
                </form>
            <?php else: ?>
                <div class="csa-notice csa-notice-error">
                    <p><?php echo esc_html($error_message); ?></p>
                    <?php if ($this->is_page_mapped('lost_password_page')): ?>
                        <p>
                            <a href="<?php echo esc_url($this->get_page_url('lost_password_page')); ?>">
                                <?php esc_html_e('Request a new password reset link', 'custom-secure-auth'); ?>
                            </a>
                        </p>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
        <?php
        return ob_get_clean();
    }

    /**
     * Render [auth_button] shortcode
     *
     * Displays authentication buttons/links based on action attribute
     * Usage: [auth_button action="login|register|logout"]
     *
     * @param array $atts Shortcode attributes
     * @return string HTML for auth button
     */
    public function render_auth_button($atts) {
        $atts = shortcode_atts(array(
            'action' => 'login',
            'text' => '',
            'class' => '',
        ), $atts);

        $action = sanitize_key($atts['action']);
        $custom_text = !empty($atts['text']) ? esc_html($atts['text']) : '';
        $custom_class = !empty($atts['class']) ? esc_attr($atts['class']) : '';

        $button_classes = $this->get_button_classes() . ' ' . $custom_class;

        ob_start();

        switch ($action) {
            case 'login':
                $page_url = $this->get_page_url('login_page');

                if (!$page_url) {
                    if (current_user_can('manage_options')) {
                        ?>
                        <div class="csa-notice csa-notice-warning">
                            <p><?php esc_html_e('Login page is not configured. Please map a login page in the plugin settings.', 'custom-secure-auth'); ?></p>
                        </div>
                        <?php
                    }
                    break;
                }

                $button_text = $custom_text ? $custom_text : __('Log In', 'custom-secure-auth');

                if (is_user_logged_in()) {
                    // Show nothing or dashboard link if already logged in
                    break;
                }
                ?>
                <a href="<?php echo esc_url($page_url); ?>" class="csa-auth-button <?php echo esc_attr($button_classes); ?>">
                    <?php echo esc_html($button_text); ?>
                </a>
                <?php
                break;

            case 'register':
                $page_url = $this->get_page_url('register_page');

                if (!$page_url) {
                    if (current_user_can('manage_options')) {
                        ?>
                        <div class="csa-notice csa-notice-warning">
                            <p><?php esc_html_e('Registration page is not configured. Please map a registration page in the plugin settings.', 'custom-secure-auth'); ?></p>
                        </div>
                        <?php
                    }
                    break;
                }

                $button_text = $custom_text ? $custom_text : __('Register', 'custom-secure-auth');

                if (is_user_logged_in()) {
                    // Show nothing if already logged in
                    break;
                }
                ?>
                <a href="<?php echo esc_url($page_url); ?>" class="csa-auth-button <?php echo esc_attr($button_classes); ?>">
                    <?php echo esc_html($button_text); ?>
                </a>
                <?php
                break;

            case 'logout':
                if (!is_user_logged_in()) {
                    // Show nothing if not logged in
                    break;
                }

                $button_text = $custom_text ? $custom_text : __('Log Out', 'custom-secure-auth');
                $logout_url = wp_logout_url(home_url());
                ?>
                <a href="<?php echo esc_url($logout_url); ?>" class="csa-auth-button <?php echo esc_attr($button_classes); ?>">
                    <?php echo esc_html($button_text); ?>
                </a>
                <?php
                break;

            default:
                if (current_user_can('manage_options')) {
                    ?>
                    <div class="csa-notice csa-notice-error">
                        <p><?php esc_html_e('Invalid action specified. Use: login, register, or logout.', 'custom-secure-auth'); ?></p>
                    </div>
                    <?php
                }
                break;
        }

        return ob_get_clean();
    }

    /**
     * Render [auth_continue] shortcode
     *
     * Displays a button/link to continue browsing from where user left off before login.
     * Retrieves the last stored referrer from user meta (stored during login).
     *
     * Usage: [auth_continue text="Continue Browsing" class="my-button-class"]
     *
     * @param array $atts Shortcode attributes
     * @return string HTML for continue button
     */
    public function render_continue_button($atts) {
        // Parse shortcode attributes
        $atts = shortcode_atts(array(
            'text' => 'Enter Site',
            'class' => '',
        ), $atts);

        $button_text = !empty($atts['text']) ? esc_html($atts['text']) : 'Enter Site';
        $custom_class = !empty($atts['class']) ? esc_attr($atts['class']) : '';
        $button_classes = $this->get_button_classes() . ' ' . $custom_class;

        // Only show for logged in users
        if (!is_user_logged_in()) {
            return '';
        }

        $current_user = wp_get_current_user();

        // Get stored referrer from user meta
        $stored_referrer = get_user_meta($current_user->ID, 'csa_last_referrer', true);
        $referrer_time = get_user_meta($current_user->ID, 'csa_last_referrer_time', true);

        // Check if referrer exists and is less than 24 hours old
        if (empty($stored_referrer) || empty($referrer_time)) {
            error_log('[CSA Continue Button] No stored referrer found for user ID ' . $current_user->ID);
            return '';
        }

        // Check if referrer is expired (24 hours)
        $referrer_age = time() - intval($referrer_time);
        if ($referrer_age > (24 * HOUR_IN_SECONDS)) {
            error_log('[CSA Continue Button] Stored referrer expired for user ID ' . $current_user->ID);
            // Clean up expired user meta
            delete_user_meta($current_user->ID, 'csa_last_referrer');
            delete_user_meta($current_user->ID, 'csa_last_referrer_time');
            return '';
        }

        // Validate referrer is from same domain (defense in depth)
        $referrer_host = parse_url($stored_referrer, PHP_URL_HOST);
        $site_host = parse_url(home_url(), PHP_URL_HOST);

        if ($referrer_host !== $site_host) {
            error_log('[CSA Continue Button] Referrer host mismatch for user ID ' . $current_user->ID);
            // Clean up invalid referrer
            delete_user_meta($current_user->ID, 'csa_last_referrer');
            delete_user_meta($current_user->ID, 'csa_last_referrer_time');
            return '';
        }

        // Check if referrer is one of the auth pages - if so, don't show the button
        $page_mapping = isset($this->settings['page_mapping']) ? $this->settings['page_mapping'] : array();
        $auth_page_ids = array(
            isset($page_mapping['login_page']) ? $page_mapping['login_page'] : 0,
            isset($page_mapping['register_page']) ? $page_mapping['register_page'] : 0,
            isset($page_mapping['lost_password_page']) ? $page_mapping['lost_password_page'] : 0,
            isset($page_mapping['set_password_page']) ? $page_mapping['set_password_page'] : 0,
        );

        $referrer_page_id = url_to_postid($stored_referrer);
        if (in_array($referrer_page_id, $auth_page_ids, true) && $referrer_page_id !== 0) {
            error_log('[CSA Continue Button] Referrer is an auth page for user ID ' . $current_user->ID);
            return '';
        }

        ob_start();
        ?>
        <a href="<?php echo esc_url($stored_referrer); ?>" class="csa-auth-button csa-continue-button <?php echo esc_attr($button_classes); ?>">
            <?php echo esc_html($button_text); ?>
        </a>
        <?php
        return ob_get_clean();
    }
}
