<?php
/**
 * REST API Handler with 403 Security Gauntlet
 *
 * @package CustomSecureAuth
 */

if (!defined('ABSPATH')) {
    exit;
}

class CSA_Rest_Handler extends WP_REST_Controller {

    private $settings;
    protected $namespace = 'custom-secure-auth/v1';

    public function __construct() {
        $this->settings = get_option(CSA_SETTINGS_SLUG, array());
    }

    /**
     * Register REST API routes
     */
    public function register_routes() {
        register_rest_route($this->namespace, '/register', array(
            'methods' => 'POST',
            'callback' => array($this, 'handle_registration'),
            'permission_callback' => '__return_true',
        ));

        register_rest_route($this->namespace, '/login', array(
            'methods' => 'POST',
            'callback' => array($this, 'handle_login'),
            'permission_callback' => '__return_true',
        ));

        register_rest_route($this->namespace, '/lost-password', array(
            'methods' => 'POST',
            'callback' => array($this, 'handle_lost_password'),
            'permission_callback' => '__return_true',
        ));

        register_rest_route($this->namespace, '/set-password', array(
            'methods' => 'POST',
            'callback' => array($this, 'handle_set_password'),
            'permission_callback' => '__return_true',
        ));

        register_rest_route($this->namespace, '/get-token', array(
            'methods' => 'GET',
            'callback' => array($this, 'get_form_token'),
            'permission_callback' => '__return_true',
        ));

        register_rest_route($this->namespace, '/generate-username', array(
            'methods' => 'GET',
            'callback' => array($this, 'handle_generate_username'),
            'permission_callback' => '__return_true',
        ));
    }

    /**
     * THE 403 GAUNTLET - Security validation
     *
     * @param WP_REST_Request $request
     * @return bool|WP_Error
     */
    private function validate_request($request) {
        $ip = $this->get_user_ip();

        // Check 1: IP Lockout (The Gate)
        if (get_transient('auth_block_' . md5($ip))) {
            $this->log_security_event('blocked_ip', $ip);
            return new WP_Error(
                'csa_blocked',
                __('Too many failed attempts. Please try again later.', 'custom-secure-auth'),
                array('status' => 403)
            );
        }

        // Check 2: HTTP Referer validation
        $referer = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';
        $site_url = get_site_url();

        if (empty($referer) || strpos($referer, $site_url) !== 0) {
            $this->log_security_event('invalid_referer', $ip, array('referer' => $referer));
            return new WP_Error(
                'csa_invalid_referer',
                __('Invalid request origin.', 'custom-secure-auth'),
                array('status' => 403)
            );
        }

        // Check 3: Timed Token validation
        $submitted_token = $request->get_param('csa_token');
        $submitted_timestamp = $request->get_param('csa_timestamp');

        if (!$this->validate_timed_token($submitted_token, $submitted_timestamp, $ip)) {
            $this->log_security_event('invalid_token', $ip);
            return new WP_Error(
                'csa_invalid_token',
                __('Security token expired or invalid.', 'custom-secure-auth'),
                array('status' => 403)
            );
        }

        // Check 4: Honeypot validation
        $security = isset($this->settings['security']) ? $this->settings['security'] : array();
        $honeypot_enabled = isset($security['honeypot_enabled']) ? $security['honeypot_enabled'] : true;

        if ($honeypot_enabled) {
            $honeypot_value = $request->get_param('csa_website');
            if (!empty($honeypot_value)) {
                $this->log_security_event('honeypot_triggered', $ip);
                return new WP_Error(
                    'csa_spam_detected',
                    __('Spam detected.', 'custom-secure-auth'),
                    array('status' => 403)
                );
            }
        }

        // Check 5: reCAPTCHA v3 validation (if configured)
        if (!empty($security['recaptcha_secret_key'])) {
            $recaptcha_token = $request->get_param('recaptcha_token');
            if (!$this->validate_recaptcha($recaptcha_token, $security['recaptcha_secret_key'])) {
                $this->log_security_event('recaptcha_failed', $ip);
                return new WP_Error(
                    'csa_recaptcha_failed',
                    __('reCAPTCHA verification failed.', 'custom-secure-auth'),
                    array('status' => 403)
                );
            }
        }

        return true;
    }

    /**
     * Generate timed form token
     */
    public function get_form_token() {
        $ip = $this->get_user_ip();
        $timestamp = time();
        $token = $this->generate_timed_token($ip, $timestamp);

        return rest_ensure_response(array(
            'token' => $token,
            'timestamp' => $timestamp,
        ));
    }

    /**
     * Generate HMAC token
     */
    private function generate_timed_token($ip, $timestamp) {
        $secret = defined('AUTH_KEY') ? AUTH_KEY : 'csa_default_secret';
        return hash_hmac('sha256', $ip . $timestamp, $secret);
    }

    /**
     * Validate timed token
     */
    private function validate_timed_token($token, $timestamp, $ip) {
        if (empty($token) || empty($timestamp)) {
            return false;
        }

        // Check token expiry
        $global_config = isset($this->settings['global_config']) ? $this->settings['global_config'] : array();
        $expiry_minutes = isset($global_config['token_expiry']) ? intval($global_config['token_expiry']) : 30;

        if ((time() - $timestamp) > ($expiry_minutes * 60)) {
            return false;
        }

        // Regenerate and compare
        $expected_token = $this->generate_timed_token($ip, $timestamp);
        return hash_equals($expected_token, $token);
    }

    /**
     * Validate reCAPTCHA v3
     */
    private function validate_recaptcha($token, $secret_key) {
        if (empty($token)) {
            return false;
        }

        $response = wp_remote_post('https://www.google.com/recaptcha/api/siteverify', array(
            'body' => array(
                'secret' => $secret_key,
                'response' => $token,
            ),
        ));

        if (is_wp_error($response)) {
            return false;
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        return isset($body['success']) && $body['success'] === true;
    }

    /**
     * Handle user registration (Flow A: The Hybrid Logic)
     */
    public function handle_registration($request) {
        // Run the 403 Gauntlet
        $validation = $this->validate_request($request);
        if (is_wp_error($validation)) {
            return $validation;
        }
    
        // Use WordPress standard field names
        $username = sanitize_user($request->get_param('user_login'));
        $email = sanitize_email($request->get_param('user_email'));
        $password = $request->get_param('user_pass');
        $first_name = sanitize_text_field($request->get_param('first_name'));
        $last_name = sanitize_text_field($request->get_param('last_name'));
    
        // Validation
        if (empty($username) || empty($email)) {
            return new WP_Error(
                'csa_missing_fields',
                __('Username and email are required.', 'custom-secure-auth'),
                array('status' => 400)
            );
        }

        // Validate username against policy
        $username_validation = $this->validate_username_policy($username);
        if (is_wp_error($username_validation)) {
            return $username_validation;
        }

        if (!is_email($email)) {
            return new WP_Error(
                'csa_invalid_email',
                __('Invalid email address.', 'custom-secure-auth'),
                array('status' => 400)
            );
        }
    
        if (username_exists($username)) {
            return new WP_Error(
                'csa_username_exists',
                __('Username already exists.', 'custom-secure-auth'),
                array('status' => 400)
            );
        }
    
        if (email_exists($email)) {
            return new WP_Error(
                'csa_email_exists',
                __('Email already exists.', 'custom-secure-auth'),
                array('status' => 400)
            );
        }
    
        // Hybrid Logic: Check if password is provided
        if (!empty($password)) {
            // Flow A1: Password provided - Create active account
            $user_id = wp_create_user($username, $password, $email);
    
            if (is_wp_error($user_id)) {
                return $user_id;
            }
    
            // Add first and last name
            if (!empty($first_name) || !empty($last_name)) {
                wp_update_user(array(
                    'ID' => $user_id,
                    'first_name' => $first_name,
                    'last_name' => $last_name,
                ));
            }
    
            // Log in the user automatically
            wp_set_current_user($user_id);
            wp_set_auth_cookie($user_id);
    
            $this->log_security_event('registration_success', $this->get_user_ip(), array(
                'user_id' => $user_id,
                'username' => $username,
            ));
    
            return rest_ensure_response(array(
                'success' => true,
                'message' => __('Registration successful! You are now logged in.', 'custom-secure-auth'),
                'redirect_url' => $this->get_redirect_url(),
            ));
        } else {
            // Flow A2: No password - Send activation email
            $user_id = wp_create_user($username, wp_generate_password(), $email);
    
            if (is_wp_error($user_id)) {
                return $user_id;
            }
    
            // Add first and last name
            if (!empty($first_name) || !empty($last_name)) {
                wp_update_user(array(
                    'ID' => $user_id,
                    'first_name' => $first_name,
                    'last_name' => $last_name,
                ));
            }
    
            // Set user as pending activation
            update_user_meta($user_id, 'csa_activation_pending', true);
    
            // Generate activation key
            $activation_key = wp_generate_password(20, false);
            update_user_meta($user_id, 'csa_activation_key', $activation_key);
            update_user_meta($user_id, 'csa_activation_key_expiry', time() + (24 * 60 * 60)); // 24 hours
    
            // Send activation email
            $this->send_activation_email($user_id, $username, $email, $activation_key);
    
            $this->log_security_event('registration_activation_sent', $this->get_user_ip(), array(
                'user_id' => $user_id,
                'username' => $username,
            ));

            return rest_ensure_response(array(
                'success' => true,
                'message' => __('Registration successful! Please check your email to activate your account.', 'custom-secure-auth'),
            ));
        }
    }

    /**
     * Handle user login (Flow B: Login with activation check)
     */
    public function handle_login($request) {
        // Run the 403 Gauntlet
        $validation = $this->validate_request($request);
        if (is_wp_error($validation)) {
            return $validation;
        }

        $username = sanitize_user($request->get_param('username'));
        $password = $request->get_param('password');
        $remember = $request->get_param('remember') === 'true';

        if (empty($username) || empty($password)) {
            return new WP_Error(
                'csa_missing_credentials',
                __('Username and password are required.', 'custom-secure-auth'),
                array('status' => 400)
            );
        }

        // Attempt authentication
        $user = wp_authenticate($username, $password);

        if (is_wp_error($user)) {
            $this->increment_failed_attempts();
            $this->log_security_event('login_failed', $this->get_user_ip(), array(
                'username' => $username,
                'error' => $user->get_error_message(),
            ));

            return new WP_Error(
                'csa_login_failed',
                __('Invalid username or password.', 'custom-secure-auth'),
                array('status' => 401)
            );
        }

        // Check if account is pending activation
        if (get_user_meta($user->ID, 'csa_activation_pending', true)) {
            return new WP_Error(
                'csa_activation_required',
                __('Please activate your account first. Check your email for the activation link.', 'custom-secure-auth'),
                array('status' => 403)
            );
        }

        // Login successful
        wp_clear_auth_cookie();
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, $remember);

        $this->log_security_event('login_success', $this->get_user_ip(), array(
            'user_id' => $user->ID,
            'username' => $username,
        ));

        return rest_ensure_response(array(
            'success' => true,
            'message' => __('Login successful!', 'custom-secure-auth'),
            'redirect_url' => $this->get_redirect_url(),
        ));
    }

    /**
     * Handle lost password request (Flow C)
     */
    public function handle_lost_password($request) {
        // Run the 403 Gauntlet
        $validation = $this->validate_request($request);
        if (is_wp_error($validation)) {
            return $validation;
        }

        $user_login = sanitize_text_field($request->get_param('user_login'));

        if (empty($user_login)) {
            return new WP_Error(
                'csa_missing_user_login',
                __('Please enter your username or email address.', 'custom-secure-auth'),
                array('status' => 400)
            );
        }

        // Use WordPress core retrieve_password function
        $result = retrieve_password($user_login);

        if (is_wp_error($result)) {
            $this->log_security_event('lost_password_failed', $this->get_user_ip(), array(
                'user_login' => $user_login,
                'error' => $result->get_error_message(),
            ));

            return new WP_Error(
                'csa_retrieve_password_failed',
                __('Unable to process password reset request. Please verify your username or email.', 'custom-secure-auth'),
                array('status' => 400)
            );
        }

        // Send custom recovery email
        $user = null;
        if (strpos($user_login, '@')) {
            $user = get_user_by('email', $user_login);
        } else {
            $user = get_user_by('login', $user_login);
        }

        if ($user) {
            $this->send_recovery_email($user->ID, $user->user_login, $user->user_email);
        }

        $this->log_security_event('lost_password_success', $this->get_user_ip(), array(
            'user_login' => $user_login,
        ));

        return rest_ensure_response(array(
            'success' => true,
            'message' => __('Password reset link has been sent to your email.', 'custom-secure-auth'),
        ));
    }

    /**
     * Handle set password (Flow D: Activation or Reset)
     */
    public function handle_set_password($request) {
        // Run the 403 Gauntlet (excluding token for this flow)
        $ip = $this->get_user_ip();

        if (get_transient('auth_block_' . md5($ip))) {
            return new WP_Error(
                'csa_blocked',
                __('Too many failed attempts. Please try again later.', 'custom-secure-auth'),
                array('status' => 403)
            );
        }

        $key = sanitize_text_field($request->get_param('key'));
        $login = sanitize_user($request->get_param('login'));
        $password = $request->get_param('password');

        if (empty($key) || empty($login) || empty($password)) {
            return new WP_Error(
                'csa_missing_fields',
                __('All fields are required.', 'custom-secure-auth'),
                array('status' => 400)
            );
        }

        // Check password strength
        if (strlen($password) < 8) {
            return new WP_Error(
                'csa_weak_password',
                __('Password must be at least 8 characters long.', 'custom-secure-auth'),
                array('status' => 400)
            );
        }

        // Verify the reset key
        $user = check_password_reset_key($key, $login);

        if (is_wp_error($user)) {
            // Maybe it's an activation key
            $user = get_user_by('login', $login);

            if (!$user) {
                return new WP_Error(
                    'csa_invalid_key',
                    __('Invalid or expired key.', 'custom-secure-auth'),
                    array('status' => 400)
                );
            }

            $activation_key = get_user_meta($user->ID, 'csa_activation_key', true);
            $activation_expiry = get_user_meta($user->ID, 'csa_activation_key_expiry', true);

            if ($activation_key !== $key || time() > $activation_expiry) {
                return new WP_Error(
                    'csa_invalid_activation_key',
                    __('Invalid or expired activation key.', 'custom-secure-auth'),
                    array('status' => 400)
                );
            }

            // Valid activation key - activate account
            delete_user_meta($user->ID, 'csa_activation_pending');
            delete_user_meta($user->ID, 'csa_activation_key');
            delete_user_meta($user->ID, 'csa_activation_key_expiry');

            // Set the password
            wp_set_password($password, $user->ID);

            $this->log_security_event('account_activated', $ip, array(
                'user_id' => $user->ID,
                'username' => $login,
            ));

            // Check if auto-login is disabled
            $global_config = isset($this->settings['global_config']) ? $this->settings['global_config'] : array();
            $disable_auto_login = isset($global_config['disable_auto_login_after_reset']) ? $global_config['disable_auto_login_after_reset'] : false;

            if ($disable_auto_login) {
                // Don't auto-login, redirect to login page
                return rest_ensure_response(array(
                    'success' => true,
                    'message' => __('Account activated successfully! Please log in with your new password.', 'custom-secure-auth'),
                    'redirect_url' => $this->get_login_page_url(),
                ));
            }

            // Auto-login (default behavior)
            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID);

            return rest_ensure_response(array(
                'success' => true,
                'message' => __('Account activated successfully! You are now logged in.', 'custom-secure-auth'),
                'redirect_url' => $this->get_redirect_url(),
            ));
        }

        // Valid password reset key
        wp_set_password($password, $user->ID);

        $this->log_security_event('password_reset_success', $ip, array(
            'user_id' => $user->ID,
            'username' => $login,
        ));

        // Check if auto-login is disabled
        $global_config = isset($this->settings['global_config']) ? $this->settings['global_config'] : array();
        $disable_auto_login = isset($global_config['disable_auto_login_after_reset']) ? $global_config['disable_auto_login_after_reset'] : false;

        if ($disable_auto_login) {
            // Don't auto-login, redirect to login page
            return rest_ensure_response(array(
                'success' => true,
                'message' => __('Password reset successfully! Please log in with your new password.', 'custom-secure-auth'),
                'redirect_url' => $this->get_login_page_url(),
            ));
        }

        // Auto-login (default behavior)
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID);

        return rest_ensure_response(array(
            'success' => true,
            'message' => __('Password reset successfully! You are now logged in.', 'custom-secure-auth'),
            'redirect_url' => $this->get_redirect_url(),
        ));
    }

    /**
     * Send activation email
     */
    private function send_activation_email($user_id, $username, $email, $activation_key) {
        $emails = isset($this->settings['emails']) ? $this->settings['emails'] : array();
        $page_mapping = isset($this->settings['page_mapping']) ? $this->settings['page_mapping'] : array();

        $set_password_page_id = isset($page_mapping['set_password_page']) ? $page_mapping['set_password_page'] : 0;
        $set_password_url = get_permalink($set_password_page_id);

        if (!$set_password_url) {
            $set_password_url = wp_lostpassword_url();
        }

        $set_password_url = add_query_arg(array(
            'action' => 'activate',
            'key' => $activation_key,
            'login' => rawurlencode($username),
        ), $set_password_url);

        // Get email template
        $subject = isset($emails['activation_subject']) ? $emails['activation_subject'] : 'Activate Your Account - {site_name}';
        $template = isset($emails['activation_template']) ? $emails['activation_template'] : '<p>Hello {user_name},</p><p>Please click the link below to activate your account:</p><p><a href="{set_password_url}">Activate Account</a></p>';

        // Replace placeholders
        $subject = str_replace(
            array('{site_name}', '{user_name}'),
            array(get_bloginfo('name'), $username),
            $subject
        );

        $message = str_replace(
            array('{site_name}', '{user_name}', '{set_password_url}'),
            array(get_bloginfo('name'), $username, $set_password_url),
            $template
        );

        // Send email
        add_filter('wp_mail_content_type', function() { return 'text/html'; });
        wp_mail($email, $subject, $message);
        remove_filter('wp_mail_content_type', function() { return 'text/html'; });
    }

    /**
     * Handle username generation request
     *
     * Generates a fun username if the feature is enabled in settings.
     * Returns 403 error if feature is disabled.
     *
     * @param WP_REST_Request $request Request object
     * @return WP_REST_Response|WP_Error Response with generated username or error
     */
    public function handle_generate_username($request) {
        $settings = $this->settings;
        $fun_username_enabled = isset($settings['grid_builder']['fun_username_enabled']) ? $settings['grid_builder']['fun_username_enabled'] : false;

        if (!$fun_username_enabled) {
            return new WP_Error(
                'csa_feature_disabled',
                __('Fun username generation is disabled.', 'custom-secure-auth'),
                array('status' => 403)
            );
        }

        $username = $this->generate_fun_username();

        return rest_ensure_response(array(
            'success' => true,
            'username' => $username,
        ));
    }

    /**
     * Send recovery email
     */
    private function send_recovery_email($user_id, $username, $email) {
        $emails = isset($this->settings['emails']) ? $this->settings['emails'] : array();
        $page_mapping = isset($this->settings['page_mapping']) ? $this->settings['page_mapping'] : array();

        // Generate password reset key
        $key = get_password_reset_key(get_userdata($user_id));

        if (is_wp_error($key)) {
            return;
        }

        $set_password_page_id = isset($page_mapping['set_password_page']) ? $page_mapping['set_password_page'] : 0;
        $set_password_url = get_permalink($set_password_page_id);

        if (!$set_password_url) {
            $set_password_url = wp_lostpassword_url();
        }

        $set_password_url = add_query_arg(array(
            'action' => 'rp',
            'key' => $key,
            'login' => rawurlencode($username),
        ), $set_password_url);

        // Get email template
        $subject = isset($emails['recovery_subject']) ? $emails['recovery_subject'] : 'Reset Your Password - {site_name}';
        $template = isset($emails['recovery_template']) ? $emails['recovery_template'] : '<p>Hello {user_name},</p><p>Please click the link below to reset your password:</p><p><a href="{set_password_url}">Reset Password</a></p>';

        // Replace placeholders
        $subject = str_replace(
            array('{site_name}', '{user_name}'),
            array(get_bloginfo('name'), $username),
            $subject
        );

        $message = str_replace(
            array('{site_name}', '{user_name}', '{set_password_url}'),
            array(get_bloginfo('name'), $username, $set_password_url),
            $template
        );

        // Send email
        add_filter('wp_mail_content_type', function() { return 'text/html'; });
        wp_mail($email, $subject, $message);
        remove_filter('wp_mail_content_type', function() { return 'text/html'; });
    }

    /**
     * Increment failed attempts with IP velocity tracking
     */
    private function increment_failed_attempts() {
        $ip = $this->get_user_ip();
        $ip_hash = md5($ip);
        $transient_key = 'auth_attempts_' . $ip_hash;

        $attempts = get_transient($transient_key);
        $attempts = $attempts ? intval($attempts) + 1 : 1;

        // Set transient for 15 minutes
        set_transient($transient_key, $attempts, 15 * 60);

        // Check if max attempts reached
        $security = isset($this->settings['security']) ? $this->settings['security'] : array();
        $max_attempts = isset($security['max_failed_attempts']) ? intval($security['max_failed_attempts']) : 5;
        $lockout_duration = isset($security['lockout_duration']) ? intval($security['lockout_duration']) : 1;

        if ($attempts >= $max_attempts) {
            set_transient('auth_block_' . $ip_hash, true, $lockout_duration * 60 * 60);
            $this->log_security_event('ip_locked_out', $ip, array('attempts' => $attempts));
        }
    }

    /**
     * Get user IP address
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
     * Log security events
     */
    private function log_security_event($event_type, $ip, $data = array()) {
        $log_entry = array(
            'timestamp' => current_time('mysql'),
            'event_type' => $event_type,
            'ip_address' => $ip,
            'user_agent' => !empty($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field($_SERVER['HTTP_USER_AGENT']) : '',
            'data' => $data,
        );

        // Get existing logs
        $logs = get_option('csa_security_logs', array());

        // Add new log entry
        array_unshift($logs, $log_entry);

        // Keep only last 1000 entries
        $logs = array_slice($logs, 0, 1000);

        // Save logs
        update_option('csa_security_logs', $logs, false);

        // Also log to error_log for critical events
        if (in_array($event_type, array('blocked_ip', 'ip_locked_out', 'honeypot_triggered'))) {
            error_log(sprintf(
                'CSA Security Event: %s | IP: %s | Data: %s',
                $event_type,
                $ip,
                wp_json_encode($data)
            ));
        }
    }

    /**
     * Get redirect URL after login
     */
    private function get_redirect_url() {
        $global_config = isset($this->settings['global_config']) ? $this->settings['global_config'] : array();
        $redirect_page_id = isset($global_config['redirect_after_login']) ? $global_config['redirect_after_login'] : 0;

        // Get URL from page ID, or use home_url() if not set
        if ($redirect_page_id) {
            $redirect_url = get_permalink($redirect_page_id);
            if (!$redirect_url) {
                $redirect_url = home_url(); // Fallback if page doesn't exist
            }
        } else {
            $redirect_url = home_url();
        }

        // Allow redirect parameter override
        if (!empty($_GET['redirect_to'])) {
            $redirect_url = esc_url_raw($_GET['redirect_to']);
        }

        return $redirect_url;
    }

    /**
     * Get login page URL
     *
     * @return string Login page URL or home URL if not configured
     */
    private function get_login_page_url() {
        $page_mapping = isset($this->settings['page_mapping']) ? $this->settings['page_mapping'] : array();
        $login_page_id = isset($page_mapping['login_page']) ? $page_mapping['login_page'] : 0;

        if ($login_page_id) {
            return get_permalink($login_page_id);
        }

        return home_url();
    }

    /**
     * Generate a fun, unique username
     *
     * Generates creative usernames like "Sassy_Clanker42" by combining
     * random prefixes, suffixes, and numbers. Ensures uniqueness by checking
     * against existing usernames in the database.
     *
     * @return string Generated lowercase username (e.g., "sassy_clanker429")
     */
    private function generate_fun_username() {
        $prefixes = array(
            // Tech, AI & Code Status
            'Digital', 'Analog', 'Synthetic', 'Latent', 'Glitchy', 'Pixelated',
            'Rendered', 'Cyber', 'Virtual', 'Diffused', 'Neural', 'Binary',
            'Recursive', 'Deprecated', 'Cached', 'Encrypted', 'Compiled', 'Runtime',
            'Lossy', 'Lossless', 'Vector', 'Fractal', 'Quantum', 'Haptic',
            'Volumetric', 'Static', 'Dynamic', 'Root', 'Sudo', 'Headless',
            'Hosted', 'Local', 'Zipped', 'Corrupt', 'Null', 'Undefined',

            // Mood, Personality & Vibe
            'Unapologetic', 'Sassy', 'Confused', 'Aggressive', 'Suspicious',
            'Dramatic', 'Feral', 'Domestic', 'Panic', 'Chill', 'Manic',
            'Vague', 'Obscure', 'Explicit', 'Censored', 'Salty', 'Spicy',
            'Thirsty', 'Petty', 'Bitter', 'Stoic', 'Existential', 'Chaotic',
            'Lawful', 'Neutral', 'Cursed', 'Blessed', 'Blighted', 'Radiant',
            'Tired', 'Wired', 'Shady', 'Loud', 'Quiet', 'Humble', 'Vain',
            'Reckless', 'Anxious', 'Smug', 'Grumpy', 'Based', 'Cringy',

            // Aesthetic, Texture & Physical
            'Velvet', 'Neon', 'Gritty', 'Polished', 'Matte', 'Chrome',
            'Golden', 'Rusty', 'Hollow', 'Dense', 'Fluid', 'Rigid',
            'Sharp', 'Soft', 'Jagged', 'Smooth', 'Rough', 'Slick',
            'Oily', 'Dry', 'Wet', 'Dusty', 'Clean', 'Dirty', 'Raw',
            'Fried', 'Cooked', 'Burnt', 'Frozen', 'Melted', 'Broken',
            'Sticky', 'Slippery', 'Heavy', 'Light', 'Dark', 'Bright',

            // Absurd, Weird & "Internet"
            'Wobbly', 'Moist', 'Crunchy', 'Floppy', 'Illegal', 'Forbidden',
            'Haunted', 'Sentient', 'Rogue', 'Sleepy', 'Infinite',
            'Soggy', 'Moldy', 'Stale', 'Fresh', 'Spooky', 'Sketchy',
            'Dangerous', 'Safe', 'Radical', 'Basic', 'Fancy', 'Cheap',
            'Expensive', 'Discount', 'Premium', 'Luxury', 'Bespoke',
            'Artisan', 'Vintage', 'Retro', 'Modern', 'Futuristic'
        );

        $suffixes = array(
            // AI, Hardware & Tech Objects
            'Clanker', 'GPU', 'Tensor', 'Node', 'Token', 'Seed', 'Prompt',
            'Algorithm', 'Mainframe', 'Glitch', 'Voxel', 'Server', 'Bot',
            'Daemon', 'Kernel', 'Shell', 'Proxy', 'Cache', 'Buffer',
            'Latency', 'Ping', 'Packet', 'Protocol', 'Firewall', 'Driver',
            'Socket', 'Wire', 'Cable', 'Screen', 'Mouse', 'Key', 'Code',
            'Script', 'Bug', 'Feature', 'Patch', 'Update', 'Version',
            'Cycle', 'Stack', 'Heap', 'Queue', 'Array', 'String', 'Integer',

            // Art, Abstract & Concepts
            'Gaze', 'Void', 'Canvas', 'Shadow', 'Dream', 'Nightmare', 'Illusion',
            'Specter', 'Echo', 'Noise', 'Grain', 'Focus', 'Blur', 'Lambda',
            'Vertex', 'Mesh', 'Layer', 'Texture', 'Shader', 'Render',
            'Batch', 'Epoch', 'Loss', 'Weight', 'Bias', 'Model', 'Checkpoint',
            'Lora', 'Embedding', 'Negative', 'Positive', 'Mask', 'Inpaint',
            'Outpaint', 'Upscale', 'Denoise', 'Sampler', 'Step', 'Cfg',

            // Creatures (Chaos & Memes)
            'Goblin', 'Gremlin', 'Badger', 'Goose', 'Cryptid', 'Demon',
            'Dragon', 'Panda', 'Otter', 'Wolf', 'Crow', 'Lobster',
            'Opossum', 'Raccoon', 'Skunk', 'Armadillo', 'Capybara', 'Wombat',
            'Koala', 'Kangaroo', 'Frog', 'Toad', 'Newt', 'Lizard', 'Snake',
            'Turtle', 'Shark', 'Whale', 'Dolphin', 'Seal', 'Walrus', 'Penguin',
            'Chicken', 'Duck', 'Swan', 'Owl', 'Hawk', 'Eagle', 'Pigeon',

            // Random Objects & Food (The "Absurd" Factor)
            'Toast', 'Potato', 'Muffin', 'Spoon', 'Cactus', 'Sock', 'Brick',
            'Noodle', 'Biscuit', 'Tornado', 'Chaos', 'Soup', 'Sandwich',
            'Disaster', 'Incident', 'Theory', 'Paradox',
            'Pizza', 'Burger', 'Taco', 'Burrito', 'Salad', 'Sushi', 'Ramen',
            'Pasta', 'Bread', 'Cheese', 'Butter', 'Milk', 'Coffee', 'Tea',
            'Soda', 'Water', 'Juice', 'Spatula', 'Toaster', 'Fridge', 'Oven',
            'Sink', 'Chair', 'Table', 'Desk', 'Lamp', 'Rug', 'Mat', 'Pillow'
        );

        // Generate unique username with do-while loop
        do {
            $random_prefix = $prefixes[array_rand($prefixes)];
            $random_suffix = $suffixes[array_rand($suffixes)];

            // Increased entropy to 3 digits (100-999) for 2.6m combos
            $generated_username = $random_prefix . '_' . $random_suffix . rand(100, 999);

        } while (username_exists($generated_username));

        return strtolower($generated_username);
    }

    /**
     * Validate username against policy rules
     *
     * @param string $username The username to validate
     * @return true|WP_Error True if valid, WP_Error if invalid
     */
    private function validate_username_policy($username) {
        $policy = isset($this->settings['username_policy']) ? $this->settings['username_policy'] : array();

        // Convert to lowercase for checking
        $username_lower = strtolower($username);
        $violations = array();

        // Format Rules (Always Enforced)

        // Length: 6-24 characters
        if (strlen($username) < 6 || strlen($username) > 24) {
            return new WP_Error(
                'csa_username_length',
                __('Username must be between 6 and 24 characters.', 'custom-secure-auth'),
                array('status' => 400)
            );
        }

        // Allowed characters: a-z, 0-9, underscore, hyphen
        if (!preg_match('/^[a-z0-9_-]+$/i', $username)) {
            return new WP_Error(
                'csa_username_invalid_chars',
                __('Username can only contain letters, numbers, underscores, and hyphens.', 'custom-secure-auth'),
                array('status' => 400)
            );
        }

        // No purely numeric usernames
        if (is_numeric($username)) {
            return new WP_Error(
                'csa_username_numeric',
                __('Username cannot be purely numeric.', 'custom-secure-auth'),
                array('status' => 400)
            );
        }

        // No email addresses
        if (strpos($username, '@') !== false) {
            return new WP_Error(
                'csa_username_email',
                __('Username cannot be an email address.', 'custom-secure-auth'),
                array('status' => 400)
            );
        }

        // Reserved Words (Always Active)
        $reserved_words = isset($policy['reserved_words']) ? $policy['reserved_words'] : array();
        $reserved_boundary_match = isset($policy['reserved_words_boundary_match']) && $policy['reserved_words_boundary_match'];
        $has_reserved = false;

        foreach ($reserved_words as $word) {
            $word_lower = strtolower($word);

            if ($reserved_boundary_match) {
                // Word boundary match: block if word appears with boundaries
                if (preg_match('/\b' . preg_quote($word_lower, '/') . '\b/', $username_lower)) {
                    $violations[] = 'reserved';
                    $has_reserved = true;
                    break;
                }
            } else {
                // Exact match only
                if ($username_lower === $word_lower) {
                    $violations[] = 'reserved';
                    $has_reserved = true;
                    break;
                }
            }
        }

        // Tier 1: Strict Block (Substring Match)
        $strict_enabled = isset($policy['restricted_strict_enabled']) && $policy['restricted_strict_enabled'];
        $has_inappropriate = false;
        if ($strict_enabled) {
            $strict_words = isset($policy['restricted_strict_words']) ? $policy['restricted_strict_words'] : array();

            foreach ($strict_words as $word) {
                $word_lower = strtolower($word);
                // Substring match: block if word appears anywhere
                if (strpos($username_lower, $word_lower) !== false) {
                    $violations[] = 'inappropriate';
                    $has_inappropriate = true;
                    break;
                }
            }
        }

        // Tier 2: Isolated Block (Word Boundary Match)
        $isolated_enabled = isset($policy['restricted_isolated_enabled']) && $policy['restricted_isolated_enabled'];
        if ($isolated_enabled && !$has_inappropriate) {
            $isolated_words = isset($policy['restricted_isolated_words']) ? $policy['restricted_isolated_words'] : array();

            foreach ($isolated_words as $word) {
                $word_lower = strtolower($word);
                // Word boundary match: block only when word stands alone
                if (preg_match('/\b' . preg_quote($word_lower, '/') . '\b/', $username_lower)) {
                    $violations[] = 'inappropriate';
                    $has_inappropriate = true;
                    break;
                }
            }
        }

        // If there are violations, return combined error message
        if (!empty($violations)) {
            $message_parts = array();

            if ($has_reserved) {
                $message_parts[] = __('reserved words', 'custom-secure-auth');
            }
            if ($has_inappropriate) {
                $message_parts[] = __('content that goes against our guidelines', 'custom-secure-auth');
            }

            $message = sprintf(
                __('Username contains %s.', 'custom-secure-auth'),
                implode(' and ', $message_parts)
            );

            return new WP_Error(
                'csa_username_policy_violation',
                $message,
                array('status' => 400)
            );
        }

        return true;
    }
}
