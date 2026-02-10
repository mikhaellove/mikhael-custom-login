<?php
/**
 * Email Manager Class
 *
 * Handles email template processing and sending for Custom Secure Auth
 *
 * @package Custom_Secure_Auth
 * @since 2.0.0
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * CSA_Email_Manager Class
 *
 * Manages all email-related functionality including:
 * - Custom email templates
 * - WordPress password reset email customization
 * - Activation email handling
 * - Proper HTML email formatting
 */
class CSA_Email_Manager {

    /**
     * Plugin settings
     *
     * @var array
     */
    private $settings;

    /**
     * Constructor
     *
     * Initializes the email manager and hooks into WordPress filters
     */
    public function __construct() {
        $this->settings = get_option(CSA_SETTINGS_SLUG, array());
        $this->init_hooks();
    }

    /**
     * Initialize WordPress hooks
     */
    private function init_hooks() {
        // Hook into WordPress password reset email
        add_filter('retrieve_password_message', array($this, 'customize_password_reset_message'), 10, 4);
        add_filter('retrieve_password_title', array($this, 'customize_password_reset_subject'), 10, 3);

        // Ensure HTML emails are sent properly
        add_filter('wp_mail_content_type', array($this, 'maybe_set_html_content_type'), 999);
    }

    /**
     * Customize password reset email message
     *
     * This filter is called by WordPress when a password reset is requested.
     * We check if the user needs activation or password recovery and use the appropriate template.
     *
     * @param string $message Default message
     * @param string $key The reset key
     * @param string $user_login The user login
     * @param WP_User $user_data WP_User object
     * @return string Modified message
     */
    public function customize_password_reset_message($message, $key, $user_login, $user_data) {
        // Check if user is pending activation
        $is_activation = $this->is_user_pending_activation($user_data->ID);

        // Get the appropriate template
        if ($is_activation) {
            $template = $this->get_activation_template();
        } else {
            $template = $this->get_recovery_template();
        }

        // Build the password reset URL
        $reset_url = $this->build_reset_url($key, $user_login, $is_activation);

        // Prepare placeholders (pre-sanitized for security)
        $placeholders = array(
            'user_name' => esc_html($this->get_user_display_name($user_data)),
            'set_password_url' => $reset_url, // Already sanitized with esc_url_raw() in build_reset_url()
            'site_name' => esc_html($this->get_site_name()),
            'user_email' => esc_html($user_data->user_email),
            'user_login' => esc_html($user_data->user_login),
        );

        // Replace placeholders in template
        $customized_message = $this->replace_placeholders($template, $placeholders);

        return $customized_message;
    }

    /**
     * Customize password reset email subject
     *
     * @param string $title Default title
     * @param string $user_login The user login
     * @param WP_User $user_data WP_User object
     * @return string Modified title
     */
    public function customize_password_reset_subject($title, $user_login, $user_data) {
        // Check if user is pending activation
        $is_activation = $this->is_user_pending_activation($user_data->ID);

        // Get the appropriate subject
        if ($is_activation) {
            $subject = $this->get_activation_subject();
        } else {
            $subject = $this->get_recovery_subject();
        }

        // Prepare placeholders (pre-sanitized for security)
        $placeholders = array(
            'user_name' => esc_html($this->get_user_display_name($user_data)),
            'site_name' => esc_html($this->get_site_name()),
            'user_email' => esc_html($user_data->user_email),
            'user_login' => esc_html($user_data->user_login),
        );

        // Replace placeholders in subject
        $customized_subject = $this->replace_placeholders($subject, $placeholders);

        return $customized_subject;
    }

    /**
     * Check if user is pending activation
     *
     * Checks both csa_activation_pending and _requires_activation meta keys
     *
     * @param int $user_id User ID
     * @return bool True if pending activation
     */
    private function is_user_pending_activation($user_id) {
        $csa_pending = get_user_meta($user_id, 'csa_activation_pending', true);
        $requires_activation = get_user_meta($user_id, '_requires_activation', true);

        return !empty($csa_pending) || !empty($requires_activation);
    }

    /**
     * Build password reset URL
     *
     * Uses the Set Password page from Page Mapper settings
     *
     * @param string $key Reset key
     * @param string $user_login User login
     * @param bool $is_activation Whether this is an activation email
     * @return string Password reset URL
     */
    private function build_reset_url($key, $user_login, $is_activation = false) {
        $page_mapping = isset($this->settings['page_mapping']) ? $this->settings['page_mapping'] : array();
        $set_password_page_id = isset($page_mapping['set_password_page']) ? absint($page_mapping['set_password_page']) : 0;

        // Get the set password page URL
        if ($set_password_page_id > 0) {
            $base_url = get_permalink($set_password_page_id);
        } else {
            // Fallback to WordPress default
            $base_url = network_site_url('wp-login.php?action=rp', 'login');
        }

        // Ensure we have a valid URL
        if (!$base_url) {
            $base_url = network_site_url('wp-login.php?action=rp', 'login');
        }

        // Build query args
        $query_args = array(
            'action' => $is_activation ? 'activate' : 'rp',
            'key' => $key,
            'login' => rawurlencode($user_login),
        );

        // Build the full URL
        $reset_url = add_query_arg($query_args, $base_url);

        return esc_url_raw($reset_url);
    }

    /**
     * Get activation email template
     *
     * @return string Activation template
     */
    private function get_activation_template() {
        $emails = isset($this->settings['emails']) ? $this->settings['emails'] : array();

        $default_template = '<p>Hello {user_name},</p>' . "\n" .
                           '<p>Welcome to {site_name}! Please click the link below to activate your account and set your password:</p>' . "\n" .
                           '<p><a href="{set_password_url}" style="display: inline-block; padding: 10px 20px; background-color: #0073aa; color: #ffffff; text-decoration: none; border-radius: 3px;">Activate Your Account</a></p>' . "\n" .
                           '<p>Or copy and paste this URL into your browser:</p>' . "\n" .
                           '<p>{set_password_url}</p>' . "\n" .
                           '<p>This link will expire in 24 hours.</p>' . "\n" .
                           '<p>If you did not create an account, please ignore this email.</p>';

        return isset($emails['activation_template']) ? $emails['activation_template'] : $default_template;
    }

    /**
     * Get activation email subject
     *
     * @return string Activation subject
     */
    private function get_activation_subject() {
        $emails = isset($this->settings['emails']) ? $this->settings['emails'] : array();
        $default_subject = 'Activate Your Account - {site_name}';

        return isset($emails['activation_subject']) ? $emails['activation_subject'] : $default_subject;
    }

    /**
     * Get recovery email template
     *
     * @return string Recovery template
     */
    private function get_recovery_template() {
        $emails = isset($this->settings['emails']) ? $this->settings['emails'] : array();

        $default_template = '<p>Hello {user_name},</p>' . "\n" .
                           '<p>Someone has requested a password reset for the following account on {site_name}:</p>' . "\n" .
                           '<p>Username: {user_login}</p>' . "\n" .
                           '<p>If this was a mistake, just ignore this email and nothing will happen.</p>' . "\n" .
                           '<p>To reset your password, click the link below:</p>' . "\n" .
                           '<p><a href="{set_password_url}" style="display: inline-block; padding: 10px 20px; background-color: #0073aa; color: #ffffff; text-decoration: none; border-radius: 3px;">Reset Your Password</a></p>' . "\n" .
                           '<p>Or copy and paste this URL into your browser:</p>' . "\n" .
                           '<p>{set_password_url}</p>' . "\n" .
                           '<p>This link will expire in 24 hours.</p>';

        return isset($emails['recovery_template']) ? $emails['recovery_template'] : $default_template;
    }

    /**
     * Get recovery email subject
     *
     * @return string Recovery subject
     */
    private function get_recovery_subject() {
        $emails = isset($this->settings['emails']) ? $this->settings['emails'] : array();
        $default_subject = 'Reset Your Password - {site_name}';

        return isset($emails['recovery_subject']) ? $emails['recovery_subject'] : $default_subject;
    }

    /**
     * Replace placeholders in template
     *
     * Note: Placeholder values should already be sanitized before being passed to this function.
     * URLs should be sanitized with esc_url_raw(), text with esc_html(), etc.
     * This function performs NO additional escaping to preserve HTML links and formatting.
     *
     * @param string $template Template content
     * @param array $placeholders Associative array of placeholders and their values (pre-sanitized)
     * @return string Template with placeholders replaced
     */
    private function replace_placeholders($template, $placeholders) {
        // Ensure template is a string
        if (!is_string($template)) {
            $template = '';
        }

        // Build search and replace arrays
        $search = array();
        $replace = array();

        foreach ($placeholders as $key => $value) {
            $search[] = '{' . $key . '}';
            // No escaping here - values must be pre-sanitized at source
            $replace[] = $value;
        }

        // Replace placeholders
        $output = str_replace($search, $replace, $template);

        return $output;
    }

    /**
     * Get user display name
     *
     * Returns the user's display name as configured in their WordPress profile.
     * Respects the user's display name preference from Settings > Profile.
     *
     * @param WP_User $user User object
     * @return string User display name
     */
    private function get_user_display_name($user) {
        // Always use display_name - this is the user's chosen preference in WordPress
        // WordPress automatically sets this to user_login if no other value is chosen
        if (!empty($user->display_name)) {
            return $user->display_name;
        }

        // Fallback only if display_name is somehow empty (shouldn't happen in normal WordPress)
        return $user->user_login;
    }

    /**
     * Get site name
     *
     * @return string Site name
     */
    private function get_site_name() {
        return wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
    }

    /**
     * Maybe set HTML content type
     *
     * This filter ensures emails are sent as HTML when using our templates
     *
     * @param string $content_type Current content type
     * @return string Content type
     */
    public function maybe_set_html_content_type($content_type) {
        // Only apply to password reset emails
        if (doing_filter('retrieve_password_message') || doing_filter('retrieve_password_title')) {
            return 'text/html';
        }

        return $content_type;
    }

    /**
     * Set email content type to HTML
     *
     * @return string
     */
    public function set_html_content_type() {
        return 'text/html';
    }

    /**
     * Send email using template
     *
     * Public method for sending custom emails with templates
     *
     * @param string $to Recipient email
     * @param string $subject Email subject
     * @param string $template Email template content
     * @param array $placeholders Placeholders to replace
     * @return bool Whether the email was sent successfully
     */
    public function send_email($to, $subject, $template, $placeholders = array()) {
        // Validate email address
        if (!is_email($to)) {
            return false;
        }

        // Add default placeholders
        $default_placeholders = array(
            'site_name' => $this->get_site_name(),
        );

        $placeholders = wp_parse_args($placeholders, $default_placeholders);

        // Replace placeholders in subject
        $subject = $this->replace_placeholders($subject, $placeholders);

        // Replace placeholders in template
        $message = $this->replace_placeholders($template, $placeholders);

        // Set content type to HTML
        add_filter('wp_mail_content_type', array($this, 'set_html_content_type'));

        // Set up email headers
        $headers = array(
            'Content-Type: text/html; charset=UTF-8',
        );

        // Send email
        $result = wp_mail($to, $subject, $message, $headers);

        // Remove filter
        remove_filter('wp_mail_content_type', array($this, 'set_html_content_type'));

        return $result;
    }

    /**
     * Send activation email to user
     *
     * @param int $user_id User ID
     * @param string $activation_key Activation key
     * @return bool Whether the email was sent successfully
     */
    public function send_activation_email($user_id, $activation_key) {
        $user = get_userdata($user_id);

        if (!$user) {
            return false;
        }

        // Build activation URL
        $activation_url = $this->build_reset_url($activation_key, $user->user_login, true);

        // Get templates
        $subject = $this->get_activation_subject();
        $template = $this->get_activation_template();

        // Prepare placeholders
        $placeholders = array(
            'user_name' => $this->get_user_display_name($user),
            'set_password_url' => $activation_url,
            'site_name' => $this->get_site_name(),
            'user_email' => $user->user_email,
            'user_login' => $user->user_login,
        );

        // Send email
        return $this->send_email($user->user_email, $subject, $template, $placeholders);
    }

    /**
     * Send password recovery email to user
     *
     * @param int $user_id User ID
     * @param string $reset_key Password reset key
     * @return bool Whether the email was sent successfully
     */
    public function send_recovery_email($user_id, $reset_key) {
        $user = get_userdata($user_id);

        if (!$user) {
            return false;
        }

        // Build reset URL
        $reset_url = $this->build_reset_url($reset_key, $user->user_login, false);

        // Get templates
        $subject = $this->get_recovery_subject();
        $template = $this->get_recovery_template();

        // Prepare placeholders
        $placeholders = array(
            'user_name' => $this->get_user_display_name($user),
            'set_password_url' => $reset_url,
            'site_name' => $this->get_site_name(),
            'user_email' => $user->user_email,
            'user_login' => $user->user_login,
        );

        // Send email
        return $this->send_email($user->user_email, $subject, $template, $placeholders);
    }

    /**
     * Send custom notification email
     *
     * Generic method for sending any custom email with proper escaping and security
     *
     * @param string $to Recipient email address
     * @param string $subject Subject line
     * @param string $message Message body (can contain placeholders)
     * @param array $placeholders Optional placeholders to replace
     * @param array $headers Optional additional headers
     * @return bool Whether the email was sent successfully
     */
    public function send_notification($to, $subject, $message, $placeholders = array(), $headers = array()) {
        // Validate recipient
        if (!is_email($to)) {
            return false;
        }

        // Sanitize subject
        $subject = sanitize_text_field($subject);

        // Add default placeholders
        $default_placeholders = array(
            'site_name' => $this->get_site_name(),
        );

        $placeholders = wp_parse_args($placeholders, $default_placeholders);

        // Replace placeholders
        $subject = $this->replace_placeholders($subject, $placeholders);
        $message = $this->replace_placeholders($message, $placeholders);

        // Set up headers
        $default_headers = array(
            'Content-Type: text/html; charset=UTF-8',
        );

        $headers = wp_parse_args($headers, $default_headers);

        // Set content type to HTML
        add_filter('wp_mail_content_type', array($this, 'set_html_content_type'));

        // Send email
        $result = wp_mail($to, $subject, $message, $headers);

        // Remove filter
        remove_filter('wp_mail_content_type', array($this, 'set_html_content_type'));

        return $result;
    }

    /**
     * Send admin notification email when new user registers
     *
     * @param int $user_id User ID
     * @return bool Whether the email was sent successfully
     */
    public function send_admin_registration_notification($user_id) {
        // Check if admin notifications are enabled
        $emails = isset($this->settings['emails']) ? $this->settings['emails'] : array();
        $notification_enabled = isset($emails['admin_notification_enabled']) && $emails['admin_notification_enabled'];

        if (!$notification_enabled) {
            return false;
        }

        // Get user data
        $user = get_userdata($user_id);

        if (!$user) {
            return false;
        }

        // Get admin email
        $admin_email = get_option('admin_email');

        if (!is_email($admin_email)) {
            return false;
        }

        // Get subject and template
        $subject = isset($emails['admin_notification_subject']) ? $emails['admin_notification_subject'] : 'New User Registration - {site_name}';
        $template = isset($emails['admin_notification_template']) ? $emails['admin_notification_template'] : '<p>A new user has registered on {site_name}:</p><p><strong>Username:</strong> {user_login}<br><strong>Email:</strong> {user_email}<br><strong>Display Name:</strong> {user_name}<br><strong>Registration Date:</strong> {registration_date}</p>';

        // Prepare placeholders (pre-sanitized for security)
        $placeholders = array(
            'user_name' => esc_html($this->get_user_display_name($user)),
            'site_name' => esc_html($this->get_site_name()),
            'user_email' => esc_html($user->user_email),
            'user_login' => esc_html($user->user_login),
            'registration_date' => esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($user->user_registered))),
        );

        // Send email
        return $this->send_email($admin_email, $subject, $template, $placeholders);
    }
}
