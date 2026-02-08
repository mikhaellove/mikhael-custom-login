<?php
/**
 * Admin Settings Class
 *
 * Handles all admin settings pages and form processing for Custom Secure Auth
 *
 * @package Custom_Secure_Auth
 * @since 2.0.0
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * CSA_Admin_Settings Class
 *
 * Creates and manages the admin settings interface with multiple tabs
 */
class CSA_Admin_Settings {

    /**
     * Settings page hook suffix
     *
     * @var string
     */
    private $hook_suffix;

    /**
     * Current active tab
     *
     * @var string
     */
    private $current_tab;

    /**
     * Available tabs configuration
     *
     * @var array
     */
    private $tabs;

    /**
     * Constructor
     *
     * Initializes the admin settings page and hooks
     */
    public function __construct() {
        $this->init_tabs();
        $this->init_hooks();
    }

    /**
     * Initialize tab configuration
     */
    private function init_tabs() {
        $this->tabs = array(
            'page_mapping' => array(
                'title' => __('Page Mapping & Logic', 'custom-secure-auth'),
                'icon' => 'dashicons-admin-page',
            ),
            'security' => array(
                'title' => __('Security (The 403 Vault)', 'custom-secure-auth'),
                'icon' => 'dashicons-shield',
            ),
            'grid_builder' => array(
                'title' => __('Registration Grid Builder', 'custom-secure-auth'),
                'icon' => 'dashicons-editor-table',
            ),
            'username_policy' => array(
                'title' => __('Username Policy', 'custom-secure-auth'),
                'icon' => 'dashicons-admin-users',
            ),
            'email_templates' => array(
                'title' => __('Email Templates', 'custom-secure-auth'),
                'icon' => 'dashicons-email',
            ),
            'shortcodes' => array(
                'title' => __('Shortcodes', 'custom-secure-auth'),
                'icon' => 'dashicons-shortcode',
            ),
        );
    }

    /**
     * Initialize WordPress hooks
     */
    private function init_hooks() {
        add_action('admin_menu', array($this, 'add_settings_page'));
        add_action('admin_init', array($this, 'process_form_submission'));
        add_action('admin_notices', array($this, 'display_admin_notices'));
    }

    /**
     * Add settings page to WordPress admin menu
     */
    public function add_settings_page() {
        $this->hook_suffix = add_menu_page(
            __('Custom Secure Auth', 'custom-secure-auth'),        // Page title
            __('Secure Auth', 'custom-secure-auth'),               // Menu title
            'manage_options',                                       // Capability
            'custom-secure-auth',                                   // Menu slug
            array($this, 'render_settings_page'),                  // Callback
            'dashicons-shield',                                     // Icon
            30                                                      // Position
        );
    }

    /**
     * Get current settings from database
     *
     * @return array Current settings with defaults
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
                'redirect_after_login' => 0,
                'disable_auto_login_after_reset' => false,
                'button_css_classes' => 'btn btn-primary',
            ),
            'security' => array(
                'honeypot_enabled' => true,
                'max_failed_attempts' => 5,
                'lockout_duration' => 1,
                'recaptcha_site_key' => '',
                'recaptcha_secret_key' => '',
                'disable_user_enumeration' => true,
                'rest_api_authentication_required' => false,
                'rest_api_whitelisted_namespaces' => array('custom-secure-auth'),
            ),
            'grid_builder' => array(
                'username_privacy_warning' => 'Privacy Tip: To keep your identity separate, we recommend using a username different from your real name or public social media handles.',
            ),
            'emails' => array(
                'activation_subject' => 'Activate Your Account - {site_name}',
                'activation_template' => '<p>Hello {user_name},</p><p>Please click the link below to activate your account:</p><p><a href="{set_password_url}">Activate Account</a></p>',
                'recovery_subject' => 'Reset Your Password - {site_name}',
                'recovery_template' => '<p>Hello {user_name},</p><p>Please click the link below to reset your password:</p><p><a href="{set_password_url}">Reset Password</a></p>',
            ),
            'username_policy' => array(
                'reserved_words' => array(
                    'admin', 'administrator', 'root', 'system', 'server', 'bot', 'cron',
                    'null', 'undefined', 'api', 'mod', 'moderator', 'staff', 'support',
                    'help', 'official', 'owner', 'founder', 'verify', 'verification',
                    'security', 'webmaster', 'sysadmin', 'superuser', 'editor'
                ),
                'reserved_words_boundary_match' => false,
                'restricted_strict_enabled' => true,
                'restricted_strict_words' => array(
                    'nigger', 'nigga', 'kike', 'chink', 'spic', 'wetback', 'gook', 'towelhead',
                    'faggot', 'dyke', 'tranny', 'fuck', 'shit', 'cunt', 'rape', 'rapist',
                    'pedophile', 'pedo', 'molest', 'incest', 'nazi', 'hitler', 'kkk',
                    'swastika', 'retard'
                ),
                'restricted_isolated_enabled' => true,
                'restricted_isolated_words' => array(
                    'ass', 'dick', 'cock', 'pussy', 'tit', 'tits', 'boob', 'boobs',
                    'sex', 'xxx', 'porn', 'hentai', 'whore', 'slut', 'bitch',
                    'bastard', 'damn', 'hell', 'piss', 'crap'
                ),
            ),
        );

        $settings = get_option(CSA_SETTINGS_SLUG, $defaults);

        // Ensure all keys exist
        return wp_parse_args($settings, $defaults);
    }

    /**
     * Process form submission and save settings
     */
    public function process_form_submission() {
        // Check if form was submitted
        if (!isset($_POST['csa_settings_nonce'])) {
            return;
        }

        // Verify nonce
        if (!wp_verify_nonce($_POST['csa_settings_nonce'], 'csa_save_settings')) {
            add_settings_error(
                'csa_messages',
                'csa_nonce_error',
                __('Security check failed. Please try again.', 'custom-secure-auth'),
                'error'
            );
            return;
        }

        // Check user capabilities
        if (!current_user_can('manage_options')) {
            add_settings_error(
                'csa_messages',
                'csa_permission_error',
                __('You do not have sufficient permissions to access this page.', 'custom-secure-auth'),
                'error'
            );
            return;
        }

        // Get current settings
        $settings = $this->get_settings();

        // Get the tab being saved
        $tab = isset($_POST['csa_tab']) ? sanitize_key($_POST['csa_tab']) : '';

        // Process based on tab
        switch ($tab) {
            case 'page_mapping':
                $settings = $this->save_page_mapping_settings($settings);
                break;

            case 'security':
                $settings = $this->save_security_settings($settings);
                break;

            case 'grid_builder':
                $settings = $this->save_grid_builder_settings($settings);
                break;

            case 'username_policy':
                $settings = $this->save_username_policy_settings($settings);
                break;

            case 'email_templates':
                $settings = $this->save_email_templates_settings($settings);
                break;
        }

        // Save to database
        update_option(CSA_SETTINGS_SLUG, $settings);

        // Add success message
        add_settings_error(
            'csa_messages',
            'csa_message',
            __('Settings saved successfully.', 'custom-secure-auth'),
            'success'
        );

        // Set transient to display notice
        set_transient('csa_settings_saved', true, 30);
    }

    /**
     * Save page mapping settings
     *
     * @param array $settings Current settings
     * @return array Updated settings
     */
    private function save_page_mapping_settings($settings) {
        // Page mapping
        $settings['page_mapping']['login_page'] = isset($_POST['login_page']) ? absint($_POST['login_page']) : 0;
        $settings['page_mapping']['register_page'] = isset($_POST['register_page']) ? absint($_POST['register_page']) : 0;
        $settings['page_mapping']['lost_password_page'] = isset($_POST['lost_password_page']) ? absint($_POST['lost_password_page']) : 0;
        $settings['page_mapping']['set_password_page'] = isset($_POST['set_password_page']) ? absint($_POST['set_password_page']) : 0;

        // Global config
        $settings['global_config']['token_expiry'] = isset($_POST['token_expiry']) ? absint($_POST['token_expiry']) : 30;
        $settings['global_config']['redirect_after_login'] = isset($_POST['redirect_after_login']) ? absint($_POST['redirect_after_login']) : 0;
        $settings['global_config']['disable_auto_login_after_reset'] = isset($_POST['disable_auto_login_after_reset']) ? true : false;
        $settings['global_config']['button_css_classes'] = isset($_POST['button_css_classes']) ? sanitize_text_field($_POST['button_css_classes']) : '';

        return $settings;
    }

    /**
     * Save security settings
     *
     * @param array $settings Current settings
     * @return array Updated settings
     */
    private function save_security_settings($settings) {
        $settings['security']['honeypot_enabled'] = isset($_POST['honeypot_enabled']) ? true : false;
        $settings['security']['max_failed_attempts'] = isset($_POST['max_failed_attempts']) ? absint($_POST['max_failed_attempts']) : 5;
        $settings['security']['lockout_duration'] = isset($_POST['lockout_duration']) ? absint($_POST['lockout_duration']) : 1;
        $settings['security']['recaptcha_site_key'] = isset($_POST['recaptcha_site_key']) ? sanitize_text_field($_POST['recaptcha_site_key']) : '';
        $settings['security']['recaptcha_secret_key'] = isset($_POST['recaptcha_secret_key']) ? sanitize_text_field($_POST['recaptcha_secret_key']) : '';

        // REST API Security
        $settings['security']['disable_user_enumeration'] = isset($_POST['disable_user_enumeration']) ? true : false;
        $settings['security']['rest_api_authentication_required'] = isset($_POST['rest_api_authentication_required']) ? true : false;

        // Whitelisted Namespaces (comma-delimited)
        if (isset($_POST['rest_api_whitelisted_namespaces'])) {
            $namespaces = sanitize_textarea_field($_POST['rest_api_whitelisted_namespaces']);
            $namespaces_array = array_filter(array_map('trim', explode(',', $namespaces)));
            // Remove duplicates and force lowercase
            $namespaces_array = array_unique(array_map('strtolower', $namespaces_array));
            $settings['security']['rest_api_whitelisted_namespaces'] = array_values($namespaces_array);
        }

        return $settings;
    }

    /**
     * Save grid builder settings
     *
     * @param array $settings Current settings
     * @return array Updated settings
     */
    private function save_grid_builder_settings($settings) {
        $grid_fields = array();

        if (isset($_POST['grid_fields']) && is_array($_POST['grid_fields'])) {
            foreach ($_POST['grid_fields'] as $field) {
                $grid_fields[] = array(
                    'id' => isset($field['id']) ? sanitize_key($field['id']) : '',
                    'label' => isset($field['label']) ? sanitize_text_field($field['label']) : '',
                    'placeholder' => isset($field['placeholder']) ? sanitize_text_field($field['placeholder']) : '',
                    'type' => isset($field['type']) ? sanitize_key($field['type']) : 'text',
                    'width' => isset($field['width']) ? sanitize_text_field($field['width']) : '100%',
                    'required' => isset($field['required']) ? true : false,
                );
            }
        }

        $settings['grid_builder'] = array(
            'fields' => $grid_fields,
            'fun_username_enabled' => isset($_POST['fun_username_enabled']) ? true : false,
            'username_privacy_warning' => isset($_POST['username_privacy_warning']) ? sanitize_text_field($_POST['username_privacy_warning']) : '',
        );

        return $settings;
    }

    /**
     * Save email templates settings
     *
     * @param array $settings Current settings
     * @return array Updated settings
     */
    private function save_email_templates_settings($settings) {
        $settings['emails']['activation_subject'] = isset($_POST['activation_subject']) ? sanitize_text_field($_POST['activation_subject']) : '';
        $settings['emails']['activation_template'] = isset($_POST['activation_template']) ? wp_kses_post($_POST['activation_template']) : '';
        $settings['emails']['recovery_subject'] = isset($_POST['recovery_subject']) ? sanitize_text_field($_POST['recovery_subject']) : '';
        $settings['emails']['recovery_template'] = isset($_POST['recovery_template']) ? wp_kses_post($_POST['recovery_template']) : '';

        return $settings;
    }

    /**
     * Save username policy settings
     *
     * @param array $settings Current settings
     * @return array Updated settings
     */
    private function save_username_policy_settings($settings) {
        // Initialize username_policy if not exists
        if (!isset($settings['username_policy'])) {
            $settings['username_policy'] = array();
        }

        // Save Reserved Words (always active)
        if (isset($_POST['reserved_words'])) {
            $reserved_words = sanitize_textarea_field($_POST['reserved_words']);
            $reserved_words_array = array_filter(array_map('trim', explode(',', $reserved_words)));
            // Force lowercase and remove duplicates
            $reserved_words_array = array_unique(array_map('strtolower', $reserved_words_array));
            $settings['username_policy']['reserved_words'] = array_values($reserved_words_array);
        }

        // Save Reserved Words boundary match toggle
        $settings['username_policy']['reserved_words_boundary_match'] = isset($_POST['reserved_words_boundary_match']) ? true : false;

        // Save Strict Block toggle and words
        $settings['username_policy']['restricted_strict_enabled'] = isset($_POST['restricted_strict_enabled']) ? true : false;

        if (isset($_POST['restricted_strict_words'])) {
            $strict_words = sanitize_textarea_field($_POST['restricted_strict_words']);
            $strict_words_array = array_filter(array_map('trim', explode(',', $strict_words)));
            // Force lowercase and remove duplicates
            $strict_words_array = array_unique(array_map('strtolower', $strict_words_array));
            $settings['username_policy']['restricted_strict_words'] = array_values($strict_words_array);
        }

        // Save Isolated Block toggle and words
        $settings['username_policy']['restricted_isolated_enabled'] = isset($_POST['restricted_isolated_enabled']) ? true : false;

        if (isset($_POST['restricted_isolated_words'])) {
            $isolated_words = sanitize_textarea_field($_POST['restricted_isolated_words']);
            $isolated_words_array = array_filter(array_map('trim', explode(',', $isolated_words)));
            // Force lowercase and remove duplicates
            $isolated_words_array = array_unique(array_map('strtolower', $isolated_words_array));
            $settings['username_policy']['restricted_isolated_words'] = array_values($isolated_words_array);
        }

        return $settings;
    }

    /**
     * Display admin notices
     */
    public function display_admin_notices() {
        // Only show on our settings page
        $screen = get_current_screen();
        if (!$screen || $screen->id !== $this->hook_suffix) {
            return;
        }

        // Check for success message
        if (get_transient('csa_settings_saved')) {
            ?>
            <div class="notice notice-success is-dismissible">
                <p><strong><?php esc_html_e('Settings saved successfully.', 'custom-secure-auth'); ?></strong></p>
            </div>
            <?php
            delete_transient('csa_settings_saved');
        }

        // Display any other admin notices
        settings_errors('csa_messages');
    }

    /**
     * Render the main settings page
     */
    public function render_settings_page() {
        // Get current tab
        $this->current_tab = isset($_GET['tab']) ? sanitize_key($_GET['tab']) : 'page_mapping';

        // Validate tab
        if (!isset($this->tabs[$this->current_tab])) {
            $this->current_tab = 'page_mapping';
        }

        // Get settings
        $settings = $this->get_settings();
        ?>
        <div class="wrap csa-settings-wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

            <?php $this->render_tabs(); ?>

            <form method="post" action="" class="csa-settings-form">
                <?php
                wp_nonce_field('csa_save_settings', 'csa_settings_nonce');
                ?>
                <input type="hidden" name="csa_tab" value="<?php echo esc_attr($this->current_tab); ?>">

                <div class="csa-tab-content">
                    <?php
                    // Render the appropriate tab content
                    $method = 'render_' . $this->current_tab . '_tab';
                    if (method_exists($this, $method)) {
                        $this->$method($settings);
                    }
                    ?>
                </div>

                <?php submit_button(__('Save Settings', 'custom-secure-auth'), 'primary large'); ?>
            </form>
        </div>
        <?php
    }

    /**
     * Render navigation tabs
     */
    private function render_tabs() {
        echo '<nav class="nav-tab-wrapper csa-nav-tab-wrapper">';

        foreach ($this->tabs as $tab_key => $tab_data) {
            $url = add_query_arg(array(
                'page' => 'custom-secure-auth',
                'tab' => $tab_key,
            ), admin_url('admin.php'));

            $active = ($this->current_tab === $tab_key) ? 'nav-tab-active' : '';

            printf(
                '<a href="%s" class="nav-tab csa-nav-tab %s"><span class="dashicons %s"></span>%s</a>',
                esc_url($url),
                esc_attr($active),
                esc_attr($tab_data['icon']),
                esc_html($tab_data['title'])
            );
        }

        echo '</nav>';
    }

    /**
     * Render Page Mapping & Logic tab
     *
     * @param array $settings Current settings
     */
    private function render_page_mapping_tab($settings) {
        ?>
        <table class="form-table csa-form-table">
            <tbody>
                <tr>
                    <th scope="row">
                        <label for="login_page"><?php esc_html_e('Login Page', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <?php
                        wp_dropdown_pages(array(
                            'name' => 'login_page',
                            'id' => 'login_page',
                            'selected' => $settings['page_mapping']['login_page'],
                            'show_option_none' => __('— Select —', 'custom-secure-auth'),
                            'option_none_value' => '0',
                        ));
                        ?>
                        <span class="description"><?php esc_html_e('Select the page that will display the login form.', 'custom-secure-auth'); ?></span>
                    </td>
                </tr>

                <tr>
                    <th scope="row">
                        <label for="register_page"><?php esc_html_e('Registration Page', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <?php
                        wp_dropdown_pages(array(
                            'name' => 'register_page',
                            'id' => 'register_page',
                            'selected' => $settings['page_mapping']['register_page'],
                            'show_option_none' => __('— Select —', 'custom-secure-auth'),
                            'option_none_value' => '0',
                        ));
                        ?>
                        <span class="description"><?php esc_html_e('Select the page that will display the registration form.', 'custom-secure-auth'); ?></span>
                    </td>
                </tr>

                <tr>
                    <th scope="row">
                        <label for="lost_password_page"><?php esc_html_e('Lost Password Page', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <?php
                        wp_dropdown_pages(array(
                            'name' => 'lost_password_page',
                            'id' => 'lost_password_page',
                            'selected' => $settings['page_mapping']['lost_password_page'],
                            'show_option_none' => __('— Select —', 'custom-secure-auth'),
                            'option_none_value' => '0',
                        ));
                        ?>
                        <span class="description"><?php esc_html_e('Select the page that will display the password recovery form.', 'custom-secure-auth'); ?></span>
                    </td>
                </tr>

                <tr>
                    <th scope="row">
                        <label for="set_password_page"><?php esc_html_e('Set Password Page', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <?php
                        wp_dropdown_pages(array(
                            'name' => 'set_password_page',
                            'id' => 'set_password_page',
                            'selected' => $settings['page_mapping']['set_password_page'],
                            'show_option_none' => __('— Select —', 'custom-secure-auth'),
                            'option_none_value' => '0',
                        ));
                        ?>
                        <span class="description"><?php esc_html_e('Select the page that will display the set/reset password form.', 'custom-secure-auth'); ?></span>
                    </td>
                </tr>
            </tbody>
        </table>

        <h2><?php esc_html_e('Global Configuration', 'custom-secure-auth'); ?></h2>

        <table class="form-table csa-form-table">
            <tbody>
                <tr>
                    <th scope="row">
                        <label for="token_expiry"><?php esc_html_e('Token Expiry (minutes)', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <input
                            type="number"
                            name="token_expiry"
                            id="token_expiry"
                            value="<?php echo esc_attr($settings['global_config']['token_expiry']); ?>"
                            min="1"
                            max="1440"
                            step="1"
                        >
                        <span class="description"><?php esc_html_e('How long activation and password reset tokens remain valid (in minutes).', 'custom-secure-auth'); ?></span>
                    </td>
                </tr>

                <tr>
                    <th scope="row">
                        <label for="redirect_after_login"><?php esc_html_e('Redirect After Login', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <?php
                        wp_dropdown_pages(array(
                            'name' => 'redirect_after_login',
                            'id' => 'redirect_after_login',
                            'selected' => $settings['global_config']['redirect_after_login'],
                            'show_option_none' => __('— Home Page —', 'custom-secure-auth'),
                            'option_none_value' => '0',
                        ));
                        ?>
                        <span class="description"><?php esc_html_e('Select the page to redirect users after successful login. Leave as "Home Page" to use the site homepage.', 'custom-secure-auth'); ?></span>
                    </td>
                </tr>

                <tr>
                    <th scope="row">
                        <label for="disable_auto_login_after_reset"><?php esc_html_e('Auto-Login After Password Reset', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <label>
                            <input
                                type="checkbox"
                                name="disable_auto_login_after_reset"
                                id="disable_auto_login_after_reset"
                                value="1"
                                <?php checked($settings['global_config']['disable_auto_login_after_reset'], true); ?>
                            >
                            <?php esc_html_e('Disable auto-login after password reset', 'custom-secure-auth'); ?>
                        </label>
                        <span class="description"><?php esc_html_e('When enabled, users who reset their password or activate their account will be redirected to the login page instead of being automatically logged in.', 'custom-secure-auth'); ?></span>
                    </td>
                </tr>

                <tr>
                    <th scope="row">
                        <label for="button_css_classes"><?php esc_html_e('Button CSS Classes', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <input
                            type="text"
                            name="button_css_classes"
                            id="button_css_classes"
                            value="<?php echo esc_attr($settings['global_config']['button_css_classes']); ?>"
                            placeholder="btn btn-primary"
                        >
                        <span class="description"><?php esc_html_e('CSS classes to apply to form submit buttons (space-separated).', 'custom-secure-auth'); ?></span>
                    </td>
                </tr>
            </tbody>
        </table>
        <?php
    }

    /**
     * Render Security (The 403 Vault) tab
     *
     * @param array $settings Current settings
     */
    private function render_security_tab($settings) {
        ?>
        <table class="form-table csa-form-table">
            <tbody>
                <tr>
                    <th scope="row">
                        <label for="honeypot_enabled"><?php esc_html_e('Enable Honeypot', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <label>
                            <input
                                type="checkbox"
                                name="honeypot_enabled"
                                id="honeypot_enabled"
                                value="1"
                                <?php checked($settings['security']['honeypot_enabled'], true); ?>
                            >
                            <?php esc_html_e('Add hidden honeypot field to prevent bot submissions', 'custom-secure-auth'); ?>
                        </label>
                        <span class="description"><?php esc_html_e('Honeypot fields are invisible to humans but bots typically fill them out, allowing us to detect and block automated spam.', 'custom-secure-auth'); ?></span>
                    </td>
                </tr>

                <tr>
                    <th scope="row">
                        <label for="max_failed_attempts"><?php esc_html_e('Max Failed Attempts', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <input
                            type="number"
                            name="max_failed_attempts"
                            id="max_failed_attempts"
                            value="<?php echo esc_attr($settings['security']['max_failed_attempts']); ?>"
                            min="1"
                            max="20"
                            step="1"
                        >
                        <span class="description"><?php esc_html_e('Number of failed login attempts before locking out a user.', 'custom-secure-auth'); ?></span>
                    </td>
                </tr>

                <tr>
                    <th scope="row">
                        <label for="lockout_duration"><?php esc_html_e('Lockout Duration (hours)', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <input
                            type="number"
                            name="lockout_duration"
                            id="lockout_duration"
                            value="<?php echo esc_attr($settings['security']['lockout_duration']); ?>"
                            min="1"
                            max="72"
                            step="1"
                        >
                        <span class="description"><?php esc_html_e('How long users are locked out after exceeding max failed attempts (in hours).', 'custom-secure-auth'); ?></span>
                    </td>
                </tr>

                <tr>
                    <th scope="row">
                        <label for="recaptcha_site_key"><?php esc_html_e('reCAPTCHA Site Key', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <input
                            type="text"
                            name="recaptcha_site_key"
                            id="recaptcha_site_key"
                            value="<?php echo esc_attr($settings['security']['recaptcha_site_key']); ?>"
                            placeholder="6Lc..."
                        >
                        <span class="description">
                            <?php
                            printf(
                                /* translators: %s: URL to Google reCAPTCHA admin */
                                esc_html__('Get your reCAPTCHA keys from %s', 'custom-secure-auth'),
                                '<a href="https://www.google.com/recaptcha/admin" target="_blank">Google reCAPTCHA</a>'
                            );
                            ?>
                        </span>
                    </td>
                </tr>

                <tr>
                    <th scope="row">
                        <label for="recaptcha_secret_key"><?php esc_html_e('reCAPTCHA Secret Key', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <input
                            type="password"
                            name="recaptcha_secret_key"
                            id="recaptcha_secret_key"
                            value="<?php echo esc_attr($settings['security']['recaptcha_secret_key']); ?>"
                            placeholder="6Lc..."
                            autocomplete="off"
                        >
                        <span class="description"><?php esc_html_e('Keep this secret key secure. It is used to verify reCAPTCHA responses on the server.', 'custom-secure-auth'); ?></span>
                    </td>
                </tr>
            </tbody>
        </table>

        <!-- REST API Security Section -->
        <h2><?php esc_html_e('REST API Security', 'custom-secure-auth'); ?></h2>
        <p><?php esc_html_e('Control public access to WordPress REST API endpoints. These settings help prevent user enumeration and unauthorized API access.', 'custom-secure-auth'); ?></p>

        <table class="form-table csa-form-table">
            <tbody>
                <tr>
                    <th scope="row">
                        <label for="disable_user_enumeration"><?php esc_html_e('Disable User Enumeration', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <label>
                            <input
                                type="checkbox"
                                name="disable_user_enumeration"
                                id="disable_user_enumeration"
                                value="1"
                                <?php checked($settings['security']['disable_user_enumeration'], true); ?>
                            >
                            <?php esc_html_e('Block /wp/v2/users endpoints', 'custom-secure-auth'); ?>
                        </label>
                        <span class="description"><?php esc_html_e('Prevents attackers from discovering admin usernames via REST API. Recommended: Always enabled.', 'custom-secure-auth'); ?></span>
                    </td>
                </tr>

                <tr>
                    <th scope="row">
                        <label for="rest_api_authentication_required"><?php esc_html_e('Require Authentication', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <label>
                            <input
                                type="checkbox"
                                name="rest_api_authentication_required"
                                id="rest_api_authentication_required"
                                value="1"
                                <?php checked($settings['security']['rest_api_authentication_required'], true); ?>
                            >
                            <?php esc_html_e('Require login for REST API access', 'custom-secure-auth'); ?>
                        </label>
                        <span class="description">
                            <strong style="color: #d63638;"><?php esc_html_e('⚠️ Warning:', 'custom-secure-auth'); ?></strong>
                            <?php esc_html_e('May break plugins/themes that use REST API for public features. Test thoroughly before enabling on production.', 'custom-secure-auth'); ?>
                        </span>
                    </td>
                </tr>

                <tr>
                    <th scope="row">
                        <label for="rest_api_whitelisted_namespaces"><?php esc_html_e('Whitelisted Namespaces', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <?php
                        $namespaces = isset($settings['security']['rest_api_whitelisted_namespaces'])
                            ? $settings['security']['rest_api_whitelisted_namespaces']
                            : array();
                        ?>
                        <div class="csa-tag-input-wrapper" data-field-name="rest_api_whitelisted_namespaces">
                            <div class="csa-tag-display"></div>
                            <div class="csa-tag-input-row">
                                <input type="text" class="csa-tag-input" placeholder="Type namespace and press Enter or click Add" aria-label="Add REST API namespace">
                                <button type="button" class="button csa-tag-add-btn"><?php esc_html_e('Add', 'custom-secure-auth'); ?></button>
                            </div>
                            <input type="hidden" name="rest_api_whitelisted_namespaces" id="rest_api_whitelisted_namespaces" value="<?php echo esc_attr(is_array($namespaces) ? implode(', ', $namespaces) : ''); ?>">
                        </div>
                        <span class="description">
                            <?php esc_html_e('Add REST API namespaces one at a time that should remain publicly accessible. Example: custom-secure-auth, contact-form-7, wpgform, fluentform', 'custom-secure-auth'); ?>
                            <br>
                            <strong><?php esc_html_e('Important:', 'custom-secure-auth'); ?></strong>
                            <?php esc_html_e('"custom-secure-auth" is included by default to ensure this plugin\'s registration and login features continue working. You can remove it if you want to disable public registration.', 'custom-secure-auth'); ?>
                            <br>
                            <strong><?php esc_html_e('Note:', 'custom-secure-auth'); ?></strong>
                            <?php esc_html_e('This setting only applies when "Require Authentication" is enabled.', 'custom-secure-auth'); ?>
                        </span>

                        <?php
                        // Display last 20 blocked namespaces for debugging
                        $blocked_log = get_option('csa_blocked_namespaces_log', array());
                        if (!empty($blocked_log)):
                        ?>
                            <div class="csa-blocked-log" style="margin-top: 20px; padding: 15px; background: #f9f9f9; border: 1px solid #ddd; border-radius: 4px;">
                                <strong style="display: block; margin-bottom: 10px;">
                                    <span class="dashicons dashicons-warning" style="color: #d63638;"></span>
                                    <?php esc_html_e('Recent Blocked Attempts (Last 20):', 'custom-secure-auth'); ?>
                                </strong>
                                <div style="max-height: 200px; overflow-y: auto; font-family: monospace; font-size: 12px;">
                                    <table style="width: 100%; border-collapse: collapse;">
                                        <thead>
                                            <tr style="background: #fff; border-bottom: 2px solid #ddd;">
                                                <th style="padding: 5px; text-align: left;"><?php esc_html_e('Time', 'custom-secure-auth'); ?></th>
                                                <th style="padding: 5px; text-align: left;"><?php esc_html_e('Blocked Route', 'custom-secure-auth'); ?></th>
                                                <th style="padding: 5px; text-align: left;"><?php esc_html_e('IP Address', 'custom-secure-auth'); ?></th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php
                                            // Reverse to show newest first
                                            foreach (array_reverse($blocked_log) as $entry):
                                            ?>
                                                <tr style="border-bottom: 1px solid #eee;">
                                                    <td style="padding: 5px;"><?php echo esc_html($entry['timestamp']); ?></td>
                                                    <td style="padding: 5px; color: #d63638;"><strong><?php echo esc_html($entry['route']); ?></strong></td>
                                                    <td style="padding: 5px;"><?php echo esc_html($entry['ip']); ?></td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                                <p style="margin: 10px 0 0 0; font-size: 11px; color: #666;">
                                    <?php esc_html_e('These are REST API routes that were blocked because "Require Authentication" is enabled and they are not in the whitelist. If you see routes that should be allowed, add their namespace to the whitelist above.', 'custom-secure-auth'); ?>
                                </p>
                            </div>
                        <?php endif; ?>
                    </td>
                </tr>
            </tbody>
        </table>

        <style>
            /* Tag-Style Input Interface */
            .csa-tag-input-wrapper {
                max-width: 800px;
            }
            .csa-tag-display {
                min-height: 50px;
                padding: 10px;
                background: #fff;
                border: 1px solid #8c8f94;
                border-radius: 4px;
                margin-bottom: 10px;
                display: flex;
                flex-wrap: wrap;
                gap: 6px;
                align-items: flex-start;
            }
            .csa-tag-display:empty::before {
                content: 'No items added yet. Type below and press Enter or click Add.';
                color: #999;
                font-style: italic;
                font-size: 13px;
            }
            .csa-tag {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                padding: 5px 10px;
                background: #2271b1;
                color: #fff;
                border-radius: 3px;
                font-size: 13px;
                line-height: 1.4;
                transition: background 0.15s ease;
            }
            .csa-tag:hover {
                background: #135e96;
            }
            .csa-tag-remove {
                background: none;
                border: none;
                color: #fff;
                cursor: pointer;
                padding: 0;
                margin: 0;
                font-size: 16px;
                line-height: 1;
                opacity: 0.8;
                transition: opacity 0.15s ease;
            }
            .csa-tag-remove:hover {
                opacity: 1;
            }
            .csa-tag-input-row {
                display: flex;
                gap: 8px;
                align-items: center;
            }
            .csa-tag-input {
                flex: 1;
                padding: 6px 10px;
                border: 1px solid #8c8f94;
                border-radius: 4px;
                font-size: 14px;
            }
            .csa-tag-input:focus {
                border-color: #2271b1;
                outline: none;
                box-shadow: 0 0 0 1px #2271b1;
            }
            .csa-tag-add-btn {
                white-space: nowrap;
            }
        </style>

        <script>
        (function() {
            // Only initialize if CSATagManager hasn't been defined yet
            if (typeof window.CSATagManager !== 'undefined') {
                return;
            }

            /**
             * CSA Tag Manager - WordPress-style tag interface
             */
            window.CSATagManager = class CSATagManager {
                constructor(wrapperElement) {
                    this.wrapper = wrapperElement;
                    this.display = this.wrapper.querySelector('.csa-tag-display');
                    this.input = this.wrapper.querySelector('.csa-tag-input');
                    this.addButton = this.wrapper.querySelector('.csa-tag-add-btn');
                    this.hiddenInput = this.wrapper.querySelector('input[type="hidden"]');
                    this.tags = new Set();

                    this.init();
                }

                init() {
                    this.loadExistingTags();
                    this.addButton.addEventListener('click', () => this.handleAdd());
                    this.input.addEventListener('keypress', (e) => this.handleKeyPress(e));
                    this.display.addEventListener('click', (e) => this.handleRemove(e));
                }

                loadExistingTags() {
                    const value = this.hiddenInput.value.trim();
                    if (value) {
                        const items = value.split(',').map(item => item.trim()).filter(item => item);
                        items.forEach(item => this.tags.add(item.toLowerCase()));
                    }
                    this.render();
                }

                handleAdd() {
                    const value = this.input.value.trim();
                    if (value) {
                        this.addTag(value);
                        this.input.value = '';
                        this.input.focus();
                    }
                }

                handleKeyPress(e) {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        this.handleAdd();
                    }
                }

                handleRemove(e) {
                    if (e.target.classList.contains('csa-tag-remove')) {
                        const tag = e.target.closest('.csa-tag').dataset.value;
                        this.removeTag(tag);
                    }
                }

                addTag(value) {
                    const normalized = value.toLowerCase().trim();
                    if (!normalized) return false;

                    if (this.tags.has(normalized)) {
                        const existingTag = this.display.querySelector(`[data-value="${normalized}"]`);
                        if (existingTag) {
                            existingTag.style.animation = 'none';
                            setTimeout(() => {
                                existingTag.style.animation = 'csaFlash 0.5s ease';
                            }, 10);
                        }
                        return false;
                    }

                    this.tags.add(normalized);
                    this.render();
                    this.updateHiddenInput();
                    return true;
                }

                removeTag(value) {
                    this.tags.delete(value);
                    this.render();
                    this.updateHiddenInput();
                }

                render() {
                    this.display.innerHTML = '';
                    const sortedTags = Array.from(this.tags).sort();

                    sortedTags.forEach(tag => {
                        const tagElement = document.createElement('span');
                        tagElement.className = 'csa-tag';
                        tagElement.dataset.value = tag;

                        const text = document.createElement('span');
                        text.textContent = tag;

                        const removeBtn = document.createElement('button');
                        removeBtn.type = 'button';
                        removeBtn.className = 'csa-tag-remove';
                        removeBtn.innerHTML = '&times;';
                        removeBtn.setAttribute('aria-label', 'Remove ' + tag);

                        tagElement.appendChild(text);
                        tagElement.appendChild(removeBtn);
                        this.display.appendChild(tagElement);
                    });
                }

                updateHiddenInput() {
                    const sortedTags = Array.from(this.tags).sort();
                    this.hiddenInput.value = sortedTags.join(', ');
                }
            };

            // Initialize tag managers
            document.addEventListener('DOMContentLoaded', function() {
                const wrappers = document.querySelectorAll('.csa-tag-input-wrapper');
                wrappers.forEach(wrapper => {
                    new window.CSATagManager(wrapper);
                });
            });

            // Add flash animation
            if (!document.getElementById('csa-flash-animation')) {
                const style = document.createElement('style');
                style.id = 'csa-flash-animation';
                style.textContent = `
                    @keyframes csaFlash {
                        0%, 100% { transform: scale(1); }
                        50% { transform: scale(1.1); background: #135e96; }
                    }
                `;
                document.head.appendChild(style);
            }
        })();
        </script>

        <?php
    }

    /**
     * Render Registration Grid Builder tab
     *
     * @param array $settings Current settings
     */
    private function render_grid_builder_tab($settings) {
        $grid_fields = $settings['grid_builder']['fields'] ?? array();
        $has_fields = !empty($grid_fields);
        ?>
        <div class="csa-grid-builder">

            <!-- Help Section -->
            <div class="csa-info-box">
                <h3><span class="dashicons dashicons-info"></span> <?php esc_html_e('How Registration Forms Work', 'custom-secure-auth'); ?></h3>
                <ul>
                    <li><strong><?php esc_html_e('Username and Email are required by WordPress', 'custom-secure-auth'); ?></strong> - <?php esc_html_e('Every user must have these.', 'custom-secure-auth'); ?></li>
                    <li><strong><?php esc_html_e('Password field is optional', 'custom-secure-auth'); ?></strong> - <?php esc_html_e('If you don\'t include it, users receive an activation email to set their password.', 'custom-secure-auth'); ?></li>
                    <li><strong><?php esc_html_e('Drag fields to reorder', 'custom-secure-auth'); ?></strong> - <?php esc_html_e('Use the drag handle (≡) to arrange fields in any order.', 'custom-secure-auth'); ?></li>
                    <li><strong><?php esc_html_e('Custom fields save as user metadata', 'custom-secure-auth'); ?></strong> - <?php esc_html_e('Great for collecting phone numbers, company names, etc.', 'custom-secure-auth'); ?></li>
                </ul>
            </div>

            <!-- Fun Username Generator Toggle -->
            <div class="csa-feature-toggle" style="background: #fff; border: 1px solid #ddd; padding: 20px; margin-bottom: 20px; border-radius: 4px;">
                <label style="display: flex; align-items: center; gap: 10px; font-weight: 600;">
                    <input type="checkbox" name="fun_username_enabled" value="1" <?php checked($settings['grid_builder']['fun_username_enabled'] ?? false, true); ?>>
                    <span><?php esc_html_e('Enable Fun Username Generator', 'custom-secure-auth'); ?></span>
                </label>
                <p class="description" style="margin: 10px 0 0 34px;">
                    <?php esc_html_e('Auto-generates a fun username (like "Sassy_Clanker42") in the username field on page load. A refresh icon appears next to the label, allowing users to generate new options until they find one they like, or they can type their own.', 'custom-secure-auth'); ?>
                </p>
            </div>

            <!-- Username Privacy Warning -->
            <div class="csa-feature-toggle" style="background: #fff; border: 1px solid #ddd; padding: 20px; margin-bottom: 20px; border-radius: 4px;">
                <label for="username_privacy_warning" style="display: block; font-weight: 600; margin-bottom: 10px;">
                    <?php esc_html_e('Username Privacy Warning', 'custom-secure-auth'); ?>
                </label>
                <input
                    type="text"
                    name="username_privacy_warning"
                    id="username_privacy_warning"
                    class="regular-text"
                    style="width: 100%; max-width: 600px;"
                    value="<?php echo esc_attr($settings['grid_builder']['username_privacy_warning'] ?? ''); ?>"
                    placeholder="<?php esc_attr_e('Enter a privacy tip for users...', 'custom-secure-auth'); ?>"
                >
                <p class="description" style="margin: 10px 0 0 0;">
                    <?php esc_html_e('This warning appears below the username field on the registration form. Leave blank to disable the warning.', 'custom-secure-auth'); ?>
                </p>
            </div>

            <!-- Quick Start Presets -->
            <div class="csa-quick-start">
                <h3><span class="dashicons dashicons-star-filled"></span> <?php esc_html_e('Quick Start: Add Common Fields', 'custom-secure-auth'); ?></h3>
                <p class="description"><?php esc_html_e('Click a button to instantly add that field to your form with recommended settings.', 'custom-secure-auth'); ?></p>

                <div class="csa-preset-buttons">
                    <button type="button" class="csa-preset-btn" data-preset="username">
                        <span class="dashicons dashicons-admin-users"></span>
                        <span><?php esc_html_e('Username', 'custom-secure-auth'); ?></span>
                    </button>

                    <button type="button" class="csa-preset-btn" data-preset="email">
                        <span class="dashicons dashicons-email"></span>
                        <span><?php esc_html_e('Email Address', 'custom-secure-auth'); ?></span>
                    </button>

                    <button type="button" class="csa-preset-btn" data-preset="password">
                        <span class="dashicons dashicons-lock"></span>
                        <span><?php esc_html_e('Password', 'custom-secure-auth'); ?></span>
                    </button>

                    <button type="button" class="csa-preset-btn" data-preset="first_name">
                        <span class="dashicons dashicons-id"></span>
                        <span><?php esc_html_e('First Name', 'custom-secure-auth'); ?></span>
                    </button>

                    <button type="button" class="csa-preset-btn" data-preset="last_name">
                        <span class="dashicons dashicons-id-alt"></span>
                        <span><?php esc_html_e('Last Name', 'custom-secure-auth'); ?></span>
                    </button>

                    <button type="button" class="csa-preset-btn" data-preset="phone">
                        <span class="dashicons dashicons-phone"></span>
                        <span><?php esc_html_e('Phone Number', 'custom-secure-auth'); ?></span>
                    </button>
                </div>
            </div>

            <!-- Current Form Fields -->
            <h3><?php esc_html_e('Your Registration Form Fields', 'custom-secure-auth'); ?></h3>

            <?php if (!$has_fields) : ?>
                <div class="csa-empty-state">
                    <span class="dashicons dashicons-format-aside"></span>
                    <h4><?php esc_html_e('No fields yet!', 'custom-secure-auth'); ?></h4>
                    <p><?php esc_html_e('Use the Quick Start buttons above to add common fields, or click "Add Custom Field" below to create your own.', 'custom-secure-auth'); ?></p>
                </div>
            <?php endif; ?>

            <div id="csa-grid-fields-container">
                <?php
                if ($has_fields) {
                    foreach ($grid_fields as $index => $field) {
                        $this->render_grid_field_row($index, $field);
                    }
                }
                ?>
            </div>

            <button type="button" class="button csa-add-field" id="csa-add-field">
                <span class="dashicons dashicons-plus-alt"></span>
                <?php esc_html_e('Add Custom Field', 'custom-secure-auth'); ?>
            </button>
        </div>

        <script type="text/template" id="csa-grid-field-template">
            <?php $this->render_grid_field_row('{{INDEX}}', array()); ?>
        </script>

        <script>
        jQuery(document).ready(function($) {
            var fieldIndex = <?php echo !empty($grid_fields) ? count($grid_fields) : 0; ?>;

            // Preset field configurations
            var presets = {
                username: {
                    id: 'user_login',
                    label: '<?php echo esc_js(__('Username', 'custom-secure-auth')); ?>',
                    placeholder: '<?php echo esc_js(__('Enter your username', 'custom-secure-auth')); ?>',
                    type: 'text',
                    width: '50%',
                    required: true
                },
                email: {
                    id: 'user_email',
                    label: '<?php echo esc_js(__('Email Address', 'custom-secure-auth')); ?>',
                    placeholder: '<?php echo esc_js(__('your.email@example.com', 'custom-secure-auth')); ?>',
                    type: 'email',
                    width: '50%',
                    required: true
                },
                password: {
                    id: 'user_pass',
                    label: '<?php echo esc_js(__('Password', 'custom-secure-auth')); ?>',
                    placeholder: '<?php echo esc_js(__('Create a strong password', 'custom-secure-auth')); ?>',
                    type: 'password',
                    width: '50%',
                    required: true
                },
                first_name: {
                    id: 'first_name',
                    label: '<?php echo esc_js(__('First Name', 'custom-secure-auth')); ?>',
                    placeholder: '<?php echo esc_js(__('Your first name', 'custom-secure-auth')); ?>',
                    type: 'wp_first_name',
                    width: '50%',
                    required: false
                },
                last_name: {
                    id: 'last_name',
                    label: '<?php echo esc_js(__('Last Name', 'custom-secure-auth')); ?>',
                    placeholder: '<?php echo esc_js(__('Your last name', 'custom-secure-auth')); ?>',
                    type: 'wp_last_name',
                    width: '50%',
                    required: false
                },
                phone: {
                    id: 'phone_number',
                    label: '<?php echo esc_js(__('Phone Number', 'custom-secure-auth')); ?>',
                    placeholder: '<?php echo esc_js(__('(555) 123-4567', 'custom-secure-auth')); ?>',
                    type: 'usermeta',
                    width: '50%',
                    required: false
                }
            };

            // Hide empty state when fields exist
            function updateEmptyState() {
                var fieldCount = $('#csa-grid-fields-container .csa-grid-field').length;
                if (fieldCount > 0) {
                    $('.csa-empty-state').hide();
                } else {
                    $('.csa-empty-state').show();
                }
            }

            // Make fields sortable
            $('#csa-grid-fields-container').sortable({
                handle: '.csa-grid-field-handle',
                placeholder: 'csa-grid-field-placeholder',
                cursor: 'move',
                opacity: 0.8
            });

            // Add preset field
            $('.csa-preset-btn').on('click', function() {
                var presetName = $(this).data('preset');
                var preset = presets[presetName];

                if (!preset) return;

                var template = $('#csa-grid-field-template').html();
                var newField = template.replace(/{{INDEX}}/g, fieldIndex);
                $('#csa-grid-fields-container').append(newField);

                // Find the newly added field and populate it
                var $newField = $('#csa-grid-fields-container .csa-grid-field').last();
                $newField.find('.csa-grid-field-id').val(preset.id);
                $newField.find('.csa-grid-field-label').val(preset.label);
                $newField.find('.csa-grid-field-placeholder').val(preset.placeholder);
                $newField.find('.csa-grid-field-type').val(preset.type);
                $newField.find('.csa-grid-field-width').val(preset.width);

                if (preset.required) {
                    $newField.find('.csa-grid-field-required').prop('checked', true);
                }

                fieldIndex++;
                updateEmptyState();

                // Scroll to the new field
                $('html, body').animate({
                    scrollTop: $newField.offset().top - 100
                }, 500);
            });

            // Add custom field
            $('#csa-add-field').on('click', function() {
                var template = $('#csa-grid-field-template').html();
                var newField = template.replace(/{{INDEX}}/g, fieldIndex);
                $('#csa-grid-fields-container').append(newField);
                fieldIndex++;
                updateEmptyState();
            });

            // Remove field
            $(document).on('click', '.csa-remove-field', function(e) {
                e.preventDefault();
                if (confirm('<?php esc_html_e('Are you sure you want to remove this field?', 'custom-secure-auth'); ?>')) {
                    $(this).closest('.csa-grid-field').remove();
                    updateEmptyState();
                }
            });

            // Auto-generate ID from label
            $(document).on('blur', '.csa-grid-field-label', function() {
                var $field = $(this).closest('.csa-grid-field');
                var $idInput = $field.find('.csa-grid-field-id');

                // Only auto-generate if ID is empty
                if ($idInput.val() === '') {
                    var label = $(this).val();
                    var id = label.toLowerCase()
                        .replace(/[^a-z0-9]+/g, '_')
                        .replace(/^_+|_+$/g, '');
                    $idInput.val(id);
                }
            });

            // Update help text when field type changes
            var helpTexts = {
                'text': '<?php echo esc_js(__('Regular text input (for username, etc.)', 'custom-secure-auth')); ?>',
                'email': '<?php echo esc_js(__('Validates email format automatically', 'custom-secure-auth')); ?>',
                'password': '<?php echo esc_js(__('Masked input for secure passwords', 'custom-secure-auth')); ?>',
                'checkbox': '<?php echo esc_js(__('Yes/No or agreement checkbox', 'custom-secure-auth')); ?>',
                'wp_first_name': '<?php echo esc_js(__('Saves to WordPress user profile', 'custom-secure-auth')); ?>',
                'wp_last_name': '<?php echo esc_js(__('Saves to WordPress user profile', 'custom-secure-auth')); ?>',
                'usermeta': '<?php echo esc_js(__('Custom data (phone, company, etc.)', 'custom-secure-auth')); ?>'
            };

            $(document).on('change', '.csa-grid-field-type', function() {
                var $field = $(this).closest('.csa-grid-field');
                var selectedType = $(this).val();
                var $helpText = $field.find('.csa-field-type-help');

                if (helpTexts[selectedType]) {
                    $helpText.text(helpTexts[selectedType]);
                }
            });

            // Initialize empty state
            updateEmptyState();
        });
        </script>
        <?php
    }

    /**
     * Render a single grid field row
     *
     * @param int|string $index Field index
     * @param array $field Field data
     */
    private function render_grid_field_row($index, $field = array()) {
        $defaults = array(
            'id' => '',
            'label' => '',
            'placeholder' => '',
            'type' => 'text',
            'width' => '100%',
            'required' => false,
        );

        $field = wp_parse_args($field, $defaults);
        ?>
        <div class="csa-grid-field">
            <span class="csa-grid-field-handle dashicons dashicons-menu" title="<?php esc_attr_e('Drag to reorder', 'custom-secure-auth'); ?>"></span>
            <a href="#" class="csa-remove-field dashicons dashicons-trash" title="<?php esc_attr_e('Remove this field', 'custom-secure-auth'); ?>"></a>

            <div class="csa-grid-field-row">
                <label>
                    <?php esc_html_e('Field ID (slug):', 'custom-secure-auth'); ?>
                    <span class="csa-field-tooltip" title="<?php esc_attr_e('Unique identifier for this field. Use lowercase letters, numbers, and underscores only. Auto-generated from label if left empty.', 'custom-secure-auth'); ?>">
                        <span class="dashicons dashicons-editor-help"></span>
                    </span>
                </label>
                <input
                    type="text"
                    name="grid_fields[<?php echo esc_attr($index); ?>][id]"
                    class="csa-grid-field-id"
                    value="<?php echo esc_attr($field['id']); ?>"
                    placeholder="field_id"
                    pattern="[a-z0-9_]+"
                    title="<?php esc_attr_e('Lowercase letters, numbers, and underscores only', 'custom-secure-auth'); ?>"
                >
                <span class="csa-field-help"><?php esc_html_e('Auto-generated from label if left empty', 'custom-secure-auth'); ?></span>
            </div>

            <div class="csa-grid-field-row">
                <label>
                    <?php esc_html_e('Label:', 'custom-secure-auth'); ?>
                    <span class="csa-field-tooltip" title="<?php esc_attr_e('The text shown above the field on the registration form', 'custom-secure-auth'); ?>">
                        <span class="dashicons dashicons-editor-help"></span>
                    </span>
                </label>
                <input
                    type="text"
                    name="grid_fields[<?php echo esc_attr($index); ?>][label]"
                    class="csa-grid-field-label"
                    value="<?php echo esc_attr($field['label']); ?>"
                    placeholder="<?php esc_attr_e('Field Label', 'custom-secure-auth'); ?>"
                >
                <span class="csa-field-help"><?php esc_html_e('What users will see above this field', 'custom-secure-auth'); ?></span>
            </div>

            <div class="csa-grid-field-row">
                <label>
                    <?php esc_html_e('Placeholder:', 'custom-secure-auth'); ?>
                    <span class="csa-field-tooltip" title="<?php esc_attr_e('Hint text shown inside the field before user types', 'custom-secure-auth'); ?>">
                        <span class="dashicons dashicons-editor-help"></span>
                    </span>
                </label>
                <input
                    type="text"
                    name="grid_fields[<?php echo esc_attr($index); ?>][placeholder]"
                    class="csa-grid-field-placeholder"
                    value="<?php echo esc_attr($field['placeholder']); ?>"
                    placeholder="<?php esc_attr_e('Placeholder text', 'custom-secure-auth'); ?>"
                >
                <span class="csa-field-help"><?php esc_html_e('Example text shown inside the empty field', 'custom-secure-auth'); ?></span>
            </div>

            <div class="csa-grid-field-row">
                <label>
                    <?php esc_html_e('Field Type:', 'custom-secure-auth'); ?>
                    <span class="csa-field-tooltip" title="<?php esc_attr_e('The type of input field and where the data is stored', 'custom-secure-auth'); ?>">
                        <span class="dashicons dashicons-editor-help"></span>
                    </span>
                </label>
                <select name="grid_fields[<?php echo esc_attr($index); ?>][type]" class="csa-grid-field-type">
                    <option value="text" <?php selected($field['type'], 'text'); ?>><?php esc_html_e('Text Input', 'custom-secure-auth'); ?></option>
                    <option value="email" <?php selected($field['type'], 'email'); ?>><?php esc_html_e('Email Address', 'custom-secure-auth'); ?></option>
                    <option value="password" <?php selected($field['type'], 'password'); ?>><?php esc_html_e('Password', 'custom-secure-auth'); ?></option>
                    <option value="checkbox" <?php selected($field['type'], 'checkbox'); ?>><?php esc_html_e('Checkbox', 'custom-secure-auth'); ?></option>
                    <option value="wp_first_name" <?php selected($field['type'], 'wp_first_name'); ?>><?php esc_html_e('WordPress First Name', 'custom-secure-auth'); ?></option>
                    <option value="wp_last_name" <?php selected($field['type'], 'wp_last_name'); ?>><?php esc_html_e('WordPress Last Name', 'custom-secure-auth'); ?></option>
                    <option value="usermeta" <?php selected($field['type'], 'usermeta'); ?>><?php esc_html_e('Custom User Data', 'custom-secure-auth'); ?></option>
                </select>
                <span class="csa-field-help csa-field-type-help">
                    <?php
                    // Help text that changes based on selected type
                    $help_texts = array(
                        'text' => __('Regular text input (for username, etc.)', 'custom-secure-auth'),
                        'email' => __('Validates email format automatically', 'custom-secure-auth'),
                        'password' => __('Masked input for secure passwords', 'custom-secure-auth'),
                        'checkbox' => __('Yes/No or agreement checkbox', 'custom-secure-auth'),
                        'wp_first_name' => __('Saves to WordPress user profile', 'custom-secure-auth'),
                        'wp_last_name' => __('Saves to WordPress user profile', 'custom-secure-auth'),
                        'usermeta' => __('Custom data (phone, company, etc.)', 'custom-secure-auth')
                    );
                    echo esc_html($help_texts[$field['type']] ?? $help_texts['text']);
                    ?>
                </span>
            </div>

            <div class="csa-grid-field-row">
                <label>
                    <?php esc_html_e('Field Width:', 'custom-secure-auth'); ?>
                    <span class="csa-field-tooltip" title="<?php esc_attr_e('How wide this field should be on the form', 'custom-secure-auth'); ?>">
                        <span class="dashicons dashicons-editor-help"></span>
                    </span>
                </label>
                <select name="grid_fields[<?php echo esc_attr($index); ?>][width]" class="csa-grid-field-width">
                    <option value="33%" <?php selected($field['width'], '33%'); ?>><?php esc_html_e('One Third (33%)', 'custom-secure-auth'); ?></option>
                    <option value="50%" <?php selected($field['width'], '50%'); ?>><?php esc_html_e('Half Width (50%)', 'custom-secure-auth'); ?></option>
                    <option value="100%" <?php selected($field['width'], '100%'); ?>><?php esc_html_e('Full Width (100%)', 'custom-secure-auth'); ?></option>
                </select>
                <span class="csa-field-help"><?php esc_html_e('Fields can be placed side-by-side with smaller widths', 'custom-secure-auth'); ?></span>
            </div>

            <div class="csa-grid-field-row">
                <label class="csa-checkbox-label">
                    <input
                        type="checkbox"
                        name="grid_fields[<?php echo esc_attr($index); ?>][required]"
                        class="csa-grid-field-required"
                        value="1"
                        <?php checked($field['required'], true); ?>
                    >
                    <span><?php esc_html_e('Required Field', 'custom-secure-auth'); ?></span>
                    <span class="csa-field-tooltip" title="<?php esc_attr_e('User must fill this out to register', 'custom-secure-auth'); ?>">
                        <span class="dashicons dashicons-editor-help"></span>
                    </span>
                </label>
                <span class="csa-field-help"><?php esc_html_e('Check this if the field must be filled out', 'custom-secure-auth'); ?></span>
            </div>
        </div>
        <?php
    }

    /**
     * Render Email Templates tab
     *
     * @param array $settings Current settings
     */
    private function render_email_templates_tab($settings) {
        ?>
        <div class="csa-placeholder-help">
            <h4><?php esc_html_e('Available Placeholders', 'custom-secure-auth'); ?></h4>
            <p><?php esc_html_e('You can use the following placeholders in your email templates and subjects:', 'custom-secure-auth'); ?></p>
            <ul>
                <li><code>{user_name}</code> - <?php esc_html_e('The user\'s display name or username', 'custom-secure-auth'); ?></li>
                <li><code>{set_password_url}</code> - <?php esc_html_e('The link to set/reset password', 'custom-secure-auth'); ?></li>
                <li><code>{site_name}</code> - <?php esc_html_e('Your website name', 'custom-secure-auth'); ?></li>
                <li><code>{user_email}</code> - <?php esc_html_e('The user\'s email address', 'custom-secure-auth'); ?></li>
            </ul>
        </div>

        <h2><?php esc_html_e('Activation Email', 'custom-secure-auth'); ?></h2>
        <p><?php esc_html_e('This email is sent when a new user registers and needs to activate their account.', 'custom-secure-auth'); ?></p>

        <table class="form-table csa-form-table">
            <tbody>
                <tr>
                    <th scope="row">
                        <label for="activation_subject"><?php esc_html_e('Subject', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <input
                            type="text"
                            name="activation_subject"
                            id="activation_subject"
                            value="<?php echo esc_attr($settings['emails']['activation_subject']); ?>"
                            style="width: 100%; max-width: 600px;"
                        >
                    </td>
                </tr>

                <tr>
                    <th scope="row">
                        <label for="activation_template"><?php esc_html_e('Email Template', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <?php
                        wp_editor(
                            $settings['emails']['activation_template'],
                            'activation_template',
                            array(
                                'textarea_name' => 'activation_template',
                                'textarea_rows' => 10,
                                'media_buttons' => false,
                                'teeny' => true,
                                'quicktags' => true,
                            )
                        );
                        ?>
                    </td>
                </tr>
            </tbody>
        </table>

        <h2><?php esc_html_e('Password Recovery Email', 'custom-secure-auth'); ?></h2>
        <p><?php esc_html_e('This email is sent when a user requests to reset their password.', 'custom-secure-auth'); ?></p>

        <table class="form-table csa-form-table">
            <tbody>
                <tr>
                    <th scope="row">
                        <label for="recovery_subject"><?php esc_html_e('Subject', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <input
                            type="text"
                            name="recovery_subject"
                            id="recovery_subject"
                            value="<?php echo esc_attr($settings['emails']['recovery_subject']); ?>"
                            style="width: 100%; max-width: 600px;"
                        >
                    </td>
                </tr>

                <tr>
                    <th scope="row">
                        <label for="recovery_template"><?php esc_html_e('Email Template', 'custom-secure-auth'); ?></label>
                    </th>
                    <td>
                        <?php
                        wp_editor(
                            $settings['emails']['recovery_template'],
                            'recovery_template',
                            array(
                                'textarea_name' => 'recovery_template',
                                'textarea_rows' => 10,
                                'media_buttons' => false,
                                'teeny' => true,
                                'quicktags' => true,
                            )
                        );
                        ?>
                    </td>
                </tr>
            </tbody>
        </table>
        <?php
    }

    /**
     * Render Shortcodes tab
     *
     * @param array $settings Current settings
     */
    private function render_shortcodes_tab($settings) {
        ?>
        <div class="csa-shortcodes-documentation">
            <div class="csa-info-box">
                <h3><span class="dashicons dashicons-info"></span> <?php esc_html_e('What are Shortcodes?', 'custom-secure-auth'); ?></h3>
                <p><?php esc_html_e('Shortcodes are small snippets of code you can insert into WordPress pages, posts, or widgets to display forms and buttons. Simply copy the shortcode and paste it where you want it to appear.', 'custom-secure-auth'); ?></p>
            </div>

            <!-- Login Form -->
            <div class="csa-shortcode-card">
                <div class="csa-shortcode-header">
                    <h3><span class="dashicons dashicons-admin-network"></span> <?php esc_html_e('Login Form', 'custom-secure-auth'); ?></h3>
                    <button type="button" class="button button-small csa-copy-btn" data-shortcode="[auth_login]">
                        <span class="dashicons dashicons-clipboard"></span> <?php esc_html_e('Copy', 'custom-secure-auth'); ?>
                    </button>
                </div>
                <div class="csa-shortcode-code">
                    <code>[auth_login]</code>
                </div>
                <p class="csa-shortcode-description">
                    <?php esc_html_e('Displays a login form with username, password, and "Remember Me" checkbox. Users can log into their existing accounts.', 'custom-secure-auth'); ?>
                </p>
                <div class="csa-shortcode-example">
                    <strong><?php esc_html_e('Example:', 'custom-secure-auth'); ?></strong>
                    <p><?php esc_html_e('Add this to your Login page to display the login form.', 'custom-secure-auth'); ?></p>
                </div>
            </div>

            <!-- Registration Form -->
            <div class="csa-shortcode-card">
                <div class="csa-shortcode-header">
                    <h3><span class="dashicons dashicons-admin-users"></span> <?php esc_html_e('Registration Form', 'custom-secure-auth'); ?></h3>
                    <button type="button" class="button button-small csa-copy-btn" data-shortcode="[auth_register]">
                        <span class="dashicons dashicons-clipboard"></span> <?php esc_html_e('Copy', 'custom-secure-auth'); ?>
                    </button>
                </div>
                <div class="csa-shortcode-code">
                    <code>[auth_register]</code>
                </div>
                <p class="csa-shortcode-description">
                    <?php esc_html_e('Displays a registration form with the fields you configured in the Registration Grid Builder tab. New users can create accounts.', 'custom-secure-auth'); ?>
                </p>
                <div class="csa-shortcode-example">
                    <strong><?php esc_html_e('Example:', 'custom-secure-auth'); ?></strong>
                    <p><?php esc_html_e('Add this to your Registration page to display the sign-up form with your custom fields.', 'custom-secure-auth'); ?></p>
                </div>
            </div>

            <!-- Lost Password Form -->
            <div class="csa-shortcode-card">
                <div class="csa-shortcode-header">
                    <h3><span class="dashicons dashicons-unlock"></span> <?php esc_html_e('Lost Password Form', 'custom-secure-auth'); ?></h3>
                    <button type="button" class="button button-small csa-copy-btn" data-shortcode="[auth_lost_password]">
                        <span class="dashicons dashicons-clipboard"></span> <?php esc_html_e('Copy', 'custom-secure-auth'); ?>
                    </button>
                </div>
                <div class="csa-shortcode-code">
                    <code>[auth_lost_password]</code>
                </div>
                <p class="csa-shortcode-description">
                    <?php esc_html_e('Displays a password recovery form where users can request a password reset link via email.', 'custom-secure-auth'); ?>
                </p>
                <div class="csa-shortcode-example">
                    <strong><?php esc_html_e('Example:', 'custom-secure-auth'); ?></strong>
                    <p><?php esc_html_e('Add this to your Lost Password page so users can reset forgotten passwords.', 'custom-secure-auth'); ?></p>
                </div>
            </div>

            <!-- Set Password Form -->
            <div class="csa-shortcode-card">
                <div class="csa-shortcode-header">
                    <h3><span class="dashicons dashicons-lock"></span> <?php esc_html_e('Set Password Form', 'custom-secure-auth'); ?></h3>
                    <button type="button" class="button button-small csa-copy-btn" data-shortcode="[auth_set_password]">
                        <span class="dashicons dashicons-clipboard"></span> <?php esc_html_e('Copy', 'custom-secure-auth'); ?>
                    </button>
                </div>
                <div class="csa-shortcode-code">
                    <code>[auth_set_password]</code>
                </div>
                <p class="csa-shortcode-description">
                    <?php esc_html_e('Displays a form where users can set or reset their password. This is used both for account activation and password recovery.', 'custom-secure-auth'); ?>
                </p>
                <div class="csa-shortcode-example">
                    <strong><?php esc_html_e('Example:', 'custom-secure-auth'); ?></strong>
                    <p><?php esc_html_e('Add this to your Set Password page. This is where users land when they click the link in activation/recovery emails.', 'custom-secure-auth'); ?></p>
                </div>
            </div>

            <!-- Login Button -->
            <div class="csa-shortcode-card">
                <div class="csa-shortcode-header">
                    <h3><span class="dashicons dashicons-migrate"></span> <?php esc_html_e('Login Button', 'custom-secure-auth'); ?></h3>
                    <button type="button" class="button button-small csa-copy-btn" data-shortcode='[auth_button action="login"]'>
                        <span class="dashicons dashicons-clipboard"></span> <?php esc_html_e('Copy', 'custom-secure-auth'); ?>
                    </button>
                </div>
                <div class="csa-shortcode-code">
                    <code>[auth_button action="login"]</code>
                </div>
                <p class="csa-shortcode-description">
                    <?php esc_html_e('Displays a button that links to your login page. Great for navigation menus or widgets.', 'custom-secure-auth'); ?>
                </p>
                <div class="csa-shortcode-options">
                    <strong><?php esc_html_e('Optional Parameters:', 'custom-secure-auth'); ?></strong>
                    <ul>
                        <li><code>text="Custom Text"</code> - <?php esc_html_e('Change the button text', 'custom-secure-auth'); ?></li>
                        <li><code>class="my-class"</code> - <?php esc_html_e('Add custom CSS classes', 'custom-secure-auth'); ?></li>
                    </ul>
                </div>
                <div class="csa-shortcode-example">
                    <strong><?php esc_html_e('Examples:', 'custom-secure-auth'); ?></strong>
                    <p><code>[auth_button action="login" text="Sign In"]</code></p>
                    <p><code>[auth_button action="login" class="my-button"]</code></p>
                </div>
            </div>

            <!-- Register Button -->
            <div class="csa-shortcode-card">
                <div class="csa-shortcode-header">
                    <h3><span class="dashicons dashicons-plus-alt"></span> <?php esc_html_e('Register Button', 'custom-secure-auth'); ?></h3>
                    <button type="button" class="button button-small csa-copy-btn" data-shortcode='[auth_button action="register"]'>
                        <span class="dashicons dashicons-clipboard"></span> <?php esc_html_e('Copy', 'custom-secure-auth'); ?>
                    </button>
                </div>
                <div class="csa-shortcode-code">
                    <code>[auth_button action="register"]</code>
                </div>
                <p class="csa-shortcode-description">
                    <?php esc_html_e('Displays a button that links to your registration page. Perfect for encouraging new user sign-ups.', 'custom-secure-auth'); ?>
                </p>
                <div class="csa-shortcode-example">
                    <strong><?php esc_html_e('Examples:', 'custom-secure-auth'); ?></strong>
                    <p><code>[auth_button action="register" text="Create Account"]</code></p>
                    <p><code>[auth_button action="register" text="Join Now" class="highlight"]</code></p>
                </div>
            </div>

            <!-- Logout Button -->
            <div class="csa-shortcode-card">
                <div class="csa-shortcode-header">
                    <h3><span class="dashicons dashicons-exit"></span> <?php esc_html_e('Logout Button', 'custom-secure-auth'); ?></h3>
                    <button type="button" class="button button-small csa-copy-btn" data-shortcode='[auth_button action="logout"]'>
                        <span class="dashicons dashicons-clipboard"></span> <?php esc_html_e('Copy', 'custom-secure-auth'); ?>
                    </button>
                </div>
                <div class="csa-shortcode-code">
                    <code>[auth_button action="logout"]</code>
                </div>
                <p class="csa-shortcode-description">
                    <?php esc_html_e('Displays a logout button. Only visible to logged-in users. Clicking it logs the user out immediately.', 'custom-secure-auth'); ?>
                </p>
                <div class="csa-shortcode-example">
                    <strong><?php esc_html_e('Examples:', 'custom-secure-auth'); ?></strong>
                    <p><code>[auth_button action="logout" text="Sign Out"]</code></p>
                    <p><code>[auth_button action="logout" text="Log Out" class="logout-btn"]</code></p>
                </div>
            </div>

            <!-- Quick Reference -->
            <div class="csa-quick-reference">
                <h3><span class="dashicons dashicons-book"></span> <?php esc_html_e('Quick Setup Guide', 'custom-secure-auth'); ?></h3>
                <ol class="csa-setup-steps">
                    <li>
                        <strong><?php esc_html_e('Step 1: Configure Page Mapping', 'custom-secure-auth'); ?></strong>
                        <p><?php esc_html_e('Go to the "Page Mapping & Logic" tab and select which pages will display each form.', 'custom-secure-auth'); ?></p>
                    </li>
                    <li>
                        <strong><?php esc_html_e('Step 2: Create Your Pages', 'custom-secure-auth'); ?></strong>
                        <p><?php esc_html_e('Create 4 WordPress pages: Login, Registration, Lost Password, and Set Password.', 'custom-secure-auth'); ?></p>
                    </li>
                    <li>
                        <strong><?php esc_html_e('Step 3: Add Shortcodes', 'custom-secure-auth'); ?></strong>
                        <p><?php esc_html_e('Add the appropriate shortcode to each page. For example, add [auth_login] to your Login page.', 'custom-secure-auth'); ?></p>
                    </li>
                    <li>
                        <strong><?php esc_html_e('Step 4: Configure Grid Builder', 'custom-secure-auth'); ?></strong>
                        <p><?php esc_html_e('Go to the "Registration Grid Builder" tab and add the fields you want on your registration form.', 'custom-secure-auth'); ?></p>
                    </li>
                    <li>
                        <strong><?php esc_html_e('Step 5: Customize Emails (Optional)', 'custom-secure-auth'); ?></strong>
                        <p><?php esc_html_e('Edit email templates in the "Email Templates" tab to match your brand.', 'custom-secure-auth'); ?></p>
                    </li>
                </ol>
            </div>
        </div>

        <script>
        jQuery(document).ready(function($) {
            // Copy shortcode to clipboard
            $('.csa-copy-btn').on('click', function() {
                var shortcode = $(this).data('shortcode');
                var $btn = $(this);

                // Create temporary input
                var $temp = $('<input>');
                $('body').append($temp);
                $temp.val(shortcode).select();
                document.execCommand('copy');
                $temp.remove();

                // Show feedback
                var originalText = $btn.html();
                $btn.html('<span class="dashicons dashicons-yes"></span> <?php echo esc_js(__('Copied!', 'custom-secure-auth')); ?>');
                $btn.addClass('button-primary');

                setTimeout(function() {
                    $btn.html(originalText);
                    $btn.removeClass('button-primary');
                }, 2000);
            });
        });
        </script>

        <style>
            .csa-shortcodes-documentation {
                max-width: 900px;
            }
            .csa-shortcode-card {
                background: #fff;
                border: 1px solid #ddd;
                border-radius: 6px;
                padding: 25px;
                margin-bottom: 25px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            }
            .csa-shortcode-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 15px;
                padding-bottom: 15px;
                border-bottom: 2px solid #f0f0f0;
            }
            .csa-shortcode-header h3 {
                margin: 0;
                font-size: 18px;
                color: #333;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .csa-shortcode-header .dashicons {
                color: #0073aa;
            }
            .csa-shortcode-code {
                background: #f8f9fa;
                border: 1px solid #e1e4e8;
                border-radius: 4px;
                padding: 15px;
                margin: 15px 0;
                font-family: 'Courier New', monospace;
            }
            .csa-shortcode-code code {
                font-size: 16px;
                color: #d73a49;
                font-weight: 600;
            }
            .csa-shortcode-description {
                color: #666;
                line-height: 1.6;
                margin: 15px 0;
            }
            .csa-shortcode-options {
                background: #fffbf0;
                border-left: 4px solid #f6b027;
                padding: 15px;
                margin: 15px 0;
            }
            .csa-shortcode-options ul {
                margin: 10px 0 0 20px;
            }
            .csa-shortcode-options li {
                margin-bottom: 8px;
            }
            .csa-shortcode-example {
                background: #f0f6fc;
                border-left: 4px solid #0073aa;
                padding: 15px;
                margin: 15px 0;
            }
            .csa-shortcode-example p {
                margin: 8px 0;
            }
            .csa-quick-reference {
                background: #e7f3ff;
                border: 2px solid #0073aa;
                border-radius: 6px;
                padding: 25px;
                margin-top: 30px;
            }
            .csa-quick-reference h3 {
                margin-top: 0;
                color: #0073aa;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .csa-setup-steps {
                counter-reset: step-counter;
                list-style: none;
                padding: 0;
            }
            .csa-setup-steps li {
                position: relative;
                padding: 20px 20px 20px 60px;
                margin-bottom: 20px;
                background: #fff;
                border-radius: 4px;
                border-left: 4px solid #0073aa;
            }
            .csa-setup-steps li:before {
                counter-increment: step-counter;
                content: counter(step-counter);
                position: absolute;
                left: 15px;
                top: 20px;
                width: 35px;
                height: 35px;
                background: #0073aa;
                color: #fff;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: bold;
                font-size: 18px;
            }
            .csa-setup-steps strong {
                display: block;
                margin-bottom: 8px;
                color: #333;
                font-size: 15px;
            }
            .csa-setup-steps p {
                margin: 0;
                color: #666;
                line-height: 1.5;
            }
            .csa-copy-btn {
                transition: all 0.2s ease;
            }
            .csa-copy-btn:hover {
                transform: translateY(-1px);
            }
        </style>
        <?php
    }

    /**
     * Render Username Policy tab
     *
     * @param array $settings Current settings
     */
    private function render_username_policy_tab($settings) {
        $policy = isset($settings['username_policy']) ? $settings['username_policy'] : array();

        // Get word lists and settings
        $reserved_words = isset($policy['reserved_words']) ? $policy['reserved_words'] : array();
        $reserved_words_boundary_match = isset($policy['reserved_words_boundary_match']) ? $policy['reserved_words_boundary_match'] : false;
        $restricted_strict_enabled = isset($policy['restricted_strict_enabled']) ? $policy['restricted_strict_enabled'] : true;
        $restricted_strict_words = isset($policy['restricted_strict_words']) ? $policy['restricted_strict_words'] : array();
        $restricted_isolated_enabled = isset($policy['restricted_isolated_enabled']) ? $policy['restricted_isolated_enabled'] : true;
        $restricted_isolated_words = isset($policy['restricted_isolated_words']) ? $policy['restricted_isolated_words'] : array();
        ?>

        <div class="csa-username-policy-wrap">
            <!-- Info Box -->
            <div class="csa-info-box">
                <h3><span class="dashicons dashicons-admin-users"></span> <?php esc_html_e('Username Policy Management', 'custom-secure-auth'); ?></h3>
                <p><?php esc_html_e('Configure username validation rules and manage restricted words. These settings ensure usernames are appropriate and prevent system conflicts.', 'custom-secure-auth'); ?></p>
            </div>

            <!-- Section 1: Format Rules (Read-only) -->
            <div class="csa-policy-section">
                <h3><?php esc_html_e('Format Rules', 'custom-secure-auth'); ?></h3>
                <p><?php esc_html_e('The following format rules are always enforced:', 'custom-secure-auth'); ?></p>
                <ul class="csa-format-rules">
                    <li><strong><?php esc_html_e('Length:', 'custom-secure-auth'); ?></strong> <?php esc_html_e('6-24 characters', 'custom-secure-auth'); ?></li>
                    <li><strong><?php esc_html_e('Allowed characters:', 'custom-secure-auth'); ?></strong> <?php esc_html_e('Letters (a-z), numbers (0-9), underscores (_), hyphens (-)', 'custom-secure-auth'); ?></li>
                    <li><strong><?php esc_html_e('Automatically converted to lowercase', 'custom-secure-auth'); ?></strong></li>
                    <li><strong><?php esc_html_e('No purely numeric usernames', 'custom-secure-auth'); ?></strong> <?php esc_html_e('(e.g., "123456" is blocked)', 'custom-secure-auth'); ?></li>
                    <li><strong><?php esc_html_e('No email addresses', 'custom-secure-auth'); ?></strong> <?php esc_html_e('(@ symbol detection)', 'custom-secure-auth'); ?></li>
                </ul>
            </div>

            <!-- Section 2: Reserved Words (Always Active) -->
            <div class="csa-policy-section">
                <h3><?php esc_html_e('Reserved Words', 'custom-secure-auth'); ?></h3>
                <label class="csa-toggle-label" style="margin-top: 15px;">
                    <input
                        type="checkbox"
                        name="reserved_words_boundary_match"
                        id="reserved_words_boundary_match"
                        value="1"
                        <?php checked($reserved_words_boundary_match, true); ?>
                    >
                    <strong><?php esc_html_e('Enable Word Boundary Matching', 'custom-secure-auth'); ?></strong>
                </label>
                <p class="description" style="margin-left: 26px;">
                    <?php esc_html_e('When enabled, reserved words are blocked even with numbers/text before or after (e.g., "admin123", "879878464_admin"). When disabled, only exact matches are blocked (e.g., only "admin").', 'custom-secure-auth'); ?>
                </p>

                <p class="csa-matching-logic">
                    <span class="dashicons dashicons-info"></span>
                    <strong><?php esc_html_e('Matching Logic:', 'custom-secure-auth'); ?></strong>
                    <br>
                    <strong><?php esc_html_e('Exact Match Only (Unchecked):', 'custom-secure-auth'); ?></strong>
                    <em><?php esc_html_e('If "admin" is in the list, only "admin" is blocked. "admin123" and "879878464_admin" are allowed.', 'custom-secure-auth'); ?></em>
                    <br>
                    <strong><?php esc_html_e('Word Boundary Match (Checked):', 'custom-secure-auth'); ?></strong>
                    <em><?php esc_html_e('If "admin" is in the list, "admin", "admin123", "879878464_admin", and "_admin_" are all blocked, but "administrator" is allowed.', 'custom-secure-auth'); ?></em>
                </p>

                <p><?php esc_html_e('These words are reserved for system use and cannot be used as usernames (always active).', 'custom-secure-auth'); ?></p>

                <label for="reserved_words"><?php esc_html_e('Reserved Words:', 'custom-secure-auth'); ?></label>
                <div class="csa-tag-input-wrapper" data-field-name="reserved_words">
                    <div class="csa-tag-display"></div>
                    <div class="csa-tag-input-row">
                        <input type="text" class="csa-tag-input" placeholder="Type word and press Enter or click Add" aria-label="Add reserved word">
                        <button type="button" class="button csa-tag-add-btn"><?php esc_html_e('Add', 'custom-secure-auth'); ?></button>
                        <button type="button" class="button button-secondary csa-reset-defaults" data-default-words="admin, administrator, root, system, server, bot, cron, null, undefined, api, mod, moderator, staff, support, help, official, owner, founder, verify, verification, security, webmaster, sysadmin, superuser, editor"><?php esc_html_e('Reset to Defaults', 'custom-secure-auth'); ?></button>
                    </div>
                    <input type="hidden" name="reserved_words" id="reserved_words" value="<?php echo esc_attr(implode(', ', $reserved_words)); ?>">
                </div>
                <p class="description">
                    <?php esc_html_e('Add words one at a time. Words will be automatically converted to lowercase. Click the × to remove.', 'custom-secure-auth'); ?>
                </p>

            </div>

            <!-- Section 3: Strict Block (Substring Match) -->
            <div class="csa-policy-section">
                <h3><?php esc_html_e('Restricted Words - Tier 1: Strict Block', 'custom-secure-auth'); ?></h3>

                <label class="csa-toggle-label">
                    <input
                        type="checkbox"
                        name="restricted_strict_enabled"
                        id="restricted_strict_enabled"
                        value="1"
                        <?php checked($restricted_strict_enabled, true); ?>
                    >
                    <strong><?php esc_html_e('Enable Strict Block Filter', 'custom-secure-auth'); ?></strong>
                </label>
                <p class="description">
                    <?php esc_html_e('Block usernames containing offensive words anywhere in the username (substring match).', 'custom-secure-auth'); ?>
                </p>

                <p class="csa-matching-logic">
                    <span class="dashicons dashicons-info"></span>
                    <strong><?php esc_html_e('Matching Logic:', 'custom-secure-auth'); ?></strong>
                    <?php esc_html_e('Substring match - blocked if the word appears anywhere in the username.', 'custom-secure-auth'); ?>
                    <br>
                    <em><?php esc_html_e('Example: If "spam" is in the list, both "spam" and "spammer123" are blocked.', 'custom-secure-auth'); ?></em>
                </p>

                <details class="csa-collapsible-section">
                    <summary class="csa-warning-summary">
                        <span class="dashicons dashicons-warning"></span>
                        <?php esc_html_e('⚠️ Click to view/edit restricted words (contains offensive content)', 'custom-secure-auth'); ?>
                    </summary>
                    <div class="csa-restricted-content">
                        <label for="restricted_strict_words"><?php esc_html_e('Strict Block Words:', 'custom-secure-auth'); ?></label>
                        <div class="csa-tag-input-wrapper" data-field-name="restricted_strict_words">
                            <div class="csa-tag-display"></div>
                            <div class="csa-tag-input-row">
                                <input type="text" class="csa-tag-input" placeholder="Type word and press Enter or click Add" aria-label="Add strict block word">
                                <button type="button" class="button csa-tag-add-btn"><?php esc_html_e('Add', 'custom-secure-auth'); ?></button>
                                <button type="button" class="button button-secondary csa-reset-defaults" data-default-words="nigger, nigga, kike, chink, spic, wetback, gook, towelhead, faggot, dyke, tranny, fuck, shit, cunt, rape, rapist, pedophile, pedo, molest, incest, nazi, hitler, kkk, swastika, retard"><?php esc_html_e('Reset to Defaults', 'custom-secure-auth'); ?></button>
                            </div>
                            <input type="hidden" name="restricted_strict_words" id="restricted_strict_words" value="<?php echo esc_attr(implode(', ', $restricted_strict_words)); ?>">
                        </div>
                        <p class="description">
                            <?php esc_html_e('Add words one at a time. Words that should NEVER appear anywhere in a username. These will be automatically converted to lowercase. Click the × to remove.', 'custom-secure-auth'); ?>
                        </p>
                    </div>
                </details>
            </div>

            <!-- Section 4: Isolated Block (Word Boundary Match) -->
            <div class="csa-policy-section">
                <h3><?php esc_html_e('Restricted Words - Tier 2: Isolated Block', 'custom-secure-auth'); ?></h3>

                <label class="csa-toggle-label">
                    <input
                        type="checkbox"
                        name="restricted_isolated_enabled"
                        id="restricted_isolated_enabled"
                        value="1"
                        <?php checked($restricted_isolated_enabled, true); ?>
                    >
                    <strong><?php esc_html_e('Enable Isolated Block Filter', 'custom-secure-auth'); ?></strong>
                </label>
                <p class="description">
                    <?php esc_html_e('Block usernames where inappropriate words appear as standalone words (word boundary match).', 'custom-secure-auth'); ?>
                </p>

                <p class="csa-matching-logic">
                    <span class="dashicons dashicons-info"></span>
                    <strong><?php esc_html_e('Matching Logic:', 'custom-secure-auth'); ?></strong>
                    <?php esc_html_e('Word boundary match - blocked only when the word stands alone or is separated by underscores/hyphens.', 'custom-secure-auth'); ?>
                    <br>
                    <em><?php esc_html_e('Example: If "nazi" is in the list, "big_nazi" is blocked, but "denazification" is allowed.', 'custom-secure-auth'); ?></em>
                </p>

                <details class="csa-collapsible-section">
                    <summary class="csa-warning-summary">
                        <span class="dashicons dashicons-warning"></span>
                        <?php esc_html_e('⚠️ Click to view/edit restricted words (contains offensive content)', 'custom-secure-auth'); ?>
                    </summary>
                    <div class="csa-restricted-content">
                        <label for="restricted_isolated_words"><?php esc_html_e('Isolated Block Words:', 'custom-secure-auth'); ?></label>
                        <div class="csa-tag-input-wrapper" data-field-name="restricted_isolated_words">
                            <div class="csa-tag-display"></div>
                            <div class="csa-tag-input-row">
                                <input type="text" class="csa-tag-input" placeholder="Type word and press Enter or click Add" aria-label="Add isolated block word">
                                <button type="button" class="button csa-tag-add-btn"><?php esc_html_e('Add', 'custom-secure-auth'); ?></button>
                                <button type="button" class="button button-secondary csa-reset-defaults" data-default-words="ass, dick, cock, pussy, tit, tits, boob, boobs, sex, xxx, porn, hentai, whore, slut, bitch, bastard, damn, hell, piss, crap"><?php esc_html_e('Reset to Defaults', 'custom-secure-auth'); ?></button>
                            </div>
                            <input type="hidden" name="restricted_isolated_words" id="restricted_isolated_words" value="<?php echo esc_attr(implode(', ', $restricted_isolated_words)); ?>">
                        </div>
                        <p class="description">
                            <?php esc_html_e('Add words one at a time. Words blocked only when they appear as standalone words. These will be automatically converted to lowercase. Click the × to remove.', 'custom-secure-auth'); ?>
                        </p>
                    </div>
                </details>
            </div>
        </div>

        <style>
            .csa-username-policy-wrap {
                max-width: 900px;
            }
            .csa-info-box {
                background: #e7f3ff;
                border-left: 4px solid #0073aa;
                padding: 15px 20px;
                margin-bottom: 25px;
            }
            .csa-info-box h3 {
                margin-top: 0;
                color: #0073aa;
            }
            .csa-info-box .dashicons {
                color: #0073aa;
            }
            .csa-policy-section {
                background: #fff;
                border: 1px solid #ddd;
                padding: 20px;
                margin-bottom: 20px;
                border-radius: 4px;
            }
            .csa-policy-section h3 {
                margin-top: 0;
                border-bottom: 1px solid #ddd;
                padding-bottom: 10px;
            }
            .csa-format-rules {
                list-style: none;
                padding: 0;
                margin: 15px 0;
            }
            .csa-format-rules li {
                padding: 8px 0;
                border-bottom: 1px solid #f0f0f0;
            }
            .csa-format-rules li:last-child {
                border-bottom: none;
            }
            .csa-matching-logic {
                background: #f0f6fc;
                border-left: 3px solid #0073aa;
                padding: 12px 15px;
                margin: 15px 0;
            }
            .csa-matching-logic .dashicons {
                color: #0073aa;
                vertical-align: text-top;
            }
            .csa-toggle-label {
                display: flex;
                align-items: center;
                gap: 8px;
                margin: 15px 0;
                cursor: pointer;
            }
            .csa-toggle-label input[type="checkbox"] {
                width: 18px;
                height: 18px;
            }
            .csa-collapsible-section {
                margin: 15px 0;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
            .csa-warning-summary {
                background: #fff3cd;
                border-bottom: 1px solid #ffc107;
                padding: 12px 15px;
                cursor: pointer;
                font-weight: 600;
                color: #856404;
            }
            .csa-warning-summary:hover {
                background: #ffecb3;
            }
            .csa-warning-summary .dashicons {
                color: #ffc107;
                vertical-align: text-top;
            }
            .csa-restricted-content {
                padding: 15px;
                background: #fafafa;
            }
            .csa-username-policy-wrap textarea.large-text {
                width: 100%;
                font-family: 'Courier New', monospace;
                font-size: 13px;
            }
            .csa-username-policy-wrap label {
                display: block;
                font-weight: 600;
                margin-bottom: 8px;
            }
            .csa-username-policy-wrap .description {
                margin-top: 8px;
                color: #666;
                font-style: italic;
            }

            /* Tag-Style Input Interface */
            .csa-tag-input-wrapper {
                max-width: 800px;
            }
            .csa-tag-display {
                min-height: 50px;
                padding: 10px;
                background: #fff;
                border: 1px solid #8c8f94;
                border-radius: 4px;
                margin-bottom: 10px;
                display: flex;
                flex-wrap: wrap;
                gap: 6px;
                align-items: flex-start;
            }
            .csa-tag-display:empty::before {
                content: 'No items added yet. Type below and press Enter or click Add.';
                color: #999;
                font-style: italic;
                font-size: 13px;
            }
            .csa-tag {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                padding: 5px 10px;
                background: #2271b1;
                color: #fff;
                border-radius: 3px;
                font-size: 13px;
                line-height: 1.4;
                transition: background 0.15s ease;
            }
            .csa-tag:hover {
                background: #135e96;
            }
            .csa-tag-remove {
                background: none;
                border: none;
                color: #fff;
                cursor: pointer;
                padding: 0;
                margin: 0;
                font-size: 16px;
                line-height: 1;
                opacity: 0.8;
                transition: opacity 0.15s ease;
            }
            .csa-tag-remove:hover {
                opacity: 1;
            }
            .csa-tag-input-row {
                display: flex;
                gap: 8px;
                align-items: center;
            }
            .csa-tag-input {
                flex: 1;
                padding: 6px 10px;
                border: 1px solid #8c8f94;
                border-radius: 4px;
                font-size: 14px;
            }
            .csa-tag-input:focus {
                border-color: #2271b1;
                outline: none;
                box-shadow: 0 0 0 1px #2271b1;
            }
            .csa-tag-add-btn {
                white-space: nowrap;
            }
            .csa-reset-defaults {
                white-space: nowrap;
                margin-left: auto;
            }
        </style>

        <script>
        /**
         * CSA Tag Manager - WordPress-style tag interface
         */
        class CSATagManager {
            constructor(wrapperElement) {
                this.wrapper = wrapperElement;
                this.display = this.wrapper.querySelector('.csa-tag-display');
                this.input = this.wrapper.querySelector('.csa-tag-input');
                this.addButton = this.wrapper.querySelector('.csa-tag-add-btn');
                this.hiddenInput = this.wrapper.querySelector('input[type="hidden"]');
                this.tags = new Set();

                this.init();
            }

            init() {
                // Load existing tags from hidden input
                this.loadExistingTags();

                // Bind events
                this.addButton.addEventListener('click', () => this.handleAdd());
                this.input.addEventListener('keypress', (e) => this.handleKeyPress(e));
                this.display.addEventListener('click', (e) => this.handleRemove(e));
            }

            loadExistingTags() {
                const value = this.hiddenInput.value.trim();
                if (value) {
                    const items = value.split(',').map(item => item.trim()).filter(item => item);
                    items.forEach(item => this.tags.add(item.toLowerCase()));
                }
                this.render();
            }

            handleAdd() {
                const value = this.input.value.trim();
                if (value) {
                    this.addTag(value);
                    this.input.value = '';
                    this.input.focus();
                }
            }

            handleKeyPress(e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    this.handleAdd();
                }
            }

            handleRemove(e) {
                if (e.target.classList.contains('csa-tag-remove')) {
                    const tag = e.target.closest('.csa-tag').dataset.value;
                    this.removeTag(tag);
                }
            }

            addTag(value) {
                const normalized = value.toLowerCase().trim();

                if (!normalized) {
                    return false;
                }

                if (this.tags.has(normalized)) {
                    // Flash the existing tag to show it's already there
                    const existingTag = this.display.querySelector(`[data-value="${normalized}"]`);
                    if (existingTag) {
                        existingTag.style.animation = 'none';
                        setTimeout(() => {
                            existingTag.style.animation = 'csaFlash 0.5s ease';
                        }, 10);
                    }
                    return false;
                }

                this.tags.add(normalized);
                this.render();
                this.updateHiddenInput();
                return true;
            }

            removeTag(value) {
                this.tags.delete(value);
                this.render();
                this.updateHiddenInput();
            }

            render() {
                this.display.innerHTML = '';

                const sortedTags = Array.from(this.tags).sort();

                sortedTags.forEach(tag => {
                    const tagElement = document.createElement('span');
                    tagElement.className = 'csa-tag';
                    tagElement.dataset.value = tag;

                    const text = document.createElement('span');
                    text.textContent = tag;

                    const removeBtn = document.createElement('button');
                    removeBtn.type = 'button';
                    removeBtn.className = 'csa-tag-remove';
                    removeBtn.innerHTML = '&times;';
                    removeBtn.setAttribute('aria-label', 'Remove ' + tag);

                    tagElement.appendChild(text);
                    tagElement.appendChild(removeBtn);
                    this.display.appendChild(tagElement);
                });
            }

            updateHiddenInput() {
                const sortedTags = Array.from(this.tags).sort();
                this.hiddenInput.value = sortedTags.join(', ');
            }
        }

        // Initialize all tag managers when DOM is ready
        document.addEventListener('DOMContentLoaded', function() {
            const wrappers = document.querySelectorAll('.csa-tag-input-wrapper');
            const managers = new Map();

            wrappers.forEach(wrapper => {
                const manager = new CSATagManager(wrapper);
                const fieldName = wrapper.dataset.fieldName;
                managers.set(fieldName, manager);
            });

            // Handle "Reset to Defaults" buttons
            document.querySelectorAll('.csa-reset-defaults').forEach(btn => {
                btn.addEventListener('click', function() {
                    if (!confirm('Reset to default word list? This will replace all current words.')) {
                        return;
                    }

                    const wrapper = this.closest('.csa-tag-input-wrapper');
                    const fieldName = wrapper.dataset.fieldName;
                    const manager = managers.get(fieldName);
                    const defaultWords = this.dataset.defaultWords;

                    if (manager && defaultWords) {
                        // Clear existing tags
                        manager.tags.clear();

                        // Add default words
                        const words = defaultWords.split(',').map(w => w.trim());
                        words.forEach(word => {
                            if (word) {
                                manager.tags.add(word.toLowerCase());
                            }
                        });

                        // Re-render and update hidden input
                        manager.render();
                        manager.updateHiddenInput();
                    }
                });
            });
        });

        // Add flash animation for duplicates
        const style = document.createElement('style');
        style.textContent = `
            @keyframes csaFlash {
                0%, 100% { transform: scale(1); }
                50% { transform: scale(1.1); background: #135e96; }
            }
        `;
        document.head.appendChild(style);
        </script>

        <?php
    }
}
