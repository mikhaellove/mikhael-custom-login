<?php
/**
 * Profile Editor Class
 *
 * Provides frontend user profile editing functionality via shortcodes.
 * Allows users to manage their profiles without accessing wp-admin.
 *
 * MIGRATION NOTES
 * ===============
 * This class was migrated from the standalone "mikhael-frontend-user-page" plugin
 * into Custom Secure Auth in version 2.1.0 to provide integrated user management.
 *
 * FEATURES
 * ========
 * 1. Frontend Profile Form
 *    - Custom avatar upload (stored as attachment)
 *    - First name, last name, display name
 *    - Email change with confirmation
 *    - Website URL
 *    - Bio/description
 *    - Password change (requires current password)
 *    - Language preference
 *    - Member directory visibility toggle
 *
 * 2. Email Change Flow
 *    - Multi-site aware (different flows for multi-site vs single-site)
 *    - Sends confirmation email to new address
 *    - Uses hash-based verification link
 *    - Only updates email after confirmation
 *
 * 3. Custom Avatar System
 *    - Replaces default Gravatar with uploaded image
 *    - Custom image size: 200x200px (profile-avatar)
 *    - Stored as WordPress attachment
 *    - Old avatars automatically deleted on new upload
 *    - Filters get_avatar() to display custom avatar
 *
 * 4. Language Management
 *    - Per-user language preference
 *    - Integrates with WordPress locale system
 *    - Overrides site default for logged-in users
 *    - Falls back to site default if not set
 *
 * 5. GTranslate Integration
 *    - Automatic language switching for logged-in users
 *    - JavaScript-based translation trigger
 *    - Maps WordPress locales to GTranslate language codes
 *    - Special handling for Chinese (zh-CN, zh-TW) and Portuguese (pt-BR)
 *    - Only activates if GTranslate plugin is active
 *
 * 6. Admin Redirection
 *    - Non-admin users redirected from wp-admin/profile.php
 *    - Prevents access to backend profile editor
 *    - Redirects to configured frontend profile page
 *
 * 7. Multisite Admin Bar Control
 *    - Option to hide "My Sites" menu from admin bar
 *    - Configurable per-site in multisite installations
 *    - Only appears in settings when multisite is active
 *
 * SECURITY CONSIDERATIONS
 * =======================
 * - WordPress nonces for form validation
 * - Current password required for password changes
 * - Email change requires confirmation
 * - All input sanitized with appropriate WordPress functions
 * - File upload restricted to images only
 * - Capability checks prevent unauthorized access
 *
 * SHORTCODE USAGE
 * ===============
 * [frontend_profile]
 * - Must be logged in to view
 * - Displays complete profile editing form
 * - Handles form submission via POST
 * - Shows success/error messages via transients
 *
 * @package Custom_Secure_Auth
 * @since 2.1.0
 * @version 2.1.0
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * CSA_Profile_Editor Class
 *
 * Manages all frontend user profile editing functionality including
 * avatar uploads, email changes, password updates, and language preferences.
 */
class CSA_Profile_Editor {

    /**
     * Plugin settings array
     *
     * Contains profile editor configuration including:
     * - Enabled fields (display_name, website, language, bio, etc.)
     * - Default language setting
     * - Member directory default visibility
     *
     * @var array
     */
    private $settings;

    /**
     * Constructor
     *
     * Loads settings and initializes all WordPress hooks.
     */
    public function __construct() {
        $this->settings = get_option(CSA_SETTINGS_SLUG, array());
        $this->init_hooks();
    }

    /**
     * Initialize WordPress hooks
     */
    private function init_hooks() {
        // Register custom image size for profile avatars
        add_action('after_setup_theme', array($this, 'register_avatar_size'));

        // Register shortcode
        add_shortcode('frontend_profile', array($this, 'render_profile_form'));

        // Handle email confirmation
        add_action('init', array($this, 'handle_email_confirmation'));

        // Redirect non-admin users from wp-admin profile
        add_action('init', array($this, 'redirect_profile_page'));

        // Set default meta for new users
        add_action('user_register', array($this, 'set_new_user_defaults'));

        // Filter locale for logged-in users
        add_filter('locale', array($this, 'filter_user_locale'), 20);

        // Override avatar with custom user avatar
        add_filter('get_avatar', array($this, 'get_custom_avatar'), 10, 5);

        // GTranslate integration
        add_action('wp_footer', array($this, 'gtranslate_integration'));

        // Enqueue assets
        add_action('wp_enqueue_scripts', array($this, 'enqueue_assets'));

        // Hide "My Sites" from admin bar if enabled
        add_action('admin_bar_menu', array($this, 'hide_my_sites_from_admin_bar'), 999);
    }

    /**
     * Register custom image size for avatars
     */
    public function register_avatar_size() {
        add_image_size('profile-avatar', 200, 200, true);
    }

    /**
     * Enqueue frontend assets
     */
    public function enqueue_assets() {
        wp_enqueue_style(
            'csa-profile-editor',
            plugin_dir_url(dirname(__FILE__)) . 'assets/css/profile-editor.css',
            array(),
            '2.1.0'
        );
    }

    /**
     * Get profile settings
     *
     * @return array Profile editor settings
     */
    private function get_profile_settings() {
        return isset($this->settings['profile_editor']) ? $this->settings['profile_editor'] : array();
    }

    /**
     * Render frontend profile form
     *
     * @return string Profile form HTML
     */
    public function render_profile_form() {
        if (!is_user_logged_in()) {
            return '<p>' . esc_html__('Please log in to view your profile.', 'custom-secure-auth') . '</p>';
        }

        $current_user_id = get_current_user_id();
        $transient_key = 'profile_msg_' . $current_user_id;

        // Retrieve and immediately clear the message from the transient
        $message = get_transient($transient_key);
        if ($message) {
            delete_transient($transient_key);
        } else {
            $message = '';
        }

        $current_user = get_user_by('id', $current_user_id);
        $options = $this->get_profile_settings();

        // Handle form submission
        if (isset($_POST['update_profile']) && wp_verify_nonce($_POST['profile_nonce'], 'update_profile_nonce')) {
            $message = $this->process_profile_update($current_user, $options);
            set_transient($transient_key, $message, 30);
            wp_redirect(remove_query_arg(array('updated')));
            exit;
        }

        $avatar_id = get_user_meta($current_user->ID, 'user_avatar', true);

        ob_start();
        ?>
        <div class="csa-profile-container">
            <?php echo $message; ?>

            <form method="post" enctype="multipart/form-data" class="csa-profile-form">
                <?php wp_nonce_field('update_profile_nonce', 'profile_nonce'); ?>

                <div class="csa-avatar-section">
                    <?php
                    if ($avatar_id) {
                        echo wp_get_attachment_image($avatar_id, 'profile-avatar');
                    } else {
                        echo get_avatar($current_user->ID, 200);
                    }
                    ?>
                    <label for="file-upload" class="csa-custom-file-upload">
                        <?php _e('Change Avatar', 'custom-secure-auth'); ?>
                    </label>
                    <input id="file-upload" type="file" name="avatar" accept="image/*">
                </div>

                <div class="csa-form-row">
                    <label for="username"><?php _e('Username', 'custom-secure-auth'); ?></label>
                    <?php
                    $role_names = array();
                    if (!empty($current_user->roles)) {
                        $wp_roles = wp_roles();
                        foreach ($current_user->roles as $role_slug) {
                            if (isset($wp_roles->role_names[$role_slug])) {
                                $role_names[] = translate_user_role($wp_roles->role_names[$role_slug]);
                            }
                        }
                    }
                    $display_roles = !empty($role_names) ? implode(', ', $role_names) : __('No role', 'custom-secure-auth');
                    $combined_display = sprintf('%s (%s)', $current_user->user_login, $display_roles);
                    ?>
                    <input type="text" name="username" id="username" value="<?php echo esc_attr($combined_display); ?>" disabled>
                </div>

                <div class="csa-form-row">
                    <label for="first_name"><?php _e('First Name', 'custom-secure-auth'); ?></label>
                    <input type="text" name="first_name" id="first_name" value="<?php echo esc_attr($current_user->first_name); ?>">
                </div>

                <div class="csa-form-row">
                    <label for="last_name"><?php _e('Last Name', 'custom-secure-auth'); ?></label>
                    <input type="text" name="last_name" id="last_name" value="<?php echo esc_attr($current_user->last_name); ?>">
                </div>

                <div class="csa-form-row">
                    <label for="email"><?php _e('Email', 'custom-secure-auth'); ?></label>
                    <input type="email" name="email" id="email" value="<?php echo esc_attr($current_user->user_email); ?>">
                </div>

                <?php if (!empty($options['enable_display_name'])) : ?>
                    <div class="csa-form-row">
                        <label for="display_name"><?php _e('Display name publicly as', 'custom-secure-auth'); ?></label>
                        <select name="display_name" id="display_name">
                            <?php
                            $public_display = array();
                            $public_display['display_username'] = $current_user->user_login;
                            $public_display['display_nickname'] = $current_user->nickname;

                            if (!empty($current_user->first_name)) {
                                $public_display['display_firstname'] = $current_user->first_name;
                            }

                            if (!empty($current_user->last_name)) {
                                $public_display['display_lastname'] = $current_user->last_name;
                            }

                            if (!empty($current_user->first_name) && !empty($current_user->last_name)) {
                                $public_display['display_firstlast'] = $current_user->first_name . ' ' . $current_user->last_name;
                                $public_display['display_lastfirst'] = $current_user->last_name . ' ' . $current_user->first_name;
                            }

                            if (!in_array($current_user->display_name, $public_display)) {
                                $public_display['display_archive'] = $current_user->display_name;
                            }

                            $public_display = array_unique($public_display);

                            foreach ($public_display as $id => $item) {
                                ?>
                                <option <?php selected($current_user->display_name, $item); ?>><?php echo esc_html($item); ?></option>
                                <?php
                            }
                            ?>
                        </select>
                    </div>
                <?php endif; ?>

                <?php if (!empty($options['enable_website'])) : ?>
                    <div class="csa-form-row">
                        <label for="website"><?php _e('Website', 'custom-secure-auth'); ?></label>
                        <input type="url" name="website" id="website" value="<?php echo esc_url($current_user->user_url); ?>">
                    </div>
                <?php endif; ?>

                <?php if (!empty($options['enable_language'])) : ?>
                    <div class="csa-form-row">
                        <label for="locale"><?php _e('Language', 'custom-secure-auth'); ?></label>
                        <?php
                        $user_locale = get_user_meta($current_user->ID, 'locale', true);
                        if (!function_exists('wp_get_available_translations')) {
                            require_once ABSPATH . 'wp-admin/includes/translation-install.php';
                        }
                        $languages = get_available_languages();
                        $translations = wp_get_available_translations();
                        ?>
                        <select name="locale" id="locale">
                            <?php
                            $default_lang = isset($options['default_language']) ? $options['default_language'] : 'en_US';
                            $default_lang_name = 'English (United States)';
                            if ($default_lang !== 'en_US') {
                                foreach ($translations as $translation) {
                                    if ($translation['language'] === $default_lang) {
                                        $default_lang_name = $translation['native_name'];
                                        break;
                                    }
                                }
                            }
                            ?>
                            <option value="site-default" <?php selected($user_locale, ''); ?>><?php printf(__('Site Default (%s)', 'custom-secure-auth'), $default_lang_name); ?></option>
                            <option value="en_US" <?php selected($user_locale, 'en_US'); ?>>English (United States)</option>
                            <?php
                            foreach ($translations as $translation) {
                                $selected = selected($user_locale, $translation['language'], false);
                                echo '<option value="' . esc_attr($translation['language']) . '" ' . $selected . '>' . esc_html($translation['native_name']) . '</option>';
                            }
                            ?>
                        </select>
                    </div>
                <?php endif; ?>

                <?php if (!empty($options['enable_bio'])) : ?>
                    <div class="csa-form-row">
                        <label for="bio"><?php _e('Bio', 'custom-secure-auth'); ?></label>
                        <textarea name="bio" id="bio"><?php echo esc_textarea($current_user->description); ?></textarea>
                    </div>
                <?php endif; ?>

                <?php if (!empty($options['enable_member_directory'])) : ?>
                    <div class="csa-form-row csa-checkbox-row">
                        <?php
                        $show_in_dir = get_user_meta($current_user->ID, 'show_in_member_directory', true);
                        ?>
                        <input type="checkbox" name="show_in_directory" id="show_in_directory" value="1" <?php checked($show_in_dir, '1'); ?>>
                        <label for="show_in_directory"><?php _e('Show in member directory', 'custom-secure-auth'); ?></label>
                    </div>
                <?php endif; ?>

                <div class="csa-form-row">
                    <label for="current_password"><?php _e('Current Password', 'custom-secure-auth'); ?></label>
                    <input type="password" name="current_password" id="current_password">
                </div>

                <div class="csa-form-row">
                    <label for="new_password"><?php _e('New Password', 'custom-secure-auth'); ?></label>
                    <input type="password" name="new_password" id="new_password">
                </div>

                <div class="csa-form-row">
                    <input type="submit" name="update_profile" value="<?php _e('Update Profile', 'custom-secure-auth'); ?>" class="et_pb_button">
                </div>
            </form>
        </div>
        <?php
        return ob_get_clean();
    }

    /**
     * Process profile update
     *
     * @param WP_User $current_user Current user object
     * @param array $options Profile settings
     * @return string Status message HTML
     */
    private function process_profile_update($current_user, $options) {
        $new_email = sanitize_email($_POST['email']);
        $error_occurred = false;
        $status_message = '';

        $user_data = array(
            'ID' => $current_user->ID,
            'first_name' => sanitize_text_field($_POST['first_name']),
            'last_name' => sanitize_text_field($_POST['last_name']),
        );

        if (!empty($options['enable_bio'])) {
            $user_data['description'] = sanitize_textarea_field($_POST['bio']);
        }

        if (!empty($options['enable_display_name']) && !empty($_POST['display_name'])) {
            $user_data['display_name'] = sanitize_text_field($_POST['display_name']);
        } else {
            $user_data['display_name'] = sprintf(
                '%s %s',
                sanitize_text_field($_POST['first_name']),
                sanitize_text_field($_POST['last_name'])
            );
        }

        if (!empty($options['enable_website'])) {
            $user_data['user_url'] = esc_url_raw($_POST['website']);
        }

        if (!empty($options['enable_language'])) {
            $new_locale = sanitize_text_field($_POST['locale']);
            if ($new_locale === 'site-default') {
                $new_locale = ''; // Clear it to use site/plugin default
            }
            update_user_meta($current_user->ID, 'locale', $new_locale);
        }

        if (!empty($options['enable_member_directory'])) {
            $show_in_dir = isset($_POST['show_in_directory']) ? '1' : '0';
            update_user_meta($current_user->ID, 'show_in_member_directory', $show_in_dir);
        }

        // Email Change Logic
        if ($new_email !== $current_user->user_email) {
            if (email_exists($new_email) && email_exists($new_email) != $current_user->ID) {
                $status_message = '<div class="csa-error">' . __('This email is already in use.', 'custom-secure-auth') . '</div>';
                $error_occurred = true;
            } else {
                if (is_multisite()) {
                    $hash = md5($new_email . time() . wp_generate_password(20, false));
                    update_user_meta($current_user->ID, '_new_email', array('hash' => $hash, 'newemail' => $new_email));

                    $email_text = __("Hi, \n\nPlease click the link below to confirm your new email: \n###LINK###", 'custom-secure-auth');
                    wp_mail(
                        $new_email,
                        sprintf(__('[%s] Confirm Email Change', 'custom-secure-auth'), get_option('blogname')),
                        str_replace('###LINK###', esc_url(add_query_arg(array('newuseremailconfirm' => $hash), home_url('/'))), $email_text)
                    );
                    $status_message = '<div class="csa-success">' . __('A confirmation email has been sent to your new address.', 'custom-secure-auth') . '</div>';
                } else {
                    $_POST['email'] = $new_email;
                    send_confirmation_on_profile_email();
                    $status_message = '<div class="csa-success">' . __('A confirmation email has been sent to your new address.', 'custom-secure-auth') . '</div>';
                }
                $user_data['user_email'] = $current_user->user_email; // Keep old email for now
            }
        }

        // Password Change Logic
        if (!$error_occurred && !empty($_POST['new_password'])) {
            if (wp_check_password($_POST['current_password'], $current_user->user_pass, $current_user->ID)) {
                $user_data['user_pass'] = $_POST['new_password'];
            } else {
                $status_message = '<div class="csa-error">' . __('Current password is incorrect.', 'custom-secure-auth') . '</div>';
                $error_occurred = true;
            }
        }

        // Process Update
        if (!$error_occurred) {
            $user_id = wp_update_user($user_data);

            if (is_wp_error($user_id)) {
                $status_message = '<div class="csa-error">' . $user_id->get_error_message() . '</div>';
            } else {
                // Avatar Upload logic
                if (isset($_FILES['avatar']) && $_FILES['avatar']['size'] > 0) {
                    $status_message = $this->handle_avatar_upload($current_user->ID, $status_message);
                }

                if (empty($status_message)) {
                    $status_message = '<div class="csa-success">' . __('Profile updated successfully!', 'custom-secure-auth') . '</div>';
                }
            }
        }

        return $status_message;
    }

    /**
     * Handle avatar upload
     *
     * @param int $user_id User ID
     * @param string $existing_message Existing status message
     * @return string Status message
     */
    private function handle_avatar_upload($user_id, $existing_message) {
        require_once(ABSPATH . 'wp-admin/includes/image.php');
        require_once(ABSPATH . 'wp-admin/includes/file.php');
        require_once(ABSPATH . 'wp-admin/includes/media.php');

        add_filter('intermediate_image_sizes_advanced', array($this, 'remove_other_image_sizes'));
        $attachment_id = media_handle_upload('avatar', 0);
        remove_filter('intermediate_image_sizes_advanced', array($this, 'remove_other_image_sizes'));

        if (!is_wp_error($attachment_id)) {
            $old_avatar_id = get_user_meta($user_id, 'user_avatar', true);
            if ($old_avatar_id) {
                wp_delete_attachment($old_avatar_id, true);
            }
            update_user_meta($user_id, 'user_avatar', $attachment_id);
        }

        return $existing_message;
    }

    /**
     * Remove other image sizes during avatar upload
     *
     * @param array $sizes Image sizes
     * @return array Modified sizes
     */
    public function remove_other_image_sizes($sizes) {
        // Only keep profile-avatar size for avatar uploads
        if (!empty($_FILES['avatar'])) {
            return array('profile-avatar' => isset($sizes['profile-avatar']) ? $sizes['profile-avatar'] : array());
        }
        return $sizes;
    }

    /**
     * Handle email confirmation from link
     */
    public function handle_email_confirmation() {
        if (!isset($_GET['newuseremailconfirm'])) {
            return;
        }

        $hash = sanitize_text_field($_GET['newuseremailconfirm']);
        $user_id = get_current_user_id();

        if (!$user_id) {
            return;
        }

        $new_email_data = get_user_meta($user_id, '_new_email', true);

        if ($new_email_data && $new_email_data['hash'] === $hash) {
            $new_email = $new_email_data['newemail'];

            // Update the user's email
            wp_update_user(array(
                'ID' => $user_id,
                'user_email' => $new_email
            ));

            // Clean up the meta
            delete_user_meta($user_id, '_new_email');

            // Set a success message
            set_transient('profile_msg_' . $user_id, '<div class="csa-success">' . __('Email updated successfully!', 'custom-secure-auth') . '</div>', 30);

            // Get profile page from settings
            $page_mapping = isset($this->settings['page_mapping']) ? $this->settings['page_mapping'] : array();
            $profile_page_id = isset($page_mapping['profile_page']) ? $page_mapping['profile_page'] : 0;

            if ($profile_page_id) {
                $redirect_url = get_permalink($profile_page_id);
            } else {
                // Fallback to hardcoded slug if not configured
                $profile_page = get_page_by_path('my-profile');
                $redirect_url = $profile_page ? get_permalink($profile_page) : home_url();
            }

            wp_safe_redirect($redirect_url);
            exit;
        }
    }

    /**
     * Redirect non-admin users from wp-admin profile
     */
    public function redirect_profile_page() {
        if (!is_admin() || wp_doing_ajax()) {
            return;
        }

        $current_user = wp_get_current_user();
        if (!$current_user || current_user_can('manage_options')) {
            return;
        }

        if (strpos($_SERVER['REQUEST_URI'], 'profile.php') !== false ||
            strpos($_SERVER['REQUEST_URI'], 'user-edit.php') !== false) {

            // Get profile page from settings
            $page_mapping = isset($this->settings['page_mapping']) ? $this->settings['page_mapping'] : array();
            $profile_page_id = isset($page_mapping['profile_page']) ? $page_mapping['profile_page'] : 0;

            if ($profile_page_id) {
                $redirect_url = get_permalink($profile_page_id);
            } else {
                // Fallback to hardcoded slug if not configured
                $profile_page = get_page_by_path('my-profile');
                $redirect_url = $profile_page ? get_permalink($profile_page) : home_url();
            }

            wp_safe_redirect($redirect_url);
            exit;
        }
    }

    /**
     * Set default meta for new users
     *
     * @param int $user_id User ID
     */
    public function set_new_user_defaults($user_id) {
        $options = $this->get_profile_settings();
        if (!empty($options['default_show_in_directory'])) {
            update_user_meta($user_id, 'show_in_member_directory', '1');
        }
    }

    /**
     * Filter locale for logged-in users
     *
     * @param string $locale Current locale
     * @return string Filtered locale
     */
    public function filter_user_locale($locale) {
        if (is_admin()) {
            return $locale;
        }

        $user_id = get_current_user_id();
        if (!$user_id) {
            // Fallback to plugin default language if set
            $options = $this->get_profile_settings();
            if (!empty($options['default_language'])) {
                return $options['default_language'];
            }
            return $locale;
        }

        $user_locale = get_user_meta($user_id, 'locale', true);
        if ($user_locale) {
            return $user_locale;
        }

        // Fallback to plugin default language if set
        $options = $this->get_profile_settings();
        if (!empty($options['default_language'])) {
            return $options['default_language'];
        }

        return $locale;
    }

    /**
     * Override default avatar with custom user avatar
     *
     * @param string $avatar Default avatar HTML
     * @param mixed $id_or_email User ID, email, or object
     * @param int $size Avatar size
     * @param string $default Default avatar URL
     * @param string $alt Alt text
     * @return string Avatar HTML
     */
    public function get_custom_avatar($avatar, $id_or_email, $size, $default, $alt) {
        // Get user ID based on the provided id_or_email
        $user_id = 0;
        if (is_numeric($id_or_email)) {
            $user_id = $id_or_email;
        } elseif (is_string($id_or_email)) {
            $user = get_user_by('email', $id_or_email);
            $user_id = $user ? $user->ID : 0;
        } elseif (is_object($id_or_email)) {
            if (!empty($id_or_email->user_id)) {
                $user_id = $id_or_email->user_id;
            } elseif (!empty($id_or_email->comment_author_email)) {
                $user = get_user_by('email', $id_or_email->comment_author_email);
                $user_id = $user ? $user->ID : 0;
            }
        }

        // If we have a user ID, check for custom avatar
        if ($user_id) {
            $avatar_id = get_user_meta($user_id, 'user_avatar', true);
            if ($avatar_id) {
                $image_url = wp_get_attachment_image_url($avatar_id, 'profile-avatar');
                if ($image_url) {
                    $avatar = "<img alt='{$alt}' src='{$image_url}' class='avatar avatar-{$size} photo' height='{$size}' width='{$size}' />";
                }
            }
        }

        return $avatar;
    }

    /**
     * GTranslate integration for automatic language switching
     *
     * Automatically switches GTranslate to user's preferred language when they
     * visit the site. This creates a seamless multilingual experience.
     *
     * How It Works:
     * -------------
     * 1. Check if user is logged in (anonymous users use site default)
     * 2. Get user's language preference from user meta
     * 3. Verify GTranslate plugin is active
     * 4. Map WordPress locale to GTranslate language code
     * 5. Inject JavaScript to trigger GTranslate's doGTranslate() function
     * 6. Skip if user's language matches site default (no translation needed)
     *
     * Locale Mapping:
     * ---------------
     * WordPress uses locales like "en_US", "es_ES", "pt_BR"
     * GTranslate uses two-letter codes like "en", "es", "pt"
     *
     * Special cases:
     * - zh_CN → zh-CN (Simplified Chinese)
     * - zh_TW → zh-TW (Traditional Chinese)
     * - pt_BR → pt (Brazilian Portuguese)
     *
     * GTranslate Detection:
     * ---------------------
     * 1. Check for GTRANSLATE_VERSION constant (most reliable)
     * 2. Check if gtranslate/gtranslate.php is active
     * 3. Check if GTranslate class exists (fallback)
     *
     * JavaScript Execution:
     * ---------------------
     * - Waits for window load event to ensure GTranslate is initialized
     * - Checks for googtrans cookie to prevent infinite translation loops
     * - Only triggers if user's language not already active
     * - Uses jQuery for cross-browser compatibility
     *
     * Cookie Check Rationale:
     * -----------------------
     * GTranslate sets a "googtrans" cookie when translation is active.
     * We check this cookie to avoid re-triggering translation on every page load,
     * which would cause performance issues and potential infinite loops.
     *
     * @since 2.1.0
     * @return void
     */
    public function gtranslate_integration() {
        if (!is_user_logged_in()) {
            return;
        }

        $user_id = get_current_user_id();
        $user_locale = get_user_meta($user_id, 'locale', true);

        if (!$user_locale) {
            return;
        }

        // Check if GTranslate is active
        if (!defined('GTRANSLATE_VERSION')) {
            if (!function_exists('is_plugin_active')) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            if (!is_plugin_active('gtranslate/gtranslate.php')) {
                // Double check if the class exists as a fallback
                if (!class_exists('GTranslate')) {
                    return;
                }
            }
        }

        // Map WordPress locale to GTranslate language code
        $gt_lang = substr($user_locale, 0, 2);
        if ($user_locale === 'zh_CN') $gt_lang = 'zh-CN';
        if ($user_locale === 'zh_TW') $gt_lang = 'zh-TW';
        if ($user_locale === 'pt_BR') $gt_lang = 'pt';

        // Get GTranslate settings to find the default language
        $gt_settings = get_option('gtranslate');
        $default_lang = isset($gt_settings['default_language']) ? $gt_settings['default_language'] : 'en';

        if ($gt_lang === $default_lang) {
            return;
        }

        ?>
        <script type="text/javascript">
            jQuery(window).on('load', function() {
                if (typeof doGTranslate === 'function') {
                    var gt_default = <?php echo json_encode($default_lang); ?>;
                    var gt_target = <?php echo json_encode($gt_lang); ?>;
                    // Check if already translated to avoid infinite loops
                    if (document.cookie.indexOf('googtrans') === -1 || document.cookie.indexOf(gt_target) === -1) {
                        doGTranslate(gt_default + '|' + gt_target);
                    }
                }
            });
        </script>
        <?php
    }

    /**
     * Hide "My Sites" from admin bar
     *
     * Removes the "My Sites" menu from the WordPress admin bar when enabled
     * in the plugin settings. This only applies to multisite installations and
     * does not affect administrators or editors.
     *
     * @since 2.1.0
     * @param WP_Admin_Bar $wp_admin_bar The WP_Admin_Bar instance
     * @return void
     */
    public function hide_my_sites_from_admin_bar($wp_admin_bar) {
        // Only applicable for multisite installations
        if (!is_multisite()) {
            return;
        }

        // Don't hide for administrators or editors
        if (current_user_can('manage_options') || current_user_can('edit_pages')) {
            return;
        }

        // Get profile settings
        $options = $this->get_profile_settings();

        // Check if hiding "My Sites" is enabled
        if (!empty($options['hide_my_sites'])) {
            $wp_admin_bar->remove_node('my-sites');
        }
    }
}
