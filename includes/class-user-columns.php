<?php
/**
 * User Columns Manager
 *
 * Adds custom columns to the Users list table in wp-admin.
 * Only loads for admin users with manage_options capability.
 *
 * @package Custom_Secure_Auth
 * @since 2.1.0
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class CSA_User_Columns {

    private static $instance = null;

    public static function instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        // Only load admin columns for users with manage_options capability
        if (is_admin() && current_user_can('manage_options')) {
            $this->init_hooks();
        }
    }

    /**
     * Initialize WordPress hooks
     */
    private function init_hooks() {
        // Add custom columns to Users table
        add_filter('manage_users_columns', array($this, 'add_user_columns'));
        add_action('manage_users_custom_column', array($this, 'populate_user_columns'), 10, 3);

        // Make columns sortable
        add_filter('manage_users_sortable_columns', array($this, 'make_columns_sortable'));
        add_action('pre_get_users', array($this, 'handle_column_sorting'));
    }

    /**
     * Track user login time (static method to ensure it always runs)
     * Hooked to set_auth_cookie to catch both traditional and REST API logins
     * Stores timestamp in UTC to match WordPress core behavior (user_registered)
     *
     * @param string $cookie Auth cookie value (unused)
     * @param int $expire Cookie expiration time (unused)
     * @param int $expiration Session expiration timestamp (unused)
     * @param int $user_id User ID
     * @param string $scheme Authentication scheme (unused)
     */
    public static function track_user_login($cookie, $expire, $expiration, $user_id, $scheme) {
        update_user_meta($user_id, 'last_login', gmdate('Y-m-d H:i:s'));
    }

    /**
     * Add custom columns to Users table
     *
     * @param array $columns Existing columns
     * @return array Modified columns
     */
    public function add_user_columns($columns) {
        $columns['date_created'] = __('Date Created', 'custom-secure-auth');
        $columns['last_login'] = __('Last Login', 'custom-secure-auth');
        $columns['reset_active'] = __('Reset Active', 'custom-secure-auth');
        return $columns;
    }

    /**
     * Populate custom columns with data
     *
     * @param string $output Custom column output (empty string by default)
     * @param string $column_name Name of the column
     * @param int $user_id ID of the user
     * @return string Column content
     */
    public function populate_user_columns($output, $column_name, $user_id) {
        switch ($column_name) {
            case 'date_created':
                $user = get_userdata($user_id);
                if (!$user || empty($user->user_registered) || $user->user_registered === '0000-00-00 00:00:00') {
                    return '—';
                }
                return $this->format_time_display($user->user_registered);

            case 'last_login':
                $last_login = get_user_meta($user_id, 'last_login', true);
                return $this->format_time_display($last_login);

            case 'reset_active':
                $user = get_userdata($user_id);
                // user_activation_key is only populated when a reset request is active
                if ($user && !empty($user->user_activation_key)) {
                    return '<span class="dashicons dashicons-yes" style="color: #46b450;" title="' . esc_attr__('Password reset token is active', 'custom-secure-auth') . '"></span>';
                }
                return '—';
        }
        return $output;
    }

    /**
     * Make columns sortable
     *
     * @param array $columns Existing sortable columns
     * @return array Modified sortable columns
     */
    public function make_columns_sortable($columns) {
        $columns['date_created'] = 'registered';
        $columns['last_login'] = 'last_login';
        return $columns;
    }

    /**
     * Handle column sorting
     *
     * @param WP_User_Query $query User query object
     */
    public function handle_column_sorting($query) {
        if (!is_admin()) {
            return;
        }

        $orderby = $query->get('orderby');

        if ('last_login' === $orderby) {
            $query->set('meta_key', 'last_login');
            $query->set('orderby', 'meta_value');
        }
    }

    /**
     * Format timestamp for display - shows "time ago" for dates within 7 days, otherwise shows formatted date
     *
     * @param string $time_string A MySQL datetime string (stored in UTC in database)
     * @return string The formatted time display string
     */
    private function format_time_display($time_string) {
        if (empty($time_string)) {
            return '—';
        }

        // Convert UTC datetime string to Unix timestamp, then to local time
        $time_utc = strtotime($time_string . ' UTC');
        if ($time_utc === false) {
            return '—'; // Invalid time string
        }

        // Get current time as Unix timestamp (UTC)
        $now_utc = time();
        $diff = $now_utc - $time_utc;

        // Return dash if the time is in the future (with 60 second grace period for clock skew)
        if ($diff < -60) {
            return '—';
        }

        // If older than 7 days, show formatted date in site timezone
        if ($diff > (7 * DAY_IN_SECONDS)) {
            return wp_date(get_option('date_format'), $time_utc);
        }

        // Show "time ago" format for dates within 7 days
        if ($diff < MINUTE_IN_SECONDS) {
            return __('just now', 'custom-secure-auth');
        }

        $days = floor($diff / DAY_IN_SECONDS);
        $hours = floor(($diff % DAY_IN_SECONDS) / HOUR_IN_SECONDS);
        $minutes = floor(($diff % HOUR_IN_SECONDS) / MINUTE_IN_SECONDS);

        // If more than 1 day, show only days.
        if ($days > 1) {
            return sprintf(
                /* translators: %d: number of days */
                _n('%d day ago', '%d days ago', $days, 'custom-secure-auth'),
                $days
            );
        }

        $parts = [];

        // If it's up to 1 day and some hours/minutes
        if ($days == 1) {
            $parts[] = sprintf(
                _n('%d day', '%d days', $days, 'custom-secure-auth'),
                $days
            );
        }

        if ($hours > 0) {
            $parts[] = sprintf(
                _n('%d hour', '%d hours', $hours, 'custom-secure-auth'),
                $hours
            );
        }

        if ($minutes > 0) {
            $parts[] = sprintf(
                _n('%d minute', '%d minutes', $minutes, 'custom-secure-auth'),
                $minutes
            );
        }

        if (empty($parts)) {
            return __('just now', 'custom-secure-auth');
        }

        return implode(' ', $parts) . ' ' . __('ago', 'custom-secure-auth');
    }
}
