/**
 * Custom Secure Auth - Frontend Scripts
 *
 * Handles AJAX form submissions, token fetching, and client-side interactions
 *
 * @package CustomSecureAuth
 */

(function($) {
    'use strict';

    const CSA = {
        /**
         * Initialize on document ready
         */
        init: function() {
            this.fetchToken();
            this.maybeGenerateUsername();
            this.bindEvents();
            this.initPasswordStrength();
            this.initRecaptcha();
        },

        /**
         * Fetch authentication token from REST API
         */
        fetchToken: function() {
            if (!window.csaData || !window.csaData.restUrl) {
                console.warn('CSA: REST URL not available');
                return;
            }

            $.ajax({
                url: window.csaData.restUrl + '/get-token',
                method: 'GET',
                dataType: 'json',
                success: function(response) {
                    if (response.token && response.timestamp) {
                        // Populate hidden token fields in all forms
                        $('input[name="csa_token"]').val(response.token);
                        $('input[name="csa_timestamp"]').val(response.timestamp);
                    }
                },
                error: function(xhr) {
                    console.error('CSA: Failed to fetch token', xhr);
                }
            });
        },

        /**
         * Auto-generate fun username on registration page load
         *
         * Checks if a username field exists in the registration form and is empty,
         * then fetches a generated username from the REST API if the feature is enabled.
         */
        maybeGenerateUsername: function() {
            const $usernameField = $('.csa-fun-username-field');

            if ($usernameField.length && !$usernameField.val()) {
                this.generateUsername($usernameField);
            }
        },

        /**
         * Generate username via REST API
         */
        generateUsername: function($field, callback) {
            if (!window.csaData || !window.csaData.restUrl) {
                if (callback) callback();
                return;
            }

            $.ajax({
                url: window.csaData.restUrl + '/generate-username',
                method: 'GET',
                dataType: 'json',
                success: function(response) {
                    if (response.success && response.username) {
                        $field.val(response.username);
                    }
                    if (callback) callback();
                },
                error: function() {
                    // Silently fail - feature might be disabled
                    if (callback) callback();
                }
            });
        },

        /**
         * Bind event handlers
         */
        bindEvents: function() {
            // Login form
            $(document).on('submit', '#csa-login-form', this.handleLogin.bind(this));

            // Registration form
            $(document).on('submit', '#csa-register-form', this.handleRegister.bind(this));

            // Lost password form
            $(document).on('submit', '#csa-lost-password-form', this.handleLostPassword.bind(this));

            // Set password form
            $(document).on('submit', '#csa-set-password-form', this.handleSetPassword.bind(this));

            // Password visibility toggle
            $(document).on('click', '.csa-toggle-password', this.togglePasswordVisibility);

            // Fun username generator refresh icon
            $(document).on('click', '.csa-username-refresh', function(e) {
                e.preventDefault();
                const $icon = $(e.currentTarget);
                const $field = $('.csa-fun-username-field');
                if ($field.length) {
                    $icon.addClass('csa-username-refresh-spinning');
                    this.generateUsername($field, function() {
                        $icon.removeClass('csa-username-refresh-spinning');
                    });
                }
            }.bind(this));

            // Refresh token periodically (every 5 minutes)
            setInterval(this.fetchToken.bind(this), 300000);
        },

        /**
         * Handle login form submission
         */
        handleLogin: function(e) {
            e.preventDefault();

            const $form = $(e.target);
            const $button = $form.find('button[type="submit"]');
            const formData = this.serializeFormData($form);

            // Clear previous messages
            this.clearMessages($form);

            // Validate
            if (!formData.username || !formData.password) {
                this.showError($form, 'Please enter your username and password.');
                return;
            }

            // Add reCAPTCHA token if enabled
            if (window.csaData.recaptchaEnabled && window.grecaptcha) {
                this.executeRecaptcha('login', function(token) {
                    formData.recaptcha_token = token;
                    this.submitForm($form, $button, '/login', formData);
                }.bind(this));
            } else {
                this.submitForm($form, $button, '/login', formData);
            }
        },

        /**
         * Handle registration form submission
         */
        handleRegister: function(e) {
            e.preventDefault();

            const $form = $(e.target);
            const $button = $form.find('button[type="submit"]');
            const formData = this.serializeFormData($form);

            // Clear previous messages
            this.clearMessages($form);

            // Validate all required fields
            let missingFields = false;
            $form.find('[required]').each(function() {
                const $field = $(this);
                const fieldName = $field.attr('name');
                const fieldValue = formData[fieldName];

                if (!fieldValue || (typeof fieldValue === 'string' && fieldValue.trim() === '')) {
                    missingFields = true;
                    return false; // break the loop
                }
            });

            if (missingFields) {
                this.showError($form, 'Please fill in all required fields.');
                return;
            }

            // Email validation (check for any email field)
            for (let fieldName in formData) {
                const $field = $form.find('[name="' + fieldName + '"]');
                if ($field.attr('type') === 'email' && formData[fieldName]) {
                    if (!this.isValidEmail(formData[fieldName])) {
                        this.showError($form, 'Please enter a valid email address.');
                        return;
                    }
                }
            }

            // Add reCAPTCHA token if enabled
            if (window.csaData.recaptchaEnabled && window.grecaptcha) {
                this.executeRecaptcha('register', function(token) {
                    formData.recaptcha_token = token;
                    this.submitForm($form, $button, '/register', formData);
                }.bind(this));
            } else {
                this.submitForm($form, $button, '/register', formData);
            }
        },

        /**
         * Handle lost password form submission
         */
        handleLostPassword: function(e) {
            e.preventDefault();

            const $form = $(e.target);
            const $button = $form.find('button[type="submit"]');
            const formData = this.serializeFormData($form);

            // Clear previous messages
            this.clearMessages($form);

            // Validate
            if (!formData.user_login) {
                this.showError($form, 'Please enter your username or email address.');
                return;
            }

            // Add reCAPTCHA token if enabled
            if (window.csaData.recaptchaEnabled && window.grecaptcha) {
                this.executeRecaptcha('lostpassword', function(token) {
                    formData.recaptcha_token = token;
                    this.submitForm($form, $button, '/lost-password', formData);
                }.bind(this));
            } else {
                this.submitForm($form, $button, '/lost-password', formData);
            }
        },

        /**
         * Handle set password form submission
         */
        handleSetPassword: function(e) {
            e.preventDefault();

            const $form = $(e.target);
            const $button = $form.find('button[type="submit"]');
            const formData = this.serializeFormData($form);

            // Clear previous messages
            this.clearMessages($form);

            // Validate
            if (!formData.password || !formData.password_confirm) {
                this.showError($form, 'Please enter and confirm your new password.');
                return;
            }

            // Password confirmation
            if (formData.password !== formData.password_confirm) {
                this.showError($form, 'Passwords do not match.');
                return;
            }

            this.submitForm($form, $button, '/set-password', formData);
        },

        /**
         * Submit form via AJAX
         */
        submitForm: function($form, $button, endpoint, data) {
            // Disable form
            $button.addClass('csa-button-loading').prop('disabled', true);
            $form.addClass('csa-loading');

            $.ajax({
                url: window.csaData.restUrl + endpoint,
                method: 'POST',
                dataType: 'json',
                data: data,
                success: function(response) {
                    if (response.success) {
                        this.showSuccess($form, response.message || 'Success!');

                        // Redirect if provided
                        if (response.redirect_url) {
                            setTimeout(function() {
                                window.location.href = response.redirect_url;
                            }, 1000);
                        } else {
                            // No redirect - disable form to prevent resubmission
                            $form.find('input, textarea, select').prop('disabled', true);
                            $button.prop('disabled', true).text('Submitted');
                        }
                    } else {
                        this.showError($form, response.message || 'An error occurred.');
                    }
                }.bind(this),
                error: function(xhr) {
                    let errorMessage = 'An error occurred. Please try again.';

                    if (xhr.responseJSON && xhr.responseJSON.message) {
                        errorMessage = xhr.responseJSON.message;
                    } else if (xhr.status === 429) {
                        errorMessage = 'Too many attempts. Please try again later.';
                    } else if (xhr.status === 403) {
                        errorMessage = 'Access denied. Please refresh and try again.';
                    }

                    this.showError($form, errorMessage);
                }.bind(this),
                complete: function() {
                    // Re-enable form
                    $button.removeClass('csa-button-loading').prop('disabled', false);
                    $form.removeClass('csa-loading');
                }.bind(this)
            });
        },

        /**
         * Serialize form data into object
         */
        serializeFormData: function($form) {
            const formArray = $form.serializeArray();
            const formData = {};

            $.each(formArray, function(i, field) {
                formData[field.name] = field.value;
            });

            return formData;
        },

        /**
         * Show error message
         */
        showError: function($form, message) {
            this.clearMessages($form);

            const $error = $('<div class="csa-message csa-error" role="alert"></div>').text(message);
            $form.prepend($error);

            // Scroll to message
            this.scrollToMessage($error);
        },

        /**
         * Show success message
         */
        showSuccess: function($form, message) {
            this.clearMessages($form);

            const $success = $('<div class="csa-message csa-success" role="status"></div>').text(message);
            $form.prepend($success);

            // Scroll to message
            this.scrollToMessage($success);
        },

        /**
         * Clear all messages
         */
        clearMessages: function($form) {
            $form.find('.csa-message').remove();
            $form.find('.csa-field-error').remove();
            $form.find('.csa-form-field').removeClass('has-error');
        },

        /**
         * Scroll to message
         */
        scrollToMessage: function($element) {
            if ($element.length) {
                $('html, body').animate({
                    scrollTop: $element.offset().top - 100
                }, 300);
            }
        },

        /**
         * Validate email address
         */
        isValidEmail: function(email) {
            const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            return regex.test(email);
        },

        /**
         * Toggle password visibility
         */
        togglePasswordVisibility: function(e) {
            e.preventDefault();

            const $button = $(this);
            const $input = $button.closest('.csa-form-field').find('input[type="password"], input[type="text"]');

            if ($input.attr('type') === 'password') {
                $input.attr('type', 'text');
                $button.text('Hide');
            } else {
                $input.attr('type', 'password');
                $button.text('Show');
            }
        },

        /**
         * Initialize password strength indicator
         */
        initPasswordStrength: function() {
            $(document).on('input', 'input[name="password"]', function() {
                const $input = $(this);
                const password = $input.val();
                const $strength = $input.siblings('.csa-password-strength');

                if (!$strength.length) {
                    return;
                }

                const strength = CSA.checkPasswordStrength(password);

                $strength
                    .removeClass('weak medium strong')
                    .addClass(strength.class);

                $strength.find('.csa-password-strength-text').text(strength.text);
            });
        },

        /**
         * Check password strength
         */
        checkPasswordStrength: function(password) {
            let strength = 0;

            if (password.length >= 8) strength++;
            if (password.length >= 12) strength++;
            if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
            if (/\d/.test(password)) strength++;
            if (/[^a-zA-Z\d]/.test(password)) strength++;

            if (strength < 2) {
                return { class: 'weak', text: 'Weak' };
            } else if (strength < 4) {
                return { class: 'medium', text: 'Medium' };
            } else {
                return { class: 'strong', text: 'Strong' };
            }
        },

        /**
         * Initialize reCAPTCHA v3
         */
        initRecaptcha: function() {
            if (!window.csaData.recaptchaEnabled || !window.csaData.recaptchaSiteKey) {
                return;
            }

            // Load reCAPTCHA script if not already loaded
            if (typeof grecaptcha === 'undefined') {
                const script = document.createElement('script');
                script.src = 'https://www.google.com/recaptcha/api.js?render=' + window.csaData.recaptchaSiteKey;
                script.async = true;
                script.defer = true;
                document.head.appendChild(script);
            }
        },

        /**
         * Execute reCAPTCHA and get token
         */
        executeRecaptcha: function(action, callback) {
            if (typeof grecaptcha === 'undefined' || !window.csaData.recaptchaSiteKey) {
                callback('');
                return;
            }

            grecaptcha.ready(function() {
                grecaptcha.execute(window.csaData.recaptchaSiteKey, { action: action })
                    .then(function(token) {
                        callback(token);
                    })
                    .catch(function(error) {
                        console.error('reCAPTCHA error:', error);
                        callback('');
                    });
            });
        }
    };

    // Initialize on document ready
    $(document).ready(function() {
        CSA.init();
    });

    // Expose to global scope for external use
    window.CSA = CSA;

})(jQuery);
