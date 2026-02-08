/**
 * Custom Secure Auth - Admin Scripts
 *
 * Handles tab navigation, grid builder, and settings page interactions
 *
 * @package CustomSecureAuth
 */

(function($) {
    'use strict';

    const CSA_Admin = {
        /**
         * Initialize on document ready
         */
        init: function() {
            // Don't init tabs - PHP uses server-side tab navigation
            // this.initTabs();
            this.initGridBuilder();
            this.initFormValidation();
            this.initCodeCopy();
            this.bindEvents();
        },

        /**
         * Initialize tab navigation
         */
        initTabs: function() {
            const $tabs = $('.nav-tab');
            const $tabContents = $('.csa-tab-content');

            // Show first tab by default or hash tab
            const hash = window.location.hash.substring(1);
            let $activeTab;

            if (hash) {
                $activeTab = $tabs.filter('[data-tab="' + hash + '"]');
            }

            if (!$activeTab || !$activeTab.length) {
                $activeTab = $tabs.first();
            }

            this.showTab($activeTab.data('tab'));

            // Tab click handler
            $tabs.on('click', function(e) {
                e.preventDefault();
                const tabId = $(this).data('tab');
                CSA_Admin.showTab(tabId);

                // Update URL hash
                window.location.hash = tabId;
            });

            // Handle browser back/forward
            $(window).on('hashchange', function() {
                const hash = window.location.hash.substring(1);
                if (hash) {
                    CSA_Admin.showTab(hash);
                }
            });
        },

        /**
         * Show specific tab
         */
        showTab: function(tabId) {
            const $tabs = $('.nav-tab');
            const $tabContents = $('.csa-tab-content');

            // Update tab states
            $tabs.removeClass('nav-tab-active');
            $tabs.filter('[data-tab="' + tabId + '"]').addClass('nav-tab-active');

            // Update content visibility
            $tabContents.removeClass('active');
            $('#' + tabId).addClass('active');
        },

        /**
         * Initialize grid builder functionality
         */
        initGridBuilder: function() {
            // Check if we have Grid Builder data
            if (typeof csaGridBuilder === 'undefined') {
                return;
            }

            // Initialize field index
            this.fieldIndex = csaGridBuilder.fieldIndex || 0;
            this.presets = csaGridBuilder.presets || {};
            this.i18n = csaGridBuilder.i18n || {};

            // Make fields sortable
            $('#csa-grid-fields-container').sortable({
                handle: '.csa-grid-field-handle',
                placeholder: 'csa-grid-field-placeholder',
                cursor: 'move',
                opacity: 0.8
            });

            // Add preset field
            $(document).on('click', '.csa-preset-btn', this.addPresetField.bind(this));

            // Add custom field
            $(document).on('click', '#csa-add-field', this.addCustomField.bind(this));

            // Remove field button
            $(document).on('click', '.csa-remove-field', this.removeGridBuilderField.bind(this));

            // Auto-generate ID from label
            $(document).on('blur', '.csa-grid-field-label', this.autoGenerateGridFieldId.bind(this));

            // Update help text when field type changes
            $(document).on('change', '.csa-grid-field-type', this.updateFieldTypeHelp.bind(this));

            // Initialize empty state
            this.updateEmptyState();
        },

        /**
         * Update empty state visibility
         */
        updateEmptyState: function() {
            const fieldCount = $('#csa-grid-fields-container .csa-grid-field').length;
            if (fieldCount > 0) {
                $('.csa-empty-state').hide();
            } else {
                $('.csa-empty-state').show();
            }
        },

        /**
         * Add preset field
         */
        addPresetField: function(e) {
            e.preventDefault();

            const $button = $(e.currentTarget);
            const presetName = $button.data('preset');
            const preset = this.presets[presetName];

            if (!preset) return;

            const template = $('#csa-grid-field-template').html();
            const newField = template.replace(/{{INDEX}}/g, this.fieldIndex);
            $('#csa-grid-fields-container').append(newField);

            // Find the newly added field and populate it
            const $newField = $('#csa-grid-fields-container .csa-grid-field').last();
            $newField.find('.csa-grid-field-id').val(preset.id);
            $newField.find('.csa-grid-field-label').val(preset.label);
            $newField.find('.csa-grid-field-placeholder').val(preset.placeholder);
            $newField.find('.csa-grid-field-type').val(preset.type);
            $newField.find('.csa-grid-field-width').val(preset.width);

            if (preset.required) {
                $newField.find('.csa-grid-field-required').prop('checked', true);
            }

            this.fieldIndex++;
            this.updateEmptyState();

            // Scroll to the new field
            $('html, body').animate({
                scrollTop: $newField.offset().top - 100
            }, 500);
        },

        /**
         * Add custom field
         */
        addCustomField: function(e) {
            e.preventDefault();

            const template = $('#csa-grid-field-template').html();
            const newField = template.replace(/{{INDEX}}/g, this.fieldIndex);
            $('#csa-grid-fields-container').append(newField);
            this.fieldIndex++;
            this.updateEmptyState();
        },

        /**
         * Remove grid builder field
         */
        removeGridBuilderField: function(e) {
            e.preventDefault();

            const confirmMsg = this.i18n.confirmRemove || 'Are you sure you want to remove this field?';
            if (confirm(confirmMsg)) {
                $(e.currentTarget).closest('.csa-grid-field').remove();
                this.updateEmptyState();
            }
        },

        /**
         * Auto-generate ID from label for grid builder
         */
        autoGenerateGridFieldId: function(e) {
            const $labelInput = $(e.currentTarget);
            const $field = $labelInput.closest('.csa-grid-field');
            const $idInput = $field.find('.csa-grid-field-id');

            // Only auto-generate if ID is empty
            if ($idInput.val() === '') {
                const label = $labelInput.val();
                const id = label.toLowerCase()
                    .replace(/[^a-z0-9]+/g, '_')
                    .replace(/^_+|_+$/g, '');
                $idInput.val(id);
            }
        },

        /**
         * Update help text when field type changes
         */
        updateFieldTypeHelp: function(e) {
            const $select = $(e.currentTarget);
            const $field = $select.closest('.csa-grid-field');
            const selectedType = $select.val();
            const $helpText = $field.find('.csa-field-type-help');

            const helpTexts = this.i18n.helpTexts || {};

            if (helpTexts[selectedType]) {
                $helpText.text(helpTexts[selectedType]);
            }
        },

        /**
         * Initialize form validation
         */
        initFormValidation: function() {
            $('form.csa-settings-form').on('submit', function(e) {
                const $form = $(this);
                let isValid = true;

                // Clear previous errors
                $form.find('.csa-field-error').remove();

                // Validate required fields
                $form.find('[required]').each(function() {
                    const $input = $(this);

                    if (!$input.val().trim()) {
                        isValid = false;

                        $input.after(
                            '<span class="csa-field-error" style="color: #d63638; font-size: 12px;">This field is required</span>'
                        );

                        if (isValid) {
                            $input.focus();
                        }
                    }
                });

                // Validate email fields
                $form.find('input[type="email"]').each(function() {
                    const $input = $(this);
                    const email = $input.val().trim();

                    if (email && !CSA_Admin.isValidEmail(email)) {
                        isValid = false;

                        $input.after(
                            '<span class="csa-field-error" style="color: #d63638; font-size: 12px;">Please enter a valid email address</span>'
                        );
                    }
                });

                // Validate URL fields
                $form.find('input[type="url"]').each(function() {
                    const $input = $(this);
                    const url = $input.val().trim();

                    if (url && !CSA_Admin.isValidUrl(url)) {
                        isValid = false;

                        $input.after(
                            '<span class="csa-field-error" style="color: #d63638; font-size: 12px;">Please enter a valid URL</span>'
                        );
                    }
                });

                if (!isValid) {
                    e.preventDefault();

                    // Scroll to first error
                    const $firstError = $form.find('.csa-field-error').first();
                    if ($firstError.length) {
                        $('html, body').animate({
                            scrollTop: $firstError.offset().top - 100
                        }, 300);
                    }
                }
            });
        },

        /**
         * Validate email address
         */
        isValidEmail: function(email) {
            const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            return regex.test(email);
        },

        /**
         * Validate URL
         */
        isValidUrl: function(url) {
            try {
                new URL(url);
                return true;
            } catch (e) {
                return false;
            }
        },

        /**
         * Initialize code copy functionality
         */
        initCodeCopy: function() {
            $(document).on('click', '.csa-copy-code', function(e) {
                e.preventDefault();

                const $button = $(this);
                const $codeBlock = $button.closest('.csa-code-block');
                const code = $codeBlock.find('pre').text();

                // Copy to clipboard
                CSA_Admin.copyToClipboard(code);

                // Show feedback
                const originalText = $button.text();
                $button.text('Copied!');

                setTimeout(function() {
                    $button.text(originalText);
                }, 2000);
            });
        },

        /**
         * Copy text to clipboard
         */
        copyToClipboard: function(text) {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text);
            } else {
                // Fallback for older browsers
                const $temp = $('<textarea>');
                $('body').append($temp);
                $temp.val(text).select();
                document.execCommand('copy');
                $temp.remove();
            }
        },

        /**
         * Bind additional events
         */
        bindEvents: function() {
            // Toggle password visibility in settings
            $(document).on('click', '.csa-toggle-password-field', function(e) {
                e.preventDefault();

                const $button = $(this);
                const $input = $button.prev('input');

                if ($input.attr('type') === 'password') {
                    $input.attr('type', 'text');
                    $button.text('Hide');
                } else {
                    $input.attr('type', 'password');
                    $button.text('Show');
                }
            });

            // Test SMTP connection
            $(document).on('click', '.csa-test-smtp', function(e) {
                e.preventDefault();

                const $button = $(this);
                const originalText = $button.text();

                $button.text('Testing...').prop('disabled', true);

                $.ajax({
                    url: ajaxurl,
                    method: 'POST',
                    data: {
                        action: 'csa_test_smtp',
                        nonce: $button.data('nonce')
                    },
                    success: function(response) {
                        if (response.success) {
                            alert('SMTP connection successful!');
                        } else {
                            alert('SMTP connection failed: ' + response.data);
                        }
                    },
                    error: function() {
                        alert('An error occurred while testing SMTP connection.');
                    },
                    complete: function() {
                        $button.text(originalText).prop('disabled', false);
                    }
                });
            });

            // Clear logs
            $(document).on('click', '.csa-clear-logs', function(e) {
                e.preventDefault();

                if (!confirm('Are you sure you want to clear all logs? This action cannot be undone.')) {
                    return;
                }

                const $button = $(this);
                const originalText = $button.text();

                $button.text('Clearing...').prop('disabled', true);

                $.ajax({
                    url: ajaxurl,
                    method: 'POST',
                    data: {
                        action: 'csa_clear_logs',
                        nonce: $button.data('nonce')
                    },
                    success: function(response) {
                        if (response.success) {
                            location.reload();
                        } else {
                            alert('Failed to clear logs: ' + response.data);
                        }
                    },
                    error: function() {
                        alert('An error occurred while clearing logs.');
                    },
                    complete: function() {
                        $button.text(originalText).prop('disabled', false);
                    }
                });
            });

            // Export settings
            $(document).on('click', '.csa-export-settings', function(e) {
                e.preventDefault();

                const $button = $(this);

                $.ajax({
                    url: ajaxurl,
                    method: 'POST',
                    data: {
                        action: 'csa_export_settings',
                        nonce: $button.data('nonce')
                    },
                    success: function(response) {
                        if (response.success) {
                            const dataStr = JSON.stringify(response.data, null, 2);
                            const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);
                            const exportName = 'csa-settings-' + Date.now() + '.json';

                            const $link = $('<a></a>')
                                .attr('href', dataUri)
                                .attr('download', exportName);

                            $('body').append($link);
                            $link[0].click();
                            $link.remove();
                        } else {
                            alert('Failed to export settings: ' + response.data);
                        }
                    },
                    error: function() {
                        alert('An error occurred while exporting settings.');
                    }
                });
            });

            // Import settings
            $(document).on('change', '.csa-import-settings-file', function(e) {
                const file = e.target.files[0];

                if (!file) {
                    return;
                }

                const reader = new FileReader();

                reader.onload = function(e) {
                    try {
                        const settings = JSON.parse(e.target.result);

                        if (confirm('Are you sure you want to import these settings? Current settings will be overwritten.')) {
                            $.ajax({
                                url: ajaxurl,
                                method: 'POST',
                                data: {
                                    action: 'csa_import_settings',
                                    nonce: $(e.target).data('nonce'),
                                    settings: settings
                                },
                                success: function(response) {
                                    if (response.success) {
                                        alert('Settings imported successfully!');
                                        location.reload();
                                    } else {
                                        alert('Failed to import settings: ' + response.data);
                                    }
                                },
                                error: function() {
                                    alert('An error occurred while importing settings.');
                                }
                            });
                        }
                    } catch (error) {
                        alert('Invalid settings file. Please upload a valid JSON file.');
                    }
                };

                reader.readAsText(file);
            });
        }
    };

    // Initialize on document ready
    $(document).ready(function() {
        CSA_Admin.init();
    });

    // Expose to global scope
    window.CSA_Admin = CSA_Admin;

})(jQuery);
