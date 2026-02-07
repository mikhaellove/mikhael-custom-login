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
            this.initTabs();
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
            // Initialize sortable for existing fields
            this.initSortable();

            // Add field button
            $(document).on('click', '.csa-add-field-btn', this.addGridField.bind(this));

            // Remove field button
            $(document).on('click', '.csa-remove-field', this.removeGridField.bind(this));

            // Auto-generate field ID from label
            $(document).on('blur', '.csa-field-label-input', this.autoGenerateFieldId.bind(this));

            // Update field title on label change
            $(document).on('input', '.csa-field-label-input', this.updateFieldTitle.bind(this));

            // Renumber fields on change
            this.renumberFields();
        },

        /**
         * Initialize jQuery UI Sortable
         */
        initSortable: function() {
            $('.csa-grid-fields').sortable({
                handle: '.csa-drag-handle',
                placeholder: 'csa-grid-field-placeholder',
                axis: 'y',
                opacity: 0.7,
                cursor: 'move',
                tolerance: 'pointer',
                update: function(event, ui) {
                    CSA_Admin.renumberFields();
                }
            });
        },

        /**
         * Add new grid field
         */
        addGridField: function(e) {
            e.preventDefault();

            const $button = $(e.currentTarget);
            const $container = $button.closest('.csa-grid-builder').find('.csa-grid-fields');
            const fieldIndex = $container.find('.csa-grid-field-row').length;
            const fieldType = $button.data('type') || 'login';

            // Field template
            const fieldHtml = this.getFieldTemplate(fieldType, fieldIndex);

            // Add to container
            $container.append(fieldHtml);

            // Renumber fields
            this.renumberFields();

            // Scroll to new field
            const $newField = $container.find('.csa-grid-field-row').last();
            $('html, body').animate({
                scrollTop: $newField.offset().top - 100
            }, 300);

            // Focus first input
            $newField.find('input').first().focus();
        },

        /**
         * Get field template HTML
         */
        getFieldTemplate: function(fieldType, fieldIndex) {
            const uniqueId = 'field_' + Date.now();

            return `
                <div class="csa-grid-field-row" data-field-index="${fieldIndex}">
                    <div class="csa-grid-field-header">
                        <span class="dashicons dashicons-menu csa-drag-handle" title="Drag to reorder"></span>
                        <span class="csa-field-number">${fieldIndex + 1}</span>
                        <span class="csa-field-title">New Field</span>
                        <button type="button" class="csa-remove-field" title="Remove field">
                            <span class="dashicons dashicons-no-alt"></span>
                        </button>
                    </div>
                    <div class="csa-grid-field-body">
                        <div class="csa-grid-field-control">
                            <label>Field Label</label>
                            <input type="text"
                                   class="csa-field-label-input"
                                   name="csa_${fieldType}_fields[${fieldIndex}][label]"
                                   value=""
                                   placeholder="e.g., Username">
                        </div>
                        <div class="csa-grid-field-control">
                            <label>Field ID</label>
                            <input type="text"
                                   class="csa-field-id-input"
                                   name="csa_${fieldType}_fields[${fieldIndex}][id]"
                                   value="${uniqueId}"
                                   placeholder="e.g., username">
                        </div>
                        <div class="csa-grid-field-control">
                            <label>Field Type</label>
                            <select name="csa_${fieldType}_fields[${fieldIndex}][type]">
                                <option value="text">Text</option>
                                <option value="email">Email</option>
                                <option value="password">Password</option>
                                <option value="tel">Phone</option>
                                <option value="url">URL</option>
                                <option value="number">Number</option>
                                <option value="date">Date</option>
                                <option value="select">Select Dropdown</option>
                                <option value="checkbox">Checkbox</option>
                                <option value="radio">Radio Buttons</option>
                                <option value="textarea">Textarea</option>
                            </select>
                        </div>
                        <div class="csa-grid-field-control">
                            <label>Grid Width</label>
                            <select name="csa_${fieldType}_fields[${fieldIndex}][width]">
                                <option value="col-100" selected>Full Width (100%)</option>
                                <option value="col-50">Half Width (50%)</option>
                                <option value="col-33">Third Width (33%)</option>
                            </select>
                        </div>
                        <div class="csa-grid-field-control full-width">
                            <label>Placeholder Text</label>
                            <input type="text"
                                   name="csa_${fieldType}_fields[${fieldIndex}][placeholder]"
                                   value=""
                                   placeholder="Optional placeholder text">
                        </div>
                        <div class="csa-grid-field-control full-width">
                            <label>
                                <input type="checkbox"
                                       name="csa_${fieldType}_fields[${fieldIndex}][required]"
                                       value="1">
                                Required field
                            </label>
                        </div>
                    </div>
                </div>
            `;
        },

        /**
         * Remove grid field
         */
        removeGridField: function(e) {
            e.preventDefault();

            if (!confirm('Are you sure you want to remove this field?')) {
                return;
            }

            const $field = $(e.currentTarget).closest('.csa-grid-field-row');

            $field.fadeOut(300, function() {
                $(this).remove();
                CSA_Admin.renumberFields();
            });
        },

        /**
         * Auto-generate field ID from label
         */
        autoGenerateFieldId: function(e) {
            const $labelInput = $(e.currentTarget);
            const $fieldRow = $labelInput.closest('.csa-grid-field-row');
            const $idInput = $fieldRow.find('.csa-field-id-input');

            // Only auto-generate if ID is empty or looks auto-generated
            const currentId = $idInput.val();
            if (currentId && !currentId.startsWith('field_')) {
                return;
            }

            const label = $labelInput.val();
            const fieldId = this.slugify(label);

            if (fieldId) {
                $idInput.val(fieldId);
            }
        },

        /**
         * Update field title when label changes
         */
        updateFieldTitle: function(e) {
            const $labelInput = $(e.currentTarget);
            const $fieldRow = $labelInput.closest('.csa-grid-field-row');
            const $title = $fieldRow.find('.csa-field-title');
            const label = $labelInput.val();

            $title.text(label || 'New Field');
        },

        /**
         * Renumber all fields
         */
        renumberFields: function() {
            $('.csa-grid-fields').each(function() {
                $(this).find('.csa-grid-field-row').each(function(index) {
                    $(this)
                        .attr('data-field-index', index)
                        .find('.csa-field-number')
                        .text(index + 1);

                    // Update input names with correct index
                    $(this).find('input, select').each(function() {
                        const $input = $(this);
                        const name = $input.attr('name');

                        if (name) {
                            const newName = name.replace(/\[\d+\]/, '[' + index + ']');
                            $input.attr('name', newName);
                        }
                    });
                });
            });
        },

        /**
         * Convert string to slug
         */
        slugify: function(text) {
            return text
                .toString()
                .toLowerCase()
                .trim()
                .replace(/\s+/g, '_')           // Replace spaces with _
                .replace(/[^\w\-]+/g, '')       // Remove non-word chars
                .replace(/\_\_+/g, '_')         // Replace multiple _ with single _
                .replace(/^-+/, '')             // Trim - from start
                .replace(/-+$/, '');            // Trim - from end
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
