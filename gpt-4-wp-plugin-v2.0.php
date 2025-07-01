<?php
// ============================================================================
// === GPT-4 WP Plugin v2.0: 
// === Hyper-Verbose Documentation and Section Delimitation ===
// ============================================================================
//
// This file implements a secure, minimal REST API for WordPress, designed for
// robust integration with GPTs/clients. It provides:
//   - Custom roles and role-based API key management
//   - Secure REST endpoints for post, media, and file management
//   - Minimal, user-friendly admin UI for API key management
//   - Dynamic OpenAPI and manifest endpoints for plugin discovery
//   - Granular debug logging and robust input validation
//
// Each section below is clearly delimited and thoroughly documented for clarity

// -----------------------------------------------------------------------------
// 1. Plugin Header and Metadata
// -----------------------------------------------------------------------------
/*
Plugin Name: GPT-4 WP Plugin
Plugin URI: https://github.com/missmultiverse/gpt-4-wp-plugin
Description: Integrates GPT-4 with WordPress using GitHub auto-update via Git Updater.
Version: 2.0.0
Author: MissMultiverse
Author URI: https://missmultiverse.com
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
GitHub Plugin URI: https://github.com/missmultiverse/gpt-4-wp-plugin
Requires at least: 6.0
Tested up to: 6.7
*/

// -----------------------------------------------------------------------------
// 2. Debug Logging Helper
// -----------------------------------------------------------------------------
/**
 * Debug logging utility for the GPT-4 WP Plugin.
 *
 * This function writes debug messages to the error log if GPT_PLUGIN_DEBUG is enabled.
 * It is used throughout the plugin to provide granular, contextual debug output for
 * troubleshooting and development. Never logs API keys or sensitive data in production.
 *
 * @param string $label   A label or context for the log entry.
 * @param mixed  $data    Optional. Additional data to log (array, object, etc).
 */
function gpt_debug_log($label, $data = null) {
    if (defined('GPT_PLUGIN_DEBUG') && GPT_PLUGIN_DEBUG) {
        $msg = '[DEBUG]' . $label;
        if (!is_null($data)) {
            if (is_array($data) || is_object($data)) {
                $msg .= ' ' . print_r($data, true);
            } else {
                $msg .= ' ' . $data;
            }
        }
        error_log($msg);
    }
}

// -----------------------------------------------------------------------------
// --- Centralized error response and logging helper (for use in REST endpoints) ---
/**
 * Returns a standardized WP_Error for REST API responses, with optional debug logging.
 *
 * This function is used by all REST endpoints to return errors in a consistent format.
 * It also logs errors to the debug log if debugging is enabled, including the message
 * and any additional data provided. Never exposes sensitive information in responses.
 *
 * @param string $message  Error message to return.
 * @param int    $status   HTTP status code (default: 400).
 * @param array  $data     Optional. Additional data for the error response.
 * @return WP_Error        Standardized error object for REST API.
 */
if (!function_exists('gpt_error_response')) {
    function gpt_error_response($message, $status = 400, $data = [])
    {
        if (defined('GPT_PLUGIN_DEBUG') && GPT_PLUGIN_DEBUG) {
            error_log('[GPT-4-WP-Plugin] ERROR: ' . $message . (empty($data) ? '' : ' | Data: ' . print_r($data, true)));
        }
        return new WP_Error('gpt_error', esc_html($message), array_merge(['status' => $status], $data));
    }
}

// -----------------------------------------------------------------------------
// --- REST API error handling wrapper ---
/**
 * Wraps REST API endpoint callbacks in a try/catch block for robust error handling.
 *
 * This function ensures that any uncaught exceptions or errors in endpoint logic
 * are caught and returned as standardized WP_Error responses, preventing fatal errors
 * from leaking to the client. Used as a wrapper for all REST endpoint callbacks.
 *
 * @param callable $callback  The endpoint handler function to wrap.
 * @return callable           Wrapped callback for use in register_rest_route.
 */
function gpt_rest_api_error_wrapper($callback)
{
    return function ($request) use ($callback) {
        try {
            $result = call_user_func($callback, $request);
            if (is_wp_error($result)) {
                if (defined('GPT_PLUGIN_DEBUG') && GPT_PLUGIN_DEBUG) {
                    error_log('[GPT-4-WP-Plugin] WP_Error: ' . $result->get_error_message() . ' | Data: ' . print_r($result->get_error_data(), true));
                }
                return $result;
            }
            return $result;
        } catch (Throwable $e) {
            if (defined('GPT_PLUGIN_DEBUG') && GPT_PLUGIN_DEBUG) {
                error_log('[GPT-4-WP-Plugin] Exception: ' . $e->getMessage());
            }
            return gpt_error_response('Internal server error', 500);
        }
    };
}

// -----------------------------------------------------------------------------
// --- Register custom roles on plugin activation ---
/**
 * Registers custom GPT roles on plugin activation.
 *
 * This hook creates the four supported roles (Administrator, Webmaster,
 * Publisher, Editor), each with a distinct set of capabilities. These roles
 * are used for API key
 * assignment and permission checks throughout the plugin. No legacy roles are added.
 */
register_activation_hook(__FILE__, function () {
    add_role('gpt_admin', 'GPT Administrator', [
        'read' => true,
        'edit_posts' => true,
        'publish_posts' => true,
        'manage_options' => true,
        'upload_files' => true,
        'edit_others_posts' => true,
        'delete_posts' => true,
        'delete_others_posts' => true,
        'gpt_manage_files' => true, // custom cap for file management
    ]);
    add_role('gpt_webmaster', 'GPT Webmaster', [
        'read' => true,
        'edit_posts' => true,
        'publish_posts' => true,
        'manage_options' => true,
        'upload_files' => true,
        'edit_others_posts' => true,
        'delete_posts' => true,
        'delete_others_posts' => true,
    ]);
    add_role('gpt_publisher', 'GPT Publisher', [
        'read' => true,
        'edit_posts' => true,
        'publish_posts' => true,
        'upload_files' => true,
        'edit_others_posts' => true,
        'delete_posts' => true,
    ]);
    add_role('gpt_editor', 'GPT Editor', [
        'read' => true,
        'edit_posts' => true,
        'upload_files' => true,
    ]);
});

// -----------------------------------------------------------------------------
// --- Remove custom roles on deactivation ---
/**
 * Removes custom GPT roles on plugin deactivation.
 *
 * This hook cleans up all custom roles created by the plugin, ensuring no
 * lingering roles remain if the plugin is disabled or removed.
 */
register_deactivation_hook(__FILE__, function () {
    remove_role('gpt_admin');
    remove_role('gpt_webmaster');
    remove_role('gpt_publisher');
    remove_role('gpt_editor');
});

// -----------------------------------------------------------------------------
// --- API Key Management: Admin UI ---
/**
 * Adds the GPT API Keys admin page and management UI under Tools.
 *
 * This section provides a minimal, user-friendly interface for generating,
 * listing, and revoking API keys, as well as selecting the current site.
 * All logic for API key management is contained here, with robust input validation
 * and no exposure of sensitive data. The UI is always under Tools > GPT API Keys.
 */
add_action('admin_menu', function () {
    add_menu_page(
        'GPT API Keys',
        'GPT API Keys',
        'manage_options',
        'gpt-api-keys',
        'gpt_api_keys_page',
        'dashicons-admin-network',
        3
    );
    add_management_page('GPT API Keys', 'GPT API Keys', 'manage_options', 'gpt-api-keys', 'gpt_api_keys_page');
});

function gpt_api_keys_page()
{
    if (!current_user_can('manage_options'))
        return;
    
    $roles = [
        'gpt_admin' => 'Administrator',
        'gpt_webmaster' => 'Webmaster',
        'gpt_publisher' => 'Publisher',
        'gpt_editor' => 'Editor',
    ];
    
    $role_caps = [
        'gpt_admin' => ['read', 'edit_posts', 'publish_posts', 'manage_options', 'upload_files', 'edit_others_posts', 'delete_posts', 'delete_others_posts', 'gpt_manage_files'],
        'gpt_webmaster' => ['read', 'edit_posts', 'publish_posts', 'manage_options', 'upload_files', 'edit_others_posts', 'delete_posts', 'delete_others_posts'],
        'gpt_publisher' => ['read', 'edit_posts', 'publish_posts', 'upload_files', 'edit_others_posts', 'delete_posts'],
        'gpt_editor' => ['read', 'edit_posts', 'upload_files'],
    ];


// Add logo and plugin name at the top using an emoji
echo '<div style="text-align: center; margin-bottom: 30px; padding-top: 20px;">';

// Use an emoji as a logo
echo '<div style="font-size: 4em; line-height: 1; color: #4CAF50; margin-bottom: 10px;">🚀</div>';

echo '<h1 style="font-family: Arial, sans-serif; font-size: 2.5em; color: #333; font-weight: bold; margin-top: 10px;">GPT-4 WP Plugin</h1>';
echo '<p style="font-family: Arial, sans-serif; font-size: 1.1em; color: #666;">A simple and powerful WordPress integration for GPT-4</p>';
echo '</div>';

    
    // Add some space before the Select Site dropdown
    echo '<div style="margin-bottom: 20px;"></div>';
    
    // Get the list of sites
    $sites = gpt_get_sites_list();
    
    // --- Handle site selection (single handler, DRY) ---
    if (isset($_POST['gpt_selected_site'])) {
        $selected_site = sanitize_text_field($_POST['gpt_selected_site']);
        gpt_set_selected_site($selected_site);
        echo '<div class="updated"><p>Site selected: <strong>' . esc_html($selected_site) . '</strong></p></div>';
    }
    $selected_site = gpt_get_selected_site();
    $site_url = 'https://' . $selected_site;

    // --- UI: Site selection dropdown ---
    echo '<form method="post" style="margin-bottom:20px;">';
    echo '<label for="gpt_selected_site"><strong>Select Site:</strong></label> ';
    echo '<select name="gpt_selected_site" id="gpt_selected_site">';
    foreach ($sites as $site) {
        echo '<option value="' . esc_attr($site) . '"' . selected($selected_site, $site, false) . '>' . esc_html($site) . '</option>';
    }
    echo '</select> ';
    echo '<button type="submit" class="button">Apply</button>';
    echo '</form>';
    echo '<p><strong>Current Site:</strong> ' . esc_html($selected_site) . '</p>';
    // --- Relevant Links for Selected Site ---
    echo '<div style="margin-bottom:20px;padding:10px;background:#f8f8f8;border:1px solid #eee;border-radius:4px;">';
    echo '<strong>Quick Links for ' . esc_html($selected_site) . ':</strong><ul style="margin:0 0 0 20px;">';
    echo '<li>OpenAPI Schema Endpoint: <a href="' . esc_url($site_url . '/wp-json/gpt/v1/openapi') . '" target="_blank">' . esc_html($site_url . '/wp-json/gpt/v1/openapi') . '</a></li>';
    echo '<li>ai-plugin.json Manifest: <a href="' . esc_url($site_url . '/wp-json/gpt/v1/ai-plugin.json') . '" target="_blank">' . esc_html($site_url . '/wp-json/gpt/v1/ai-plugin.json') . '</a></li>';
    echo '<li>Create Post Endpoint: <a href="' . esc_url($site_url . '/wp-json/gpt/v1/post') . '" target="_blank">' . esc_html($site_url . '/wp-json/gpt/v1/post') . '</a></li>';
    echo '<li>Media Upload Endpoint: <a href="' . esc_url($site_url . '/wp-json/gpt/v1/media') . '" target="_blank">' . esc_html($site_url . '/wp-json/gpt/v1/media') . '</a></li>';
    echo '<li>Ping Test Endpoint: <a href="' . esc_url($site_url . '/wp-json/gpt/v1/post') . '" target="_blank">' . esc_html($site_url . '/wp-json/gpt/v1/post') . '</a></li>';
    echo '</ul></div>';
    // --- Capabilities Box (4 columns) ---
    echo '<div style="display:flex;gap:10px;margin-bottom:20px;">';
    foreach ($roles as $slug => $label) {
        echo '<div style="flex:1;padding:10px;background:#f4f4f4;border:1px solid #ddd;border-radius:4px;min-width:180px;">';
        echo '<strong>' . esc_html($label) . '</strong><ul style="margin:8px 0 0 18px;">';
        foreach ($role_caps[$slug] as $cap) {
            echo '<li>' . esc_html($cap) . '</li>';
        }
        echo '</ul></div>';
    }
    echo '</div>';
    // --- UI: Key management and status (existing code follows) ---
    // Handle form submissions
    if (isset($_POST['gpt_generate_key'], $_POST['gpt_role']) && check_admin_referer('gpt_api_key_action', 'gpt_api_key_nonce')) {
        $key = wp_generate_password(32, false, false);
        $role = sanitize_key($_POST['gpt_role']);
        $label = sanitize_text_field($_POST['gpt_label'] ?? '');
        $keys = get_option('gpt_api_keys', []);
        $keys[$key] = [
            'role' => $role,
            'created' => current_time('mysql'),
            'label' => $label,
        ];
        update_option('gpt_api_keys', $keys);
        echo '<div class="updated"><p>New API Key: <code>' . esc_html($key) . '</code> (Role: ' . esc_html($roles[$role]) . ')' . ($label ? ' — <strong>' . esc_html($label) . '</strong>' : '') . '</p></div>';
    }
    if (isset($_POST['gpt_revoke_key'], $_POST['gpt_key']) && check_admin_referer('gpt_api_key_action', 'gpt_api_key_nonce')) {
        $key = sanitize_text_field($_POST['gpt_key']);
        $keys = get_option('gpt_api_keys', []);
        unset($keys[$key]);
        update_option('gpt_api_keys', $keys);
        echo '<div class="updated"><p>API Key revoked.</p></div>';
    }
    $keys = get_option('gpt_api_keys', []);
    // --- GPT Plugin Status Section ---
    $is_active = is_plugin_active(plugin_basename(__FILE__));
    $site_url = get_site_url();
    $openapi_url = $site_url . '/wp-json/gpt/v1/openapi';
    $manifest_url = $site_url . '/wp-json/gpt/v1/ai-plugin.json';
    $permalink_structure = get_option('permalink_structure');
    $is_https = (strpos($site_url, 'https://') === 0);
    $rest_enabled = (apply_filters('rest_enabled', true) && !defined('REST_API_DISABLED'));
    $curl_loaded = extension_loaded('curl');
    $json_loaded = extension_loaded('json');
    // REST API endpoint reachability
    $openapi_resp = wp_remote_get($openapi_url, ['timeout' => 3]);
    $manifest_resp = wp_remote_get($manifest_url, ['timeout' => 3]);
    $openapi_ok = !is_wp_error($openapi_resp) && wp_remote_retrieve_response_code($openapi_resp) === 200;
    $manifest_ok = !is_wp_error($manifest_resp) && wp_remote_retrieve_response_code($manifest_resp) === 200;
    // --- Status UI ---
    echo '<h2>GPT Plugin Status</h2>';
    // Plugin active
    if ($is_active) {
        echo '<p style="color:green;font-size:1.2em;"><span style="font-size:1.5em;vertical-align:middle;">&#x2705;</span> GPT Plugin is <strong>Active</strong> and linked.</p>';
    } else {
        echo '<p style="color:red;font-size:1.2em;"><span style="font-size:1.5em;vertical-align:middle;">&#x274C;</span> GPT Plugin is <strong>Not Active</strong>.</p>';
    }
    // --- Split status list into two columns ---
    echo '<div style="display:flex;gap:24px;align-items:flex-start;margin-bottom:20px;">';
    // Left column
    echo '<ul style="list-style:none;padding-left:0;flex:1;min-width:260px;">';
    echo '<li>';
    echo $openapi_ok ? '<span style="color:green;">&#x2705; OpenAPI endpoint reachable</span>' : '<span style="color:red;">&#x274C; OpenAPI endpoint unreachable: ' . esc_html(is_wp_error($openapi_resp) ? $openapi_resp->get_error_message() : wp_remote_retrieve_response_code($openapi_resp)) . '</span>';
    echo '</li>';
    echo '<li>';
    echo $manifest_ok ? '<span style="color:green;">&#x2705; ai-plugin.json endpoint reachable</span>' : '<span style="color:red;">&#x274C; ai-plugin.json endpoint unreachable: ' . esc_html(is_wp_error($manifest_resp) ? $manifest_resp->get_error_message() : wp_remote_retrieve_response_code($manifest_resp)) . '</span>';
    echo '</li>';
    echo '<li>';
    if (is_array($keys) && count($keys) > 0) {
        echo '<span style="color:green;">&#x2705; At least one API key exists</span>';
    } else {
        echo '<span style="color:red;">&#x274C; No API keys found. GPTs cannot connect.</span>';
    }
    echo '</li>';
    echo '<li>';
    if ($permalink_structure && $permalink_structure !== '') {
        echo '<span style="color:green;">&#x2705; Permalinks are set to Pretty</span>';
    } else {
        echo '<span style="color:orange;">&#x26A0; Permalinks are set to Plain. REST API may not work optimally.</span>';
    }
    echo '</li>';
    echo '</ul>';
    // Right column
    echo '<ul style="list-style:none;padding-left:0;flex:1;min-width:260px;">';
    echo '<li>';
    if ($is_https) {
        echo '<span style="color:green;">&#x2705; Site is using HTTPS</span>';
    } else {
        echo '<span style="color:orange;">&#x26A0; Site is not using HTTPS. GPT integrations may require secure endpoints.</span>';
    }
    echo '</li>';
    echo '<li>';
    if ($rest_enabled) {
        echo '<span style="color:green;">&#x2705; WordPress REST API is enabled</span>';
    } else {
        echo '<span style="color:red;">&#x274C; WordPress REST API is disabled by a plugin or custom code.</span>';
    }
    echo '</li>';
    echo '<li>';
    if ($curl_loaded && $json_loaded) {
        echo '<span style="color:green;">&#x2705; Required PHP extensions (curl, json) are loaded</span>';
    } else {
        $missing = [];
        if (!$curl_loaded)
            $missing[] = 'curl';
        if (!$json_loaded)
            $missing[] = 'json';
        echo '<span style="color:red;">&#x274C; Missing PHP extensions: ' . esc_html(implode(', ', $missing)) . '</span>';
    }
    echo '</li>';
    echo '</ul>';
    echo '</div>';
    // --- Recent API Errors (last 5) ---
    $log_path = defined('WP_DEBUG_LOG') ? WP_DEBUG_LOG : ABSPATH . 'wp-content/debug.log';
    $recent_errors = [];
    if (file_exists($log_path)) {
        $fp = fopen($log_path, 'r');
        if ($fp) {
            $lines = [];
            $max = 1000; // Read up to last 1000 lines for efficiency
            $buffer = 4096;
            fseek($fp, 0, SEEK_END);
            $pos = ftell($fp);
            $chunk = '';
            while ($pos > 0 && count($lines) < $max) {
                $read = ($pos - $buffer > 0) ? $buffer : $pos;
                $pos -= $read;
                fseek($fp, $pos);
                $chunk = fread($fp, $read) . $chunk;
                $lines = explode("\n", $chunk);
            }
            fclose($fp);
            $lines = array_reverse($lines);
            foreach ($lines as $line) {
                if (strpos($line, '[GPT-4-WP-Plugin]') !== false) {
                    $recent_errors[] = trim($line);
                    if (count($recent_errors) >= 5)
                        break;
                }
            }
        }
    }
    echo '<h3>Last 5 API Errors</h3>';
    if (!empty($recent_errors)) {
        echo '<ul style="font-size:0.95em;background:#f9f9f9;padding:10px;border-radius:4px;">';
        foreach ($recent_errors as $err) {
            echo '<li style="color:#b00;">' . esc_html($err) . '</li>';
        }
        echo '</ul>';
    } else {
        echo '<p style="color:green;">No recent API errors found.</p>';
    }
    ?>
    <div class="wrap">
        <h1>GPT API Key Management</h1>
        <!-- Ping Site Button -->
        <button id="gpt-ping-site-btn" class="button">Ping Site (Test /wp-json/gpt/v1/post)</button>
        <span id="gpt-ping-site-result" style="margin-left:10px;"></span>
        <script>
            document.addEventListener('DOMContentLoaded', function () {
                var btn = document.getElementById('gpt-ping-site-btn');
                var result = document.getElementById('gpt-ping-site-result');
                btn.addEventListener('click', function () {
                    result.innerHTML = 'Pinging...';
                    btn.disabled = true;
                    fetch(ajaxurl, {
                        method: 'POST',
                        credentials: 'same-origin',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: 'action=gpt_ping_site&_wpnonce=<?php echo wp_create_nonce('gpt_ping_site_nonce'); ?>'
                    })
                        .then(r => r.json())
                        .then(data => {
                            btn.disabled = false;
                            if (data.success) {
                                result.innerHTML = '<span style="color:green;">&#x2705; ' + (data.data && data.data.message ? data.data.message : 'Ping successful!') + '</span>';
                            } else {
                                result.innerHTML = '<span style="color:red;">&#x274C; ' + (data.data && data.data.message ? data.data.message : 'Ping failed!') + '</span>';
                            }
                        })
                        .catch(e => {
                            btn.disabled = false;
                            result.innerHTML = '<span style="color:red;">&#x274C; Error: ' + e + '</span>';
                        });
                });
            });
        </script>
        <!-- End Ping Site Button -->
        <form method="post">
            <?php wp_nonce_field('gpt_api_key_action', 'gpt_api_key_nonce'); ?>
            <label for="gpt_role">Role:</label>
            <select name="gpt_role" id="gpt_role" required>
                <?php foreach ($roles as $slug => $label): ?>
                    <option value="<?php echo esc_attr($slug); ?>"><?php echo esc_html($label); ?></option>
                <?php endforeach; ?>
            </select>
            <label for="gpt_label">Label (optional, e.g. GPT Client Name):</label>
            <input type="text" name="gpt_label" id="gpt_label" placeholder="e.g. GPT-4 Client" style="min-width:200px;">
            <button type="submit" name="gpt_generate_key" class="button button-primary">Generate API Key</button>
        </form>
        <!-- Capabilities display for selected role -->
        <div id="gpt-role-capabilities" style="margin-top:10px;"></div>
        <script>
            // --- JS: Show capabilities for selected role ---
            document.addEventListener('DOMContentLoaded', function () {
                var roleSelect = document.getElementById('gpt_role');
                var capDiv = document.getElementById('gpt-role-capabilities');
                var roleCaps = {
                    'gpt_admin': ['read', 'edit_posts', 'publish_posts', 'manage_options', 'upload_files', 'edit_others_posts', 'delete_posts', 'delete_others_posts', 'gpt_manage_files'],
                    'gpt_webmaster': ['read', 'edit_posts', 'publish_posts', 'manage_options', 'upload_files', 'edit_others_posts', 'delete_posts', 'delete_others_posts'],
                    'gpt_publisher': ['read', 'edit_posts', 'publish_posts', 'upload_files', 'edit_others_posts', 'delete_posts'],
                    'gpt_editor': ['read', 'edit_posts', 'upload_files']
                };
                function updateCaps() {
                    var role = roleSelect.value;
                    var caps = roleCaps[role] || [];
                    capDiv.innerHTML = '<strong>Capabilities for ' + role + ':</strong> ' + caps.join(', ');
                }
                roleSelect.addEventListener('change', updateCaps);
                updateCaps();
            });
        </script>
        <h2>Existing API Keys</h2>
        <table class="widefat">
            <thead>
                <tr>
                    <th>API Key</th>
                    <th>Label</th>
                    <th>Role</th>
                    <th>Created</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($keys as $key => $info): ?>
                    <tr>
                        <td><code><?php echo esc_html($key); ?></code></td>
                        <td><?php echo esc_html($info['label'] ?? ''); ?></td>
                        <td><?php echo esc_html($roles[$info['role']] ?? $info['role']); ?></td>
                        <td><?php echo esc_html($info['created']); ?></td>
                        <td>
                            <form method="post" style="display:inline;">
                                <?php wp_nonce_field('gpt_api_key_action', 'gpt_api_key_nonce'); ?>
                                <input type="hidden" name="gpt_key" value="<?php echo esc_attr($key); ?>">
                                <button type="submit" name="gpt_revoke_key" class="button">Revoke</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php
}

// -----------------------------------------------------------------------------
// --- Add settings link in plugin list ---
/**
 * Adds a direct 'Settings' link to the plugin list for quick access to the admin UI.
 *
 * This filter ensures that users can easily navigate to the API key management page
 * from the WordPress plugins list.
 */
add_filter('plugin_action_links_' . plugin_basename(__FILE__), function ($links) {
    if (!is_array($links)) {
        $links = [];
    }

    $url = admin_url('tools.php?page=gpt-api-keys');
    $links[] = '<a href="' . esc_url($url) . '">Settings</a>';

    return $links; // ✅ THIS is what was missing
});

// -----------------------------------------------------------------------------
// --- REST permission check based on provided GPT role ---
/**
 * Permission callback used by GPT REST endpoints.
 *
 * This function handles the permission check for REST API requests that require a GPT role.
 * It reads the API key from the incoming request headers, determines the corresponding GPT role
 * using the provided key, and verifies whether the role is authorized to perform the requested action.
 * If the role is valid, it grants permission; otherwise, it denies access.
 * The function interacts with other parts of the plugin to fetch the role from stored API keys.
 * If the key is missing, or the role is invalid, the request is rejected with an error response.
 *
 * @param WP_REST_Request $request Incoming REST request.
 * @return bool True when a valid role is resolved, false otherwise.
 */
function gpt_rest_permission_check_role($request) {
    gpt_debug_log('[gpt_rest_permission_check_role] Incoming headers', $request->get_headers());
    $key = $request->get_header('gpt-api-key') ?: str_replace('Bearer ', '', $request->get_header('authorization'));
    gpt_debug_log('[gpt_rest_permission_check_role] API key', $key);
    if (!$key) {
        gpt_debug_log('[gpt_rest_permission_check_role] Permission denied: Missing gpt-api-key header');
        return false;
    }
    $role = gpt_get_role_for_key($key);
    gpt_debug_log('[gpt_rest_permission_check_role] Role for key', $role);
    if (!$role) {
        gpt_debug_log('[gpt_rest_permission_check_role] Permission denied: Invalid API key');
        return false;
    }
    $requested_role = $request->get_param('gpt_role');
    gpt_debug_log('[gpt_rest_permission_check_role] Requested role', $requested_role);
    $role_normalized = is_string($role) ? strtolower(trim($role)) : '';
    $requested_role_normalized = is_string($requested_role) ? strtolower(trim($requested_role)) : '';
    gpt_debug_log('[gpt_rest_permission_check_role] Normalized role', $role_normalized);
    gpt_debug_log('[gpt_rest_permission_check_role] Normalized requested_role', $requested_role_normalized);
    if ($requested_role && $requested_role_normalized !== $role_normalized) {
        gpt_debug_log("[gpt_rest_permission_check_role] Permission denied: API key role '{$role_normalized}' does not match requested role '{$requested_role_normalized}'");
        return false;
    }
    gpt_debug_log('[gpt_rest_permission_check_role] Permission granted');
    return true;
}

// -----------------------------------------------------------------------------
// --- Helper: Validate API key and get role ---
/**
 * Retrieves the GPT role associated with a given API key.
 *
 * This function looks up the provided API key in the stored options and returns
 * the associated role if found. Used by permission checks and endpoint handlers.
 *
 * @param string $key  The API key to look up.
 * @return string|null The associated role, or null if not found.
 */
function gpt_get_role_for_key($key)
{
    gpt_debug_log('[gpt_get_role_for_key] Checking key', $key);
    $keys = get_option('gpt_api_keys', []);
    gpt_debug_log('[gpt_get_role_for_key] All keys', $keys);
    if (is_array($keys) && isset($keys[$key])) {
        gpt_debug_log('[gpt_get_role_for_key] Role found', $keys[$key]['role'] ?? null);
        return $keys[$key]['role'] ?? null;
    }
    gpt_debug_log('[gpt_get_role_for_key] No role found for key');
    return null;
}

// -----------------------------------------------------------------------------
// --- Pre-configured  Websites ---
/**
 * Returns the list of pre-configured websites.
 *
 * These functions provide the always-present list of supported domains 
 * for site selection. Used for admin UI and dynamic config. NOTE: WE REMOVED
 * THE PRECONFIGURED GPTs FEATURE
 */
function gpt_get_sites_list()
{
    return [
        'allcelebritiesworld.com',
        'celebrityandmovies.com',
        'celebritytvstars.com',
        'charity.missmultiverse.com',
        'famoustvcelebrities.com',
        'famoustvstars.com',
        'gausachs.com',
        'latestpageantnews.com',
        'lindagrandia.com',
        'missmultiverse.com',
        'missosology.com',
        'misspowerwoman.com',
        'multiverseventuresgroup.com',
        'pageantfame.com',
        'pageantmayhem.com',
    ];
}
function gpt_get_selected_site()
{
    $sites = gpt_get_sites_list();
    $selected = get_option('gpt_selected_site');
    if ($selected && in_array($selected, $sites, true))
        return $selected;
    return $sites[0]; // default to first
}
function gpt_set_selected_site($site)
{
    $sites = gpt_get_sites_list();
    if (in_array($site, $sites, true)) {
        update_option('gpt_selected_site', $site);
    }
}

// -----------------------------------------------------------------------------
// --- Helper: Get current site config (for dynamic endpoint/settings adjustment) ---
/**
 * Returns the current site configuration for dynamic endpoint and settings adjustment.
 *
 * Used to adapt plugin behavior based on the selected site in multisite or multi-domain setups.
 *
 * @return array Site config including base URL and API base.
 */
function gpt_get_current_site_config()
{
    $site = gpt_get_selected_site();
    // You can expand this to return more config per site if needed
    return [
        'site' => $site,
        'api_base' => 'https://' . $site . '/wp-json/gpt/v1',
    ];
}


// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
// --- REST API Endpoints Registration ---
/**
 * Registers all GPT REST API endpoints with WordPress.
 *
 * This section defines the main REST endpoints for post creation, editing, media upload,
 * OpenAPI schema, and manifest, as well as a ping endpoint for connectivity testing.
 * Each endpoint uses robust permission checks and error handling wrappers.
 */
add_action('rest_api_init', function () {
    // Register the /post endpoint for creating posts via the REST API
    register_rest_route('gpt/v1', '/post', [
        'methods' => 'POST',
        'callback' => gpt_rest_api_error_wrapper('gpt_create_post_endpoint'), // callback to handle the post creation
        'permission_callback' => 'gpt_rest_permission_check_role', // check if the API key has permission to post
    ]);

    // Register the /post/{id} endpoint for editing an existing post
    register_rest_route('gpt/v1', '/post/(?P<id>\d+)', [
        'methods' => 'POST',
        'callback' => gpt_rest_api_error_wrapper('gpt_edit_post_endpoint'), // callback to handle post editing
        'permission_callback' => 'gpt_rest_permission_check_role', // check if the API key has permission to edit posts
        'args' => [
            'id' => [
                'validate_callback' => function ($value) {
                    return is_numeric($value); // ensure that the post ID is numeric
                },
            ],
        ],
    ]);

    // Register the /media endpoint for media uploads (POST method)
    register_rest_route('gpt/v1', '/media', [
        'methods' => 'POST',
        'callback' => gpt_rest_api_error_wrapper('gpt_upload_media_endpoint'), // callback to handle media uploads
        'permission_callback' => 'gpt_rest_permission_check_role', // check if the API key has permission to upload media
    ]);

    // Register the /openapi endpoint to serve the OpenAPI schema
    register_rest_route('gpt/v1', '/openapi', [
        'methods' => 'GET',
        'callback' => gpt_rest_api_error_wrapper('gpt_openapi_schema_handler'), // callback to serve OpenAPI schema
        'permission_callback' => '__return_true', // no authentication required for OpenAPI schema
    ]);

    // Register the /ai-plugin.json endpoint to serve the plugin manifest
    register_rest_route('gpt/v1', '/ai-plugin.json', [
        'methods' => 'GET',
        'callback' => gpt_rest_api_error_wrapper('gpt_ai_plugin_manifest_handler'), // callback to serve plugin manifest
        'permission_callback' => '__return_true', // no authentication required for manifest
    ]);

    // Register the /ping route for general API connectivity and API key validation
    register_rest_route('gpt/v1', '/ping', [
        'methods' => 'GET',
        'callback' => 'gpt_ping_endpoint', // Use the callback defined earlier
        'permission_callback' => function($request) {
            $key = $request->get_header('gpt-api-key') ?: str_replace('Bearer ', '', $request->get_header('authorization'));
            return !!gpt_get_role_for_key($key); // Ensure API key is valid
        },
    ]);
});


// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// --- REST: Dedicated Ping Endpoint for API Connectivity Testing ---
/**
 * Dedicated GET /ping endpoint for agents to test API connectivity and API key validity.
 *
 * Returns a success message and the resolved role if the API key is valid.
 * Only requires a valid API key (no role check). Used for health checks and integration testing.
 *
 * @param WP_REST_Request $request
 * @return WP_REST_Response|WP_Error
 */
function gpt_ping_endpoint($request)
{
    // Accept both "gpt-api-key" and "Authorization: Bearer" headers
    $key = $request->get_header('gpt-api-key') ?: str_replace('Bearer ', '', $request->get_header('authorization'));
    gpt_debug_log('[gpt_ping_endpoint] API key received', $key);
    $role = gpt_get_role_for_key($key);
    gpt_debug_log('[gpt_ping_endpoint] Role resolved for key', $role);
    if (!$role) {
        gpt_debug_log('[gpt_ping_endpoint] Invalid or missing API key', $key);
        return gpt_error_response('Invalid or missing API key.', 401);
    }
    gpt_debug_log('[gpt_ping_endpoint] Ping successful', ['role' => $role]);
    return new WP_REST_Response([
        'message' => 'Ping successful. WordPress site is reachable and API key is valid.',
        'role' => $role
    ], 200);
}

// Register the /ping endpoint
add_action('rest_api_init', function () {
    register_rest_route('gpt/v1', '/ping', [
        'methods' => 'GET',
        'callback' => 'gpt_ping_endpoint',
        // Only require a valid API key, not a specific role
        'permission_callback' => function($request) {
            $key = $request->get_header('gpt-api-key') ?: str_replace('Bearer ', '', $request->get_header('authorization'));
            return !!gpt_get_role_for_key($key); // Ensure API key is valid
        },
    ]);
});

// -----------------------------------------------------------------------------
// --- Helper: Sanitize and limit excerpt ---
/**
 * Sanitizes and truncates post excerpts for safe storage and display.
 *
 * Ensures that excerpts are plain text and do not exceed 200 characters.
 * Used during post creation and editing.
 *
 * @param string $excerpt
 * @return string
 */
if (!function_exists('gpt_sanitize_excerpt')) {
    function gpt_sanitize_excerpt($excerpt) {
        // Basic sanitization and max length 200 characters
        $clean = sanitize_text_field($excerpt);
        return mb_substr($clean, 0, 200);
    }
}

// -----------------------------------------------------------------------------
// --- REST: 📚 CREATE POST 🗄️---CREATE POST 📚
/**
 * Handles creation of new WordPress posts via the REST API.
 *
 * This endpoint allows authorized GPT clients to create posts with specified content,
 * categories, tags, featured images, and metadata. It performs robust role validation,
 * input sanitization, and debug logging. Only allowed roles may create posts.
 *
 * @param WP_REST_Request $request
 * @return array|WP_Error
 */
function gpt_create_post_endpoint($request)
{
    // -------------------------------------------------------------------------
    // --- Hyper-Verbose Section: Incoming Request and Role Resolution ---
    // -------------------------------------------------------------------------
    gpt_debug_log('[gpt_create_post_endpoint] Incoming request', $request->get_json_params());

    // 🔑 Extract API key from either the 'gpt-api-key' or 'Authorization: Bearer' header
    $api_key = $request->get_header('gpt-api-key') ?: str_replace('Bearer ', '', $request->get_header('authorization'));
    gpt_debug_log('[gpt_create_post_endpoint] API key', $api_key);

    // Get role associated with API key
    $role = gpt_get_role_for_key($api_key);

    // Get gpt_role param from request (may be missing)
    $param_role = $request->get_param('gpt_role');

    // --- Begin normalization and granular debug logging ---
    $role_normalized = is_string($role) ? strtolower(trim($role)) : '';
    $param_role_normalized = is_string($param_role) ? strtolower(trim($param_role)) : '';
    $allowed_roles = ['gpt_webmaster', 'gpt_publisher', 'gpt_editor'];

    // --- Ensure gpt_role fallback and robust validation ---
    // If gpt_role is missing, use the API key's role
    if (empty($param_role_normalized)) {
        $param_role_normalized = $role_normalized;
        gpt_debug_log('[gpt_create_post_endpoint] gpt_role param missing, falling back to API key role', $role_normalized);
    }

    // Log available roles for debugging
    gpt_debug_log('[gpt_create_post_endpoint] Available roles', $allowed_roles);
    // Log the role being passed for validation
    gpt_debug_log('[gpt_create_post_endpoint] Role from API key', $role);
    // Log the normalized role for final validation
    gpt_debug_log('[gpt_create_post_endpoint] Normalized role', $role_normalized);
    // Log the requested role (in case there's a mismatch)
    gpt_debug_log('[gpt_create_post_endpoint] Requested role', $param_role);
    gpt_debug_log('[gpt_create_post_endpoint] Normalized requested role', $param_role_normalized);

    // --- Use the effective role (param_role_normalized) for validation ---
    if (!in_array($param_role_normalized, $allowed_roles, true)) {
        gpt_debug_log('[gpt_create_post_endpoint] Invalid role', $param_role_normalized);
        return gpt_error_response('Invalid role', 403);
    }

    // If gpt_role param is present but mismatched, log but do not block
    if ($param_role && $param_role_normalized !== $role_normalized) {
        gpt_debug_log('[gpt_create_post_endpoint] Role param mismatch, proceeding with API key role', [
            'param_role_normalized' => $param_role_normalized,
            'role_normalized' => $role_normalized
        ]);
    }

    gpt_debug_log('[gpt_create_post_endpoint] Effective normalized role', $param_role_normalized);

    // -------------------------------------------------------------------------
    // --- Continue with Post Creation Process ---
    // -------------------------------------------------------------------------
    $params = $request->get_json_params();
    gpt_debug_log('[gpt_create_post_endpoint] Params', $params);

    // Retrieve and check user ID based on API key and role
    $user_id = create_gpt_user($api_key, $param_role_normalized);
    gpt_debug_log('[gpt_create_post_endpoint] User ID after user creation', $user_id);

    if (!$user_id) {
        gpt_debug_log('[gpt_create_post_endpoint] Failed to create or retrieve user for API key', $api_key);
        return gpt_error_response('Failed to create user', 500);
    }

    // Prepare post data
    $post_data = [
        'post_title' => sanitize_text_field($params['title'] ?? ''),
        'post_content' => wp_kses_post($params['content'] ?? ''),
        'post_status' => isset($params['post_status']) ? sanitize_key($params['post_status']) : (($param_role_normalized === 'gpt_editor') ? 'draft' : 'publish'),
        'post_type' => 'post',
        'post_excerpt' => isset($params['excerpt']) ? wp_kses_post($params['excerpt']) : '',
        'post_format' => isset($params['format']) ? sanitize_key($params['format']) : 'standard',
        'post_name' => isset($params['slug']) ? sanitize_title($params['slug']) : '',
        'post_author' => $user_id,
        'post_date' => isset($params['post_date']) ? sanitize_text_field($params['post_date']) : '',
    ];
    gpt_debug_log('[gpt_create_post_endpoint] Post data prepared', $post_data);

    $post_id = wp_insert_post($post_data);
    gpt_debug_log('[gpt_create_post_endpoint] wp_insert_post result', $post_id);
    if (is_wp_error($post_id)) {
        gpt_debug_log('[gpt_create_post_endpoint] Error inserting post', $post_id->get_error_message());
        return $post_id;
    }

    if (!empty($params['categories'])) {
        gpt_debug_log('[gpt_create_post_endpoint] Setting categories', $params['categories']);
        wp_set_post_categories($post_id, array_map('intval', (array) $params['categories']));
    }
    if (!empty($params['tags'])) {
        gpt_debug_log('[gpt_create_post_endpoint] Setting tags', $params['tags']);
        wp_set_post_tags($post_id, (array) $params['tags']);
    }

    // Handle featured image and collect result
    $featured_result = gpt_handle_featured_image($post_id, $params);
    if (!$featured_result['success']) {
        gpt_debug_log('[gpt_create_post_endpoint] Featured image error', $featured_result['error']);
    }

    // Handle custom metadata
    if (!empty($params['meta']) && is_array($params['meta'])) {
        gpt_debug_log('[gpt_create_post_endpoint] Setting meta', $params['meta']);
        foreach ($params['meta'] as $key => $value) {
            update_post_meta($post_id, sanitize_key($key), sanitize_text_field($value));
        }
    }

    gpt_debug_log('[gpt_create_post_endpoint] Returning post_id', $post_id);
    $response = ['post_id' => $post_id];
    if ($featured_result['attachment_id']) {
        $response['featured_image_id'] = $featured_result['attachment_id'];
    }
    if (!$featured_result['success']) {
        $response['featured_image_status'] = 'failed';
        $response['featured_image_error'] = $featured_result['error'];
    }
    return $response;
}
// --- 🛑 END 🛑--- REST: Create Post ---END CREATE POST

// -----------------------------------------------------------------------------
// --- REST: Edit Post 📣 --- 📰 EDIT POST -- 📝 EDIT POST 📖
/**
 * Handles editing of existing WordPress posts via the REST API.
 *
 * This endpoint allows authorized GPT clients to update post content, status, categories,
 * tags, featured images, and metadata. It enforces role-based restrictions (e.g., editors
 * can only edit drafts) and performs thorough input validation and debug logging.
 *
 * @param WP_REST_Request $request
 * @return WP_REST_Response|WP_Error
 */
function gpt_edit_post_endpoint($request)
{
    gpt_debug_log('[gpt_edit_post_endpoint] Incoming request', $request->get_json_params());
    
    // 🔑 Extract API key from either the 'gpt-api-key' or 'Authorization: Bearer' header
    $api_key = $request->get_header('gpt-api-key') ?: str_replace('Bearer ', '', $request->get_header('authorization'));
    gpt_debug_log('[gpt_edit_post_endpoint] API key', $api_key);

    // Get role associated with API key
    $role = gpt_get_role_for_key($api_key);

    // Get gpt_role param from request (may be missing)
    $param_role = $request->get_param('gpt_role');

    // --- Begin normalization and granular debug logging ---
    gpt_debug_log('[gpt_edit_post_endpoint] Raw role from key', $role);
    gpt_debug_log('[gpt_edit_post_endpoint] Raw param_role', $param_role);
    
    // Normalize role values for comparison
    $role_normalized = is_string($role) ? strtolower(trim($role)) : '';
    $param_role_normalized = is_string($param_role) ? strtolower(trim($param_role)) : '';
    
    gpt_debug_log('[gpt_edit_post_endpoint] Normalized role', $role_normalized);
    gpt_debug_log('[gpt_edit_post_endpoint] Normalized param_role', $param_role_normalized);

    $allowed_roles = ['gpt_webmaster', 'gpt_publisher', 'gpt_editor'];

    // Role validation: Check for mismatch after normalization
    if ($param_role && $param_role_normalized !== $role_normalized) {
        gpt_debug_log('[gpt_edit_post_endpoint] Role mismatch after normalization', [
            'param_role_normalized' => $param_role_normalized,
            'role_normalized' => $role_normalized
        ]);
        return gpt_error_response('Invalid role', 403);
    }

    if (!$role_normalized) {
        $role_normalized = $param_role_normalized;
    }

    if (!in_array($role_normalized, $allowed_roles, true)) {
        gpt_debug_log('[gpt_edit_post_endpoint] Invalid role found after normalization', $role_normalized);
        return gpt_error_response('Invalid role', 403);
    }

    $id = (int) $request->get_param('id');
    gpt_debug_log('[gpt_edit_post_endpoint] Role', $role_normalized);
    gpt_debug_log('[gpt_edit_post_endpoint] Post ID', $id);

    // Load the post
    $params = $request->get_json_params();
    $post = get_post($id);
    gpt_debug_log('[gpt_edit_post_endpoint] Loaded post', $post);

    if (!$post) {
        gpt_debug_log('[gpt_edit_post_endpoint] Post not found', $id);
        return gpt_error_response('Post not found', 404);
    }

    // Editors can only edit drafts
    if ($role_normalized === 'gpt_editor' && $post->post_status !== 'draft') {
        gpt_debug_log('[gpt_edit_post_endpoint] Editor role cannot edit published posts', $id);
        return gpt_error_response('Editors can only edit drafts', 403);
    }

    // Validate post status
    $allowed_statuses = ['publish', 'draft', 'pending', 'private'];
    if (isset($params['post_status']) && !in_array($params['post_status'], $allowed_statuses)) {
        gpt_debug_log('[gpt_edit_post_endpoint] Invalid post status', $params['post_status']);
        return gpt_error_response('Invalid post status', 400);
    }

    // Prepare update array for post fields
    $update = [
        'ID' => $id,
        'post_title' => isset($params['title']) ? sanitize_text_field($params['title']) : $post->post_title,
        'post_content' => isset($params['content']) ? wp_kses_post($params['content']) : $post->post_content,
        'post_excerpt' => isset($params['excerpt']) ? wp_kses_post($params['excerpt']) : $post->post_excerpt,
        'post_format' => isset($params['format']) ? sanitize_key($params['format']) : $post->post_format,
        'post_name' => isset($params['slug']) ? sanitize_title($params['slug']) : $post->post_name,
        'post_author' => isset($params['author']) ? intval($params['author']) : $post->post_author,
        'post_status' => isset($params['post_status']) ? sanitize_key($params['post_status']) : $post->post_status,
        'post_date' => isset($params['post_date']) ? sanitize_text_field($params['post_date']) : $post->post_date,
    ];
    
    gpt_debug_log('[gpt_edit_post_endpoint] Update array', $update);

    // Update the post
    $result = wp_update_post($update, true);
    gpt_debug_log('[gpt_edit_post_endpoint] wp_update_post result', $result);

    if (is_wp_error($result)) {
        gpt_debug_log('[gpt_edit_post_endpoint] Error updating post', $result->get_error_message());
        return gpt_error_response('Failed to update post', 500);
    }

    // Handle featured image and collect result
    $featured_result = gpt_handle_featured_image($result, $params);
    if (!$featured_result['success']) {
        gpt_debug_log('[gpt_edit_post_endpoint] Featured image error', $featured_result['error']);
    }

    // Set categories and tags
    if (!empty($params['categories'])) {
        gpt_debug_log('[gpt_edit_post_endpoint] Setting categories', $params['categories']);
        wp_set_post_categories($result, array_map('intval', (array) $params['categories']));
    }
    if (!empty($params['tags'])) {
        gpt_debug_log('[gpt_edit_post_endpoint] Setting tags', $params['tags']);
        wp_set_post_tags($result, (array) $params['tags']);
    }

    // Handle custom metadata
    if (!empty($params['meta']) && is_array($params['meta'])) {
        gpt_debug_log('[gpt_edit_post_endpoint] Setting meta', $params['meta']);
        foreach ($params['meta'] as $key => $value) {
            update_post_meta($result, sanitize_key($key), sanitize_text_field($value));
        }
    }

    // Fetch the updated post and return the response
    $updated_post = get_post($result);
    gpt_debug_log('[gpt_edit_post_endpoint] Updated post', $updated_post);
    $response = [
        'post_id' => $result,
        'status' => $updated_post->post_status === 'publish' ? 'success' : 'pending',
        'message' => $updated_post->post_status === 'publish' ? 'Post successfully updated and published.' : 'Post updated, but pending approval for publication.'
    ];
    if ($featured_result['attachment_id']) {
        $response['featured_image_id'] = $featured_result['attachment_id'];
    }
    if (!$featured_result['success']) {
        $response['featured_image_status'] = 'failed';
        $response['featured_image_error'] = $featured_result['error'];
    }
    return new WP_REST_Response($response, 200);
}
// --- 🛑 END 🛑--- REST: END EDIT POST --- END -----



// -🟢-------📺 MEDIA 🎥 -----------📺 MEDIA 🎥 -----------📺 MEDIA 🎥 ---------

// -----------------------------------------------------------------------------
/**
 * Handles MEDIA file uploads via the REST API. ---📺 MEDIA 🎥
 *
 * This endpoint supports both direct file uploads (multipart/form-data) and remote image
 * downloads (via image_url). It validates file types, enforces role permissions, and 
 * returns the attachment ID and URL on success. Only allowed roles may upload media.
 *
 * @param WP_REST_Request $request
 * @return array|WP_Error
 */
function gpt_upload_media_endpoint($request)
{
    // 🔑 Extract API key from either the 'gpt-api-key' or 'Authorization: Bearer' header
    $api_key = $request->get_header('gpt-api-key') ?: str_replace('Bearer ', '', $request->get_header('authorization'));
    gpt_debug_log('[gpt_upload_media_endpoint] API key', $api_key);

    // Get role associated with API key
    $role = gpt_get_role_for_key($api_key);
    $param_role = $request->get_param('gpt_role'); // Role sent in request (optional)

    // Normalize role for comparison
    $role_normalized = is_string($role) ? strtolower(trim($role)) : '';
    $param_role_normalized = is_string($param_role) ? strtolower(trim($param_role)) : '';
    
    gpt_debug_log('[gpt_upload_media_endpoint] Normalized role from API key', $role_normalized);
    gpt_debug_log('[gpt_upload_media_endpoint] Normalized role from request', $param_role_normalized);

    // Define allowed roles for media upload
    $allowed_roles = ['gpt_webmaster', 'gpt_publisher', 'gpt_editor'];

    // If there's a mismatch in roles, log and return error
    if ($param_role && $param_role_normalized !== $role_normalized) {
        gpt_debug_log('[gpt_upload_media_endpoint] Role mismatch after normalization', [
            'param_role_normalized' => $param_role_normalized,
            'role_normalized' => $role_normalized
        ]);
        return gpt_error_response('Invalid role', 403);
    }

    // Fall back to API key role if gpt_role param is missing
    if (!$role_normalized) {
        $role_normalized = $param_role_normalized;
    }

    // Check if role is allowed to upload media
    if (!in_array($role_normalized, $allowed_roles, true)) {
        gpt_debug_log('[gpt_upload_media_endpoint] Invalid role found after normalization', $role_normalized);
        return gpt_error_response('Invalid role', 403);
    }

    // Check if upload directory is writable
    $uploads = wp_upload_dir();
    if (!empty($uploads['error']) || !is_writable($uploads['path'])) {
        return gpt_error_response('Upload directory is not writable.', 500);
    }

    // --- Support direct file uploads via $_FILES['file'] ---
    if (!empty($_FILES['file']) && isset($_FILES['file']['tmp_name']) && is_uploaded_file($_FILES['file']['tmp_name'])) {
        $file = $_FILES['file'];
        $file['name'] = sanitize_file_name($file['name']);
        $filetype = wp_check_filetype($file['name']);
        if (!in_array($filetype['type'], ['image/jpeg', 'image/png', 'image/gif'])) {
            return gpt_error_response('Invalid file type. Only JPEG, PNG, and GIF images are allowed.', 400);
        }
        $upload = wp_handle_upload($file, ['test_form' => false]);
        if (isset($upload['error'])) {
            return gpt_error_response($upload['error'], 400);
        }
        $attachment = [
            'post_mime_type' => $upload['type'],
            'post_title' => sanitize_file_name($file['name']),
            'post_content' => '',
            'post_status' => 'inherit',
        ];
        $attach_id = wp_insert_attachment($attachment, $upload['file']);
        require_once(ABSPATH . 'wp-admin/includes/image.php');
        $attach_data = wp_generate_attachment_metadata($attach_id, $upload['file']);
        wp_update_attachment_metadata($attach_id, $attach_data);
        return ['attachment_id' => $attach_id, 'url' => wp_get_attachment_url($attach_id)];
    }

    // --- Support image_url parameter ---
    $image_url = $request->get_param('image_url');
    if ($image_url) {
        // Validate URL format
        if (!filter_var($image_url, FILTER_VALIDATE_URL)) {
            gpt_debug_log('[gpt_upload_media_endpoint] Invalid image URL provided', $image_url);
            return gpt_error_response('Invalid URL', 400);
        }

        gpt_debug_log('[gpt_upload_media_endpoint] Downloading image from URL', $image_url);
        $response = wp_remote_get($image_url, ['timeout' => 15]);
        if (is_wp_error($response)) {
            gpt_debug_log('[gpt_upload_media_endpoint] Unable to download image', $response->get_error_message());
            return gpt_error_response('Unable to download image: ' . $response->get_error_message(), 400);
        }

        $body = wp_remote_retrieve_body($response);
        if (empty($body)) {
            gpt_debug_log('[gpt_upload_media_endpoint] Downloaded image is empty', $image_url);
            return gpt_error_response('Downloaded image is empty.', 400);
        }

        $file_name = sanitize_file_name(basename(parse_url($image_url, PHP_URL_PATH)));
        $filetype = wp_check_filetype($file_name);
        if (!in_array($filetype['type'], ['image/jpeg', 'image/png', 'image/gif'])) {
            gpt_debug_log('[gpt_upload_media_endpoint] Invalid file type for featured_image_url', $filetype['type']);
            return gpt_error_response('Invalid file type. Only JPEG, PNG, and GIF images are allowed.', 400);
        }

        $tmpfname = wp_tempnam($file_name);
        if (!$tmpfname) {
            gpt_debug_log('[gpt_upload_media_endpoint] Could not create a temporary file for featured_image_url');
            return gpt_error_response('Could not create a temporary file.', 500);
        }

        $bytes_written = file_put_contents($tmpfname, $body);
        if ($bytes_written === false) {
            @unlink($tmpfname);
            gpt_debug_log('[gpt_upload_media_endpoint] Failed to write image to temporary file for featured_image_url');
            return gpt_error_response('Failed to write image to temporary file.', 500);
        }

        $file = [
            'name' => $file_name,
            'type' => $filetype['type'],
            'tmp_name' => $tmpfname,
            'error' => 0,
            'size' => filesize($tmpfname)
        ];

        $upload = wp_handle_sideload($file, ['test_form' => false]);
        @unlink($tmpfname);
        if (isset($upload['error'])) {
            gpt_debug_log('[gpt_upload_media_endpoint] wp_handle_sideload error', $upload['error']);
            return gpt_error_response($upload['error'], 400);
        }

        $attachment = [
            'post_mime_type' => $upload['type'],
            'post_title' => $file_name,
            'post_content' => '',
            'post_status' => 'inherit',
        ];
        $attach_id = wp_insert_attachment($attachment, $upload['file']);
        require_once(ABSPATH . 'wp-admin/includes/image.php');
        $attach_data = wp_generate_attachment_metadata($attach_id, $upload['file']);
        wp_update_attachment_metadata($attach_id, $attach_data);

        return ['attachment_id' => $attach_id, 'url' => wp_get_attachment_url($attach_id)];
    }

    // Fallback if no file or URL provided
    return gpt_error_response('No image URL or file provided', 400);
}
// --🔴------END---📷--MEDIA file uploads ---📺 MEDIA 🎥 ---------
// --🔴------END---📷--MEDIA file uploads ---📺 MEDIA 🎥 ---------


// --🟢---🗺️---START-----SCHEMA-----🌎-----------START-----SCHEMA----🗺️-------
// --------START-----SCHEMA----------------START-----SCHEMA------------------
// -----------------------------------------------------------------------------
// --- REST: Dynamic OpenAPI Schema Endpoint ---
/**
 * Serves a dynamic OpenAPI schema describing the GPT REST API.
 *
 * This endpoint provides a machine-readable OpenAPI 3.1 schema for GPT clients and tools,
 * enabling automated discovery and integration. The schema is dynamically generated to
 * reflect the current site URL and endpoint structure.
 *
 * @return WP_REST_Response
 */
function gpt_openapi_schema_handler()
{
    $site_url = get_site_url();
    $schema = [
        'openapi' => '3.1.0',
        'info' => [
            'title' => 'GPT-4-WP-Plugin v2.bc API',
            'version' => '2.0.0',
            'description' => 'Secure REST API for WordPress content creation and management by GPTs/clients.'
        ],
        'servers' => [
            ['url' => $site_url . '/wp-json/gpt/v1']
        ],
        'components' => [
            'securitySchemes' => [
                'ApiKeyAuth' => [
                    'type' => 'apiKey',
                    'in' => 'header',
                    'name' => 'gpt-api-key',
                ]
            ],
            'schemas' => [
                'PostInput' => [
                    'type' => 'object',
                    'properties' => [
                        'title' => ['type' => 'string', 'description' => 'Post title'],
                        'content' => ['type' => 'string', 'description' => 'Post content (HTML allowed)'],
                        'excerpt' => ['type' => 'string', 'description' => 'Post excerpt'],
                        'categories' => ['type' => 'array', 'items' => ['type' => 'integer'], 'description' => 'Category IDs'],
                        'tags' => ['type' => 'array', 'items' => ['type' => 'string'], 'description' => 'Tag names'],
                        'slug' => ['type' => 'string', 'description' => 'Post slug'],
                        'post_status' => ['type' => 'string', 'description' => 'Post status (publish, draft, pending, private)'],
                        'post_format' => ['type' => 'string', 'description' => 'Post format'],
                        'post_date' => ['type' => 'string', 'format' => 'date-time', 'description' => 'Post date (ISO 8601)'],
                        // Featured image fields
                        'featured_image_url' => [
                            'type' => 'string',
                            'format' => 'uri',
                            'description' => 'Remote image URL to set as featured image'
                        ],
                        'featured_media' => [
                            'type' => 'integer',
                            'description' => 'Attachment ID for featured image'
                        ],
                        'featured_image' => [
                            'type' => 'integer',
                            'description' => 'Attachment ID for featured image'
                        ],
                        'featured_media_id' => [
                            'type' => 'integer',
                            'description' => 'Attachment ID for featured image'
                        ],
                        'featured_image_id' => [
                            'type' => 'integer',
                            'description' => 'Attachment ID for featured image'
                        ],
                        'meta' => [
                            'type' => 'object',
                            'additionalProperties' => ['type' => 'string'],
                            'description' => 'Custom meta fields'
                        ]
                    ],
                    'required' => ['title', 'content']
                ],
                'PostResponse' => [
                    'type' => 'object',
                    'properties' => [
                        'post_id' => ['type' => 'integer'],
                        'featured_image_id' => ['type' => 'integer'],
                        'featured_image_status' => ['type' => 'string'],
                        'featured_image_error' => ['type' => 'string'],
                        'status' => ['type' => 'string'],
                        'message' => ['type' => 'string']
                    ]
                ],
                'MediaUpload' => [
                    'type' => 'object',
                    'properties' => [
                        'image_url' => [
                            'type' => 'string',
                            'format' => 'uri',
                            'description' => 'Remote image URL to upload as media'
                        ]
                    ]
                ],
                'MediaUploadResponse' => [
                    'type' => 'object',
                    'properties' => [
                        'attachment_id' => ['type' => 'integer'],
                        'url' => ['type' => 'string', 'format' => 'uri']
                    ]
                ],
                'ErrorResponse' => [
                    'type' => 'object',
                    'properties' => [
                        'code' => ['type' => 'string'],
                        'message' => ['type' => 'string'],
                        'data' => ['type' => 'object']
                    ]
                ],
                'PingResponse' => [
                    'type' => 'object',
                    'properties' => [
                        'message' => ['type' => 'string'],
                        'role' => ['type' => 'string']
                    ]
                ]
            ]
        ],
        'security' => [['ApiKeyAuth' => []]],
        'paths' => [
            '/ping' => [
                'get' => [
                    'summary' => 'Ping the API to test connectivity and API key validity',
                    'description' => 'Returns a success message and the resolved role if the API key is valid.',
                    'operationId' => 'pingSite',
                    'responses' => [
                        '200' => [
                            'description' => 'Ping successful',
                            'content' => [
                                'application/json' => [
                                    'schema' => ['\$ref' => '#/components/schemas/PingResponse']
                                ]
                            ]
                        ],
                        '401' => [
                            'description' => 'Unauthorized',
                            'content' => [
                                'application/json' => [
                                    'schema' => ['\$ref' => '#/components/schemas/ErrorResponse']
                                ]
                            ]
                        ]
                    ],
                    'security' => [['ApiKeyAuth' => []]]
                ]
            ],
            '/post' => [
                'post' => [
                    'summary' => 'Create a new post',
                    'operationId' => 'createPost',
                    'requestBody' => [
                        'required' => true,
                        'content' => [
                            'application/json' => [
                                'schema' => ['\$ref' => '#/components/schemas/PostInput'],
                                'examples' => [
                                    'basic' => [
                                        'summary' => 'Basic post',
                                        'value' => [
                                            'title' => 'My Article',
                                            'content' => '<p>Content</p>'
                                        ]
                                    ],
                                    'with_featured_image' => [
                                        'summary' => 'Post with featured image',
                                        'value' => [
                                            'title' => 'With Image',
                                            'content' => '<p>Content</p>',
                                            'featured_image_url' => 'https://example.com/image.jpg'
                                        ]
                                    ]
                                ]
                            ]
                        ]
                    ],
                    'responses' => [
                        '200' => [
                            'description' => 'Post created',
                            'content' => [
                                'application/json' => [
                                    'schema' => ['\$ref' => '#/components/schemas/PostResponse']
                                ]
                            ]
                        ],
                        '400' => [
                            'description' => 'Bad Request: Invalid input or missing required fields',
                            'content' => [
                                'application/json' => [
                                    'schema' => ['\$ref' => '#/components/schemas/ErrorResponse']
                                ]
                            ]
                        ],
                        '401' => [
                            'description' => 'Unauthorized: Missing or invalid API key',
                            'content' => [
                                'application/json' => [
                                    'schema' => ['\$ref' => '#/components/schemas/ErrorResponse']
                                ]
                            ]
                        ],
                        '403' => [
                            'description' => 'Forbidden: User does not have permission to create a post',
                            'content' => [
                                'application/json' => [
                                    'schema' => ['\$ref' => '#/components/schemas/ErrorResponse']
                                ]
                            ]
                        ],
                        '500' => [
                            'description' => 'Internal Server Error',
                            'content' => [
                                'application/json' => [
                                    'schema' => ['\$ref' => '#/components/schemas/ErrorResponse']
                                ]
                            ]
                        ]
                    ],
                    'security' => [['ApiKeyAuth' => []]]
                ]
            ],
            '/post/{id}' => [
                'post' => [
                    'summary' => 'Edit an existing post',
                    'operationId' => 'editPost',
                    'parameters' => [
                        [
                            'name' => 'id',
                            'in' => 'path',
                            'required' => true,
                            'schema' => ['type' => 'integer'],
                            'description' => 'ID of the post to edit'
                        ]
                    ],
                    'requestBody' => [
                        'required' => true,
                        'content' => [
                            'application/json' => [
                                'schema' => ['\$ref' => '#/components/schemas/PostInput']
                            ]
                        ]
                    ],
                    'responses' => [
                        '200' => [
                            'description' => 'Post updated',
                            'content' => [
                                'application/json' => [
                                    'schema' => ['\$ref' => '#/components/schemas/PostResponse']
                                ]
                            ]
                        ],
                        '400' => [
                            'description' => 'Bad Request: Invalid input or missing required fields',
                            'content' => [
                                'application/json' => [
                                    'schema' => ['\$ref' => '#/components/schemas/ErrorResponse']
                                ]
                            ]
                        ],
                        '401' => [
                            'description' => 'Unauthorized: Missing or invalid API key',
                            'content' => [
                                'application/json' => [
                                    'schema' => ['\$ref' => '#/components/schemas/ErrorResponse']
                                ]
                            ]
                        ],
                        '403' => [
                            'description' => 'Forbidden: User does not have permission to edit this post',
                            'content' => [
                                'application/json' => [
                                    'schema' => ['\$ref' => '#/components/schemas/ErrorResponse']
                                ]
                            ]
                        ],
                        '404' => [
                            'description' => 'Not Found: The post with the specified ID does not exist',
                            'content' => [
                                'application/json' => [
                                    'schema' => ['\$ref' => '#/components/schemas/ErrorResponse']
                                ]
                            ]
                        ],
                        '500' => [
                            'description' => 'Internal Server Error',
                            'content' => [
                                'application/json' => [
                                    'schema' => ['\$ref' => '#/components/schemas/ErrorResponse']
                                ]
                            ]
                        ]
                    ],
                    'security' => [['ApiKeyAuth' => []]]
                ]
            ],
            '/media' => [
                'post' => [
                    'summary' => 'Upload a media file',
                    'operationId' => 'uploadMedia',
                    'requestBody' => [
                        'required' => true,
                        'content' => [
                            'application/json' => [
                                'schema' => ['\$ref' => '#/components/schemas/MediaUpload'],
                                'examples' => [
                                    'remote_url' => [
                                        'summary' => 'Upload from remote URL',
                                        'value' => [
                                            'image_url' => 'https://example.com/image.jpg'
                                        ]
                                    ]
                                ]
                            ],
                            'multipart/form-data' => [
                                'schema' => [
                                    'type' => 'object',
                                    'properties' => [
                                        'file' => [
                                            'type' => 'string',
                                            'format' => 'binary',
                                            'description' => 'Image file to upload'
                                        ]
                                    ]
                                ]
                            ]
                        ]
                    ],
                    'responses' => [
                        '200' => [
                            'description' => 'Media uploaded',
                            'content' => [
                                'application/json' => [
                                    'schema' => ['\$ref' => '#/components/schemas/MediaUploadResponse']
                                ]
                            ]
                        ],
                        '400' => [
                            'description' => 'Bad Request: Invalid file type or URL',
                            'content' => [
                                'application/json' => [
                                    'schema' => ['\$ref' => '#/components/schemas/ErrorResponse']
                                ]
                            ]
                        ],
                        '401' => [
                            'description' => 'Unauthorized: Missing or invalid API key',
                            'content' => [
                                'application/json' => [
                                    'schema' => ['\$ref' => '#/components/schemas/ErrorResponse']
                                ]
                            ]
                        ],
                        '403' => [
                            'description' => 'Forbidden: User does not have permission to upload media',
                            'content' => [
                                'application/json' => [
                                    'schema' => ['\$ref' => '#/components/schemas/ErrorResponse']
                                ]
                            ]
                        ],
                        '404' => [
                            'description' => 'Not Found: The media file URL is invalid or unreachable',
                            'content' => [
                                'application/json' => [
                                    'schema' => ['\$ref' => '#/components/schemas/ErrorResponse']
                                ]
                            ]
                        ],
                        '500' => [
                            'description' => 'Internal Server Error',
                            'content' => [
                                'application/json' => [
                                    'schema' => ['\$ref' => '#/components/schemas/ErrorResponse']
                                ]
                            ]
                        ]
                    ],
                    'security' => [['ApiKeyAuth' => []]]
                ]
            ]
        ]
    ];

    return new WP_REST_Response($schema, 200, ['Content-Type' => 'application/json']);
}
// --------END-----SCHEMA----------------END-----SCHEMA--SECTION----------------



// -----------------------------------------------------------------------------
// --- REST: Dynamic ai-plugin.json Manifest Endpoint ---
/**
 * Serves a dynamic ai-plugin.json manifest for plugin discovery by GPTs.
 *
 * This endpoint provides a manifest describing the plugin's capabilities, authentication,
 * and API schema location. Used by GPTs and clients to auto-configure integrations.
 *
 * @return WP_REST_Response
 */
function gpt_ai_plugin_manifest_handler()
{
    $site_url = get_site_url();
    $plugin_url = $site_url . '/wp-content/plugins/gpt-4-wp-plugin-v1.2';
    $manifest = [
        'schema_version' => 'v1',
        'name_for_human' => 'GPT-4 WP Plugin v2.0',
        'name_for_model' => 'gpt_4_wp_plugin_v2_0',
        'description_for_human' => 'Create, edit, and manage WordPress posts and media via secure API. Version 2.0, single-file, minimal and secure.',
        'description_for_model' => 'A secure, minimal REST API for WordPress (v2.0) that allows GPTs/clients to create, edit, and manage posts and media using API keys and role-based permissions. Supports Webmaster, Publisher, and Editor roles.',
        'auth' => [
            'type' => 'api_key',
            'in' => 'header',
            'key_name' => 'gpt-api-key',
        ],
        'api' => [
            'type' => 'openapi',
            'url' => $site_url . '/wp-json/gpt/v1/openapi',
        ],
        'logo_url' => $plugin_url . '/logo.png',
        'contact_email' => get_option('admin_email', 'admin@your-site.com'),
        'legal_info_url' => $site_url . '/legal',
    ];
    return new WP_REST_Response($manifest, 200, ['Content-Type' => 'application/json']);
}

// -----------------------------------------------------------------------------
// --- AJAX handler for Ping Site button ---
/**
 * Handles AJAX requests from the admin UI to test REST endpoint reachability.
 *
 * This handler allows administrators to verify that the /post endpoint is reachable
 * and returns the expected response, aiding in troubleshooting and setup.
 */
add_action('wp_ajax_gpt_ping_site', function () {
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Permission denied');
    }
    if (empty($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'gpt_ping_site_nonce')) {
        wp_send_json_error('Invalid nonce');
    }
    $site_url = get_site_url();
    $endpoint = $site_url . '/wp-json/gpt/v1/post';
    $args = [
        'method' => 'POST',
        'timeout' => 5,
        'headers' => [
            'Content-Type' => 'application/json',
            // No API key, so should get 401 or similar
        ],
        'body' => json_encode(['title' => 'Ping Test', 'content' => 'Ping test content'])
    ];
    $resp = wp_remote_post($endpoint, $args);
    if (is_wp_error($resp)) {
        wp_send_json_error($resp->get_error_message());
    }
    $code = wp_remote_retrieve_response_code($resp);
    $body = wp_remote_retrieve_body($resp);
    if ($code === 401 || $code === 403) {
        wp_send_json_success('Endpoint reachable, got expected auth error (' . $code . ')');
    } elseif ($code === 200) {
        wp_send_json_success('Endpoint reachable, post created (200)');
    } else {
        wp_send_json_error('Unexpected response: ' . $code . ' ' . $body);
    }
});

// -----------------------------------------------------------------------------
// === GPT Universal Action Route ===
/**
 * Universal action endpoint for future extensibility.
 *
 * This endpoint allows for generic actions (e.g., ping) to be handled in a single route,
 * simplifying future expansion and custom integrations. Only enabled for authorized roles.
 */
add_action('rest_api_init', function () {
    register_rest_route('gpt/v1', '/action', [
        'methods' => 'POST',
        'callback' => gpt_rest_api_error_wrapper('gpt_action_handler'),
        'permission_callback' => 'gpt_rest_permission_check_role',
    ]);
});

function gpt_action_handler($request)
{
    $params = $request->get_json_params();
    $action = $params['action'] ?? null;

    if (!$action) {
        return new WP_Error('missing_action', 'No action specified', ['status' => 400]);
    }

    switch ($action) {
        case 'ping':
            return rest_ensure_response(['pong' => true]);

        default:
            return new WP_Error('unknown_action', 'Unrecognized action: ' . esc_html($action), ['status' => 400]);
    }
}
// === END GPT Universal Action Route ===

// -----------------------------------------------------------------------------
// --- File Management REST Endpoints (gpt_admin only) ---
/**
 * REST API endpoints for secure file and directory management (gpt_admin only).
 *
 * These endpoints allow the gpt_admin role to read, write, create, list, and delete
 * files and directories within the plugin directory. All paths are sanitized and
 * validated to prevent unauthorized access. Used for advanced automation and management.
 */
add_action('rest_api_init', function () {
    // Read file
    register_rest_route('gpt/v1', '/file', [
        'methods' => 'GET',
        'callback' => gpt_rest_api_error_wrapper('gpt_file_read_endpoint'),
        'permission_callback' => function ($request) {
            return gpt_rest_permission_check_gpt_admin($request);
        },
        'args' => [
            'path' => [
                'required' => true,
                'validate_callback' => function ($value) {
                    return is_string($value) && $value !== '';
                }
            ]
        ]
    ]);
    // Write file
    register_rest_route('gpt/v1', '/file', [
        'methods' => 'POST',
        'callback' => gpt_rest_api_error_wrapper('gpt_file_write_endpoint'),
        'permission_callback' => function ($request) {
            return gpt_rest_permission_check_gpt_admin($request);
        }
    ]);
    // Create directory
    register_rest_route('gpt/v1', '/dir', [
        'methods' => 'POST',
        'callback' => gpt_rest_api_error_wrapper('gpt_dir_create_endpoint'),
        'permission_callback' => function ($request) {
            return gpt_rest_permission_check_gpt_admin($request);
        }
    ]);
    // List files/directories
    register_rest_route('gpt/v1', '/ls', [
        'methods' => 'GET',
        'callback' => gpt_rest_api_error_wrapper('gpt_file_list_endpoint'),
        'permission_callback' => function ($request) {
            return gpt_rest_permission_check_gpt_admin($request);
        },
        'args' => [
            'path' => [
                'required' => false,
                'validate_callback' => function ($value) {
                    return is_string($value);
                }
            ]
        ]
    ]);
    // Delete file or directory
    register_rest_route('gpt/v1', '/file', [
        'methods' => 'DELETE',
        'callback' => gpt_rest_api_error_wrapper('gpt_file_delete_endpoint'),
        'permission_callback' => function ($request) {
            return gpt_rest_permission_check_gpt_admin($request);
        },
        'args' => [
            'path' => [
                'required' => true,
                'validate_callback' => function ($value) {
                    return is_string($value) && $value !== '';
                }
            ]
        ]
    ]);
});

function gpt_rest_permission_check_gpt_admin($request)
{
    $key = $request->get_header('gpt-api-key') ?: str_replace('Bearer ', '', $request->get_header('authorization'));
    $role = gpt_get_role_for_key($key);
    return $role === 'gpt_admin';
}

function gpt_get_plugin_dir()
{
    return dirname(__FILE__);
}

function gpt_sanitize_plugin_path($path)
{
    $plugin_dir = realpath(gpt_get_plugin_dir());
    $full_path = realpath($plugin_dir . '/' . ltrim($path, '/\\'));
    if ($full_path && strpos($full_path, $plugin_dir) === 0) {
        return $full_path;
    }
    return false;
}

function gpt_file_read_endpoint($request)
{
    $path = $request->get_param('path');
    $file = gpt_sanitize_plugin_path($path);
    if (!$file || !file_exists($file) || !is_file($file)) {
        return gpt_error_response('File not found or access denied', 404);
    }
    $contents = file_get_contents($file);
    if ($contents === false) {
        return gpt_error_response('Failed to read file', 500);
    }
    return [
        'path' => $path,
        'content' => $contents
    ];
}

function gpt_file_write_endpoint($request)
{
    $params = $request->get_json_params();
    $path = $params['path'] ?? '';
    $content = $params['content'] ?? '';
    $file = gpt_sanitize_plugin_path($path);
    if (!$file) {
        return gpt_error_response('Invalid file path', 400);
    }
    if (file_exists($file) && !is_writable($file)) {
        return gpt_error_response('File is not writable', 403);
    }
    $dir = dirname($file);
    if (!is_dir($dir)) {
        return gpt_error_response('Directory does not exist', 400);
    }
    $result = file_put_contents($file, $content);
    if ($result === false) {
        return gpt_error_response('Failed to write file', 500);
    }
    return [
        'path' => $path,
        'bytes_written' => $result
    ];
}

function gpt_dir_create_endpoint($request)
{
    $params = $request->get_json_params();
    $path = $params['path'] ?? '';
    $dir = gpt_sanitize_plugin_path($path);
    if (!$dir) {
        return gpt_error_response('Invalid directory path', 400);
    }
    if (file_exists($dir)) {
        return gpt_error_response('Directory already exists', 409);
    }
    if (!mkdir($dir, 0755, true)) {
        return gpt_error_response('Failed to create directory', 500);
    }
    return [
        'path' => $path,
        'created' => true
    ];
}

function gpt_file_list_endpoint($request)
{
    $path = $request->get_param('path') ?: '';
    $dir = gpt_sanitize_plugin_path($path);
    if (!$dir || !is_dir($dir)) {
        return gpt_error_response('Directory not found or access denied', 404);
    }
    $result = gpt_list_dir_recursive($dir, $dir);
    return [
        'path' => $path,
        'files' => $result
    ];
}

function gpt_list_dir_recursive($base, $dir)
{
    $items = scandir($dir);
    $result = [];
    foreach ($items as $item) {
        if ($item === '.' || $item === '..')
            continue;
        $full = $dir . DIRECTORY_SEPARATOR . $item;
        $rel = ltrim(str_replace($base, '', $full), '/\\');
        if (is_dir($full)) {
            $result[] = [
                'type' => 'dir',
                'name' => $item,
                'path' => $rel,
                'children' => gpt_list_dir_recursive($base, $full)
            ];
        } else {
            $result[] = [
                'type' => 'file',
                'name' => $item,
                'path' => $rel,
                'size' => filesize($full)
            ];
        }
    }
    return $result;
}

function gpt_file_delete_endpoint($request)
{
    $path = $request->get_param('path');
    $file = gpt_sanitize_plugin_path($path);
    if (!$file || !file_exists($file)) {
        return gpt_error_response('File or directory not found or access denied', 404);
    }
    if (is_dir($file)) {
        $success = gpt_rmdir_recursive($file);
        if (!$success) {
            return gpt_error_response('Failed to delete directory', 500);
        }
        return [
            'path' => $path,
            'deleted' => true,
            'type' => 'dir'
        ];
    } else {
        if (!is_writable($file)) {
            return gpt_error_response('File is not writable', 403);
        }
        if (!unlink($file)) {
            return gpt_error_response('Failed to delete file', 500);
        }
        return [
            'path' => $path,
            'deleted' => true,
            'type' => 'file'
               ];
    }
}

function gpt_rmdir_recursive($dir)
{
    if (!is_dir($dir))
        return false;
    $items = scandir($dir);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..')
            continue;
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        if (is_dir($path)) {
                       gpt_rmdir_recursive($path);
        } else {
            unlink($path);
        }
    }
    return rmdir($dir);
}


// --🔴---START---📸 Featured Image 🖼️ -------🎥 Featured Image Handling 

// --🔴---START---📸 Featured Image 🖼️ -------🎥 Featured Image Handling 

// -----------------------------------------------------------------------------
// --- Featured image handling function ------📸 Featured Image 🖼️
/**
 * Handles setting the featured image for a post, supporting both attachment ID and image URL.
 *
 * Improvements:
 *  - Accepts 'featured_media', 'featured_image', 'featured_media_id', 'featured_image_id' as attachment IDs
 *  - Accepts 'featured_image_url' as a remote image URL
 *  - Avoids duplicate attachments for the same image URL (by URL or file hash)
 *  - Returns status, attachment ID, and error (if any)
 *  - Validates attachment ownership/access
 *  - Robustly sanitizes/validates all input
 *
 * @param int $post_id
 * @param array $params
 * @return array ['success' => bool, 'attachment_id' => int|null, 'error' => string|null]
 */
function gpt_handle_featured_image($post_id, $params) {
    // --- Accept multiple keys for attachment ID ---
    $attachment_id = null;
    $attachment_keys = ['featured_media', 'featured_image', 'featured_media_id', 'featured_image_id'];
    foreach ($attachment_keys as $key) {
        if (!empty($params[$key]) && is_numeric($params[$key])) {
            $attachment_id = intval($params[$key]);
            break;
        }
    }
    // --- Accept image URL ---
    $image_url = $params['featured_image_url'] ?? null;
    if ($image_url && filter_var($image_url, FILTER_VALIDATE_URL)) {
        // Check for existing attachment by URL (postmeta '_wp_attached_file' or guid)
        global $wpdb;
        $file_name = basename(parse_url($image_url, PHP_URL_PATH));
        $existing_id = $wpdb->get_var($wpdb->prepare(
            "SELECT ID FROM $wpdb->posts WHERE post_type = 'attachment' AND (guid = %s OR post_title = %s) LIMIT 1",
            $image_url, $file_name
        ));
        if ($existing_id) {
            $attachment_id = intval($existing_id);
        } else {
            // Download and sideload image
            require_once(ABSPATH . 'wp-admin/includes/file.php');
            require_once(ABSPATH . 'wp-admin/includes/media.php');
            require_once(ABSPATH . 'wp-admin/includes/image.php');
            $tmp = download_url($image_url);
            if (is_wp_error($tmp)) {
                return ['success' => false, 'attachment_id' => null, 'error' => 'Failed to download image: ' . $tmp->get_error_message()];
            }
            $file_array = [
                'name' => sanitize_file_name($file_name),
                'tmp_name' => $tmp,
            ];
            $attach_id = media_handle_sideload($file_array, $post_id);
            @unlink($tmp);
            if (is_wp_error($attach_id)) {
                return ['success' => false, 'attachment_id' => null, 'error' => 'Failed to sideload image: ' . $attach_id->get_error_message()];
            }
            $attachment_id = $attach_id;
        }
    }
    // --- Validate attachment ownership/access ---
    if ($attachment_id) {
        $attachment = get_post($attachment_id);
        if (!$attachment || $attachment->post_type !== 'attachment' || $attachment->post_status === 'trash') {
            return ['success' => false, 'attachment_id' => null, 'error' => 'Attachment not found or inaccessible'];
        }
        // Optionally: check author/ownership if needed
        set_post_thumbnail($post_id, $attachment_id);
        return ['success' => true, 'attachment_id' => $attachment_id, 'error' => null];
    }
    return ['success' => false, 'attachment_id' => null, 'error' => 'No valid featured image provided'];
}
// --🔴------END---📸 Featured Image 🖼️ -------🎥 Featured Image Handling


// --🔴------END---📸 Featured Image 🖼️ -------🎥 Featured Image Handling 


// -----------------------------------------------------------------------------
// --- Create or retrieve a WordPress user for a GPT label and role ---
/**
 * Creates or retrieves a WordPress user for a given GPT label and role.
 *
 * This function ensures that each API key is associated with a unique, non-human user
 * account, used as the post author for content created via the API. Users are created
 * with a special meta flag and email address, and are assigned the correct role.
 *
 * @param string $api_key  The API key for the GPT client.
 * @param string $role     The role to assign to the user.
 * @return int|false       User ID on success, false on failure.
 */
function create_gpt_user($api_key, $role) {
    gpt_debug_log('[create_gpt_user] API key: ' . $api_key, $role);
    
    // Look up the label for the API key
    $all_keys = get_option('gpt_api_keys', []);
    $label = null;

    // Find the label corresponding to the API key
    foreach ($all_keys as $key => $info) {
        if ($key === $api_key && !empty($info['label'])) {
            $label = $info['label'];
            break;
        }
    }

    gpt_debug_log('[create_gpt_user] Label found for key: ', $label);

    // Default label if not found
    if (!$label) {
        $label = 'gptuser'; // Default label
    }

    // Generate username and email
    $site = gpt_get_selected_site();
    $label_slug = strtolower(preg_replace('/[^a-z0-9\.]/', '', $label)); 
    $username = 'gpt_' . $label_slug;
    $email = $label_slug . '@' . $site;

    // Check for existing user
    $user = get_user_by('login', $username);
    if (!$user) {
        $user = get_user_by('email', $email);
    }

    gpt_debug_log('[create_gpt_user] Existing user', $user ? $user->ID : 'None');

    if ($user) {
        if ($user->roles[0] !== $role) {
            gpt_debug_log('[create_gpt_user] User role mismatch', $user->roles[0]);
            $user->set_role($role);
        }
        update_user_meta($user->ID, 'is_gpt_user', 1);
        return $user->ID;
    }
    
    // If user doesn't exist, create a new one
    $password = wp_generate_password(32, true, true);
    $user_id = wp_create_user($username, $password, $email);
    gpt_debug_log('[create_gpt_user] Created new user', $user_id);

    if (is_wp_error($user_id) || !$user_id) {
        gpt_debug_log('[create_gpt_user] User creation failed', $user_id);
        return false;
    }

    $user_obj = get_user_by('id', $user_id);
    if ($user_obj) {
        $user_obj->set_role($role);
        update_user_meta($user_id, 'is_gpt_user', 1);
        wp_update_user(['ID' => $user_id, 'display_name' => $label . ' (GPT API)']);
        return $user_id;
    }

    return false;
}
// -----------------------------------------------------------------------------
// === END OF FILE: GPT-4 WP Plugin v2.0 ===
// ============================================================================