<?php
/*
Plugin Name: GPT-4-WP-Plugin v1.2
Description: Simple REST API and API key management for GPTs with Webmaster, Publisher, and Editor roles. No bloat. Single-file version.
Version: 1.2.0
Author: Your Team
*/

// --- Centralized error response and logging helper (for use in REST endpoints) ---
if (!function_exists('gpt_error_response')) {
    function gpt_error_response($message, $status = 400, $data = [])
    {
        if (defined('GPT_PLUGIN_DEBUG') && GPT_PLUGIN_DEBUG) {
            error_log('[GPT-4-WP-Plugin] ERROR: ' . $message . (empty($data) ? '' : ' | Data: ' . print_r($data, true)));
        }
        return new WP_Error('gpt_error', esc_html($message), array_merge(['status' => $status], $data));
    }
}

// --- REST API error handling wrapper ---
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
        } catch (Exception $e) {
            if (defined('GPT_PLUGIN_DEBUG') && GPT_PLUGIN_DEBUG) {
                error_log('[GPT-4-WP-Plugin] Exception: ' . $e->getMessage());
            }
            return gpt_error_response('Internal server error', 500);
        }
    };
}

// --- Register custom roles on plugin activation ---
register_activation_hook(__FILE__, function () {
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

// --- Remove custom roles on deactivation ---
register_deactivation_hook(__FILE__, function () {
    remove_role('gpt_webmaster');
    remove_role('gpt_publisher');
    remove_role('gpt_editor');
});

// --- API Key Management: Admin UI ---
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
        'gpt_webmaster' => 'Webmaster',
        'gpt_publisher' => 'Publisher',
        'gpt_editor' => 'Editor',
    ];
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
    // REST API endpoint reachability
    echo '<ul style="list-style:none;padding-left:0;">';
    echo '<li>';
    echo $openapi_ok ? '<span style="color:green;">&#x2705; OpenAPI endpoint reachable</span>' : '<span style="color:red;">&#x274C; OpenAPI endpoint unreachable: ' . esc_html(is_wp_error($openapi_resp) ? $openapi_resp->get_error_message() : wp_remote_retrieve_response_code($openapi_resp)) . '</span>';
    echo '</li>';
    echo '<li>';
    echo $manifest_ok ? '<span style="color:green;">&#x2705; ai-plugin.json endpoint reachable</span>' : '<span style="color:red;">&#x274C; ai-plugin.json endpoint unreachable: ' . esc_html(is_wp_error($manifest_resp) ? $manifest_resp->get_error_message() : wp_remote_retrieve_response_code($manifest_resp)) . '</span>';
    echo '</li>';
    // API key existence
    echo '<li>';
    if (count($keys) > 0) {
        echo '<span style="color:green;">&#x2705; At least one API key exists</span>';
    } else {
        echo '<span style="color:red;">&#x274C; No API keys found. GPTs cannot connect.</span>';
    }
    echo '</li>';
    // Permalink structure
    echo '<li>';
    if ($permalink_structure && $permalink_structure !== '') {
        echo '<span style="color:green;">&#x2705; Permalinks are set to Pretty</span>';
    } else {
        echo '<span style="color:orange;">&#x26A0; Permalinks are set to Plain. REST API may not work optimally.</span>';
    }
    echo '</li>';
    // HTTPS check
    echo '<li>';
    if ($is_https) {
        echo '<span style="color:green;">&#x2705; Site is using HTTPS</span>';
    } else {
        echo '<span style="color:orange;">&#x26A0; Site is not using HTTPS. GPT integrations may require secure endpoints.</span>';
    }
    echo '</li>';
    // REST API availability
    echo '<li>';
    if ($rest_enabled) {
        echo '<span style="color:green;">&#x2705; WordPress REST API is enabled</span>';
    } else {
        echo '<span style="color:red;">&#x274C; WordPress REST API is disabled by a plugin or custom code.</span>';
    }
    echo '</li>';
    // PHP extensions
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
    // --- Recent API Errors (last 5) ---
    $log_path = defined('WP_DEBUG_LOG') ? WP_DEBUG_LOG : ABSPATH . 'wp-content/debug.log';
    $recent_errors = [];
    if (file_exists($log_path)) {
        $lines = @file($log_path);
        if ($lines) {
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
    // --- Ping Site Button ---
    $ping_nonce = wp_create_nonce("gpt_ping_site_nonce");
    echo '<div style="margin:20px 0;">'
        . '<button id="gpt-ping-site-btn" class="button">Ping Site (Test /wp-json/gpt/v1/post)</button>'
        . '<span id="gpt-ping-site-result" style="margin-left:15px;font-weight:bold;"></span>'
        . '</div>';
    echo '<script type="text/javascript">
    document.addEventListener("DOMContentLoaded", function() {
        var btn = document.getElementById("gpt-ping-site-btn");
        var result = document.getElementById("gpt-ping-site-result");
        if (btn) {
            btn.addEventListener("click", function() {
                result.textContent = "Pinging...";
                btn.disabled = true;
                fetch(ajaxurl, {
                    method: "POST",
                    credentials: "same-origin",
                    headers: {"Content-Type": "application/x-www-form-urlencoded"},
                    body: "action=gpt_ping_site&nonce=' + $ping_nonce + '"
                })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        result.style.color = "green";
                        result.textContent = "Success: " + data.data;
                    } else {
                        result.style.color = "#b00";
                        result.textContent = "Error: " + (data.data || data.message);
                    }
                })
                .catch(e => {
                    result.style.color = "#b00";
                    result.textContent = "AJAX error: " + e;
                })
                .finally(() => { btn.disabled = false; });
            });
        }
    });
    </script>';
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

// Add settings link in plugin list
add_filter('plugin_action_links_' . plugin_basename(__FILE__), function ($links) {
    $url = admin_url('tools.php?page=gpt-api-keys');
    $links[] = '<a href="' . esc_url($url) . '">Settings</a>';
});

// --- Helper: Validate API key and get role ---
function gpt_get_role_for_key($key)
{
    $keys = get_option('gpt_api_keys', []);
    return isset($keys[$key]) ? $keys[$key]['role'] : false;
}

// --- Helper: Validate API key and user permissions for publishing ---
/**
 * Validates an API key and checks if the associated user role has 'publish_posts' capability.
 * Returns true if valid and permitted, otherwise a WP_Error.
 *
 * @param string $api_key The API key to validate.
 * @return true|WP_Error
 */
function gpt_validate_api_key_publish_permission($api_key)
{
    $keys = get_option('gpt_api_keys', []);
    if (empty($api_key) || !isset($keys[$api_key])) {
        return new WP_Error('gpt_invalid_key', 'Invalid or missing API key.', ['status' => 401]);
    }
    $role = $keys[$api_key]['role'];
    // Map custom roles to capabilities
    $role_caps = [
        'gpt_webmaster' => ['publish_posts'],
        'gpt_publisher' => ['publish_posts'],
        'gpt_editor' => [], // Editors do not have publish_posts
    ];
    if (!isset($role_caps[$role]) || !in_array('publish_posts', $role_caps[$role])) {
        return new WP_Error('gpt_insufficient_permissions', 'API key does not have permission to publish posts.', ['status' => 403]);
    }
    return true;
}

// --- Helper: Role-based REST permission check for each route ---
function gpt_rest_permission_check_role($request)
{
    $key = $request->get_header('gpt-api-key');
    $role = gpt_get_role_for_key($key);
    if (!$role) {
        return false;
    }
    $request->set_param('gpt_role', $role);
    // Route-specific permission logic
    $route = $request->get_route();
    // Only allow publishing for roles with 'publish_posts'
    if ($route === '/gpt/v1/post' && $request->get_method() === 'POST') {
        // Only Webmaster and Publisher can publish
        if (!in_array($role, ['gpt_webmaster', 'gpt_publisher'])) {
            return new WP_Error('gpt_forbidden', 'You do not have permission to publish posts.', ['status' => 403]);
        }
    }
    // Only allow editing for roles with edit capability
    if (preg_match('#^/gpt/v1/post/\\d+$#', $route) && $request->get_method() === 'POST') {
        // All roles can edit, but Editors can only edit drafts (handled in endpoint)
        if (!in_array($role, ['gpt_webmaster', 'gpt_publisher', 'gpt_editor'])) {
            return new WP_Error('gpt_forbidden', 'You do not have permission to edit posts.', ['status' => 403]);
        }
    }
    // Only allow media upload for all roles
    if ($route === '/gpt/v1/media' && $request->get_method() === 'POST') {
        if (!in_array($role, ['gpt_webmaster', 'gpt_publisher', 'gpt_editor'])) {
            return new WP_Error('gpt_forbidden', 'You do not have permission to upload media.', ['status' => 403]);
        }
    }
    return true;
}

// --- REST API Endpoints ---
add_action('rest_api_init', function () {
    register_rest_route('gpt/v1', '/post', [
        'methods' => 'POST',
        'callback' => gpt_rest_api_error_wrapper('gpt_create_post_endpoint'),
        'permission_callback' => 'gpt_rest_permission_check_role',
    ]);
    // --- Add GET /post for agent ping ---
    register_rest_route('gpt/v1', '/post', [
        'methods' => 'GET',
        'callback' => gpt_rest_api_error_wrapper('gpt_ping_post_endpoint'),
        'permission_callback' => 'gpt_rest_permission_check_role',
    ]);
    register_rest_route('gpt/v1', '/post/(?P<id>\\d+)', [
        'methods' => 'POST',
        'callback' => gpt_rest_api_error_wrapper('gpt_edit_post_endpoint'),
        'permission_callback' => 'gpt_rest_permission_check_role',
        'args' => [
            'id' => [
                'validate_callback' => 'is_numeric',
            ],
        ],
    ]);
    register_rest_route('gpt/v1', '/media', [
        'methods' => 'POST',
        'callback' => gpt_rest_api_error_wrapper('gpt_upload_media_endpoint'),
        'permission_callback' => 'gpt_rest_permission_check_role',
    ]);
    register_rest_route('gpt/v1', '/openapi', [
        'methods' => 'GET',
        'callback' => gpt_rest_api_error_wrapper('gpt_openapi_schema_handler'),
        'permission_callback' => '__return_true',
    ]);
    register_rest_route('gpt/v1', '/ai-plugin.json', [
        'methods' => 'GET',
        'callback' => gpt_rest_api_error_wrapper('gpt_ai_plugin_manifest_handler'),
        'permission_callback' => '__return_true',
    ]);
});

// --- REST: Ping Post Endpoint for Agent ---
function gpt_ping_post_endpoint($request)
{
    $key = $request->get_header('gpt-api-key');
    $role = gpt_get_role_for_key($key);
    if (!$role) {
        return gpt_error_response('Invalid or missing API key.', 401);
    }
    return new WP_REST_Response([
        'message' => 'Ping successful. WordPress site is reachable and API key is valid.',
        'role' => $role
    ], 200);
}

// --- REST Permission Check ---
function gpt_rest_permission_check($request)
{
    $key = $request->get_header('gpt-api-key');
    $role = gpt_get_role_for_key($key);
    if (!$role)
        return false;
    $request->set_param('gpt_role', $role);
    return true;
}

// --- REST: Create Post ---
function gpt_create_post_endpoint($request)
{
    $role = $request->get_param('gpt_role');
    if (!in_array($role, ['gpt_webmaster', 'gpt_publisher', 'gpt_editor'])) {
        return gpt_error_response('Invalid role', 403);
    }
    $params = $request->get_json_params();
    $post_data = [
        'post_title' => sanitize_text_field($params['title'] ?? ''),
        'post_content' => wp_kses_post($params['content'] ?? ''),
        'post_status' => isset($params['post_status']) ? sanitize_key($params['post_status']) : (($role === 'gpt_editor') ? 'draft' : 'publish'),
        'post_type' => 'post',
        'post_excerpt' => isset($params['excerpt']) ? wp_kses_post($params['excerpt']) : '',
        'post_format' => isset($params['format']) ? sanitize_key($params['format']) : 'standard',
        'post_name' => isset($params['slug']) ? sanitize_title($params['slug']) : '',
        'post_author' => isset($params['author']) ? intval($params['author']) : get_current_user_id(),
        'post_date' => isset($params['post_date']) ? sanitize_text_field($params['post_date']) : '',
    ];
    if ($role === 'gpt_editor') {
        $post_data['post_status'] = 'draft';
    }
    $post_id = wp_insert_post($post_data);
    if (is_wp_error($post_id)) {
        return $post_id;
    }
    if (!empty($params['categories'])) {
        wp_set_post_categories($post_id, array_map('intval', (array) $params['categories']));
    }
    if (!empty($params['tags'])) {
        wp_set_post_tags($post_id, (array) $params['tags']);
    }
    if (!empty($params['featured_image'])) {
        set_post_thumbnail($post_id, intval($params['featured_image']));
    }
    if (!empty($params['meta']) && is_array($params['meta'])) {
        foreach ($params['meta'] as $key => $value) {
            update_post_meta($post_id, sanitize_key($key), sanitize_text_field($value));
        }
    }
    return ['post_id' => $post_id];
}

// --- REST: Edit Post ---
function gpt_edit_post_endpoint($request)
{
    $role = $request->get_param('gpt_role');
    $id = (int) $request['id'];
    $params = $request->get_json_params();
    $post = get_post($id);
    if (!$post) {
        return gpt_error_response('Post not found', 404);
    }
    if ($role === 'gpt_editor' && $post->post_status !== 'draft') {
        return gpt_error_response('Editors can only edit drafts', 403);
    }
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
    $result = wp_update_post($update, true);
    if (is_wp_error($result)) {
        return $result;
    }
    if (!empty($params['categories'])) {
        wp_set_post_categories($id, array_map('intval', (array) $params['categories']));
    }
    if (!empty($params['tags'])) {
        wp_set_post_tags($id, (array) $params['tags']);
    }
    if (!empty($params['featured_image'])) {
        set_post_thumbnail($id, intval($params['featured_image']));
    }
    if (!empty($params['meta']) && is_array($params['meta'])) {
        foreach ($params['meta'] as $key => $value) {
            update_post_meta($id, sanitize_key($key), sanitize_text_field($value));
        }
    }
    return ['post_id' => $id];
}

// --- REST: Upload Media ---
function gpt_upload_media_endpoint($request)
{
    $role = $request->get_param('gpt_role');
    if (!in_array($role, ['gpt_webmaster', 'gpt_publisher', 'gpt_editor'])) {
        return gpt_error_response('Invalid role', 403);
    }
    if (empty($_FILES['file'])) {
        return gpt_error_response('No file uploaded', 400);
    }
    $file = $_FILES['file'];
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

// --- REST: Dynamic OpenAPI Schema Endpoint ---
function gpt_openapi_schema_handler()
{
    $site_url = get_site_url();
    $schema = [
        'openapi' => '3.1.0',
        'info' => [
            'title' => 'GPT-4-WP-Plugin v1 API',
            'version' => '1.0.0',
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
                        'title' => ['type' => 'string'],
                        'content' => ['type' => 'string'],
                        'excerpt' => ['type' => 'string'],
                        'categories' => ['type' => 'array', 'items' => ['type' => 'integer']],
                        'tags' => ['type' => 'array', 'items' => ['oneOf' => [['type' => 'string'], ['type' => 'integer']]]],
                        'featured_image' => ['type' => 'integer'],
                        'format' => ['type' => 'string'],
                        'slug' => ['type' => 'string'],
                        'author' => ['type' => 'integer'],
                        'post_status' => ['type' => 'string'],
                        'post_date' => ['type' => 'string'],
                        'meta' => ['type' => 'object', 'additionalProperties' => ['type' => 'string']]
                    ],
                    'required' => ['title', 'content']
                ]
            ]
        ],
        'security' => [['ApiKeyAuth' => []]],
        'paths' => [
            '/post' => [
                'post' => [
                    'summary' => 'Create a new post',
                    'operationId' => 'createPost',
                    'requestBody' => [
                        'required' => true,
                        'content' => [
                            'application/json' => [
                                'schema' => ['$ref' => '#/components/schemas/PostInput']
                            ]
                        ]
                    ],
                    'responses' => [
                        '200' => [
                            'description' => 'Post created',
                            'content' => [
                                'application/json' => [
                                    'schema' => [
                                        'type' => 'object',
                                        'properties' => ['post_id' => ['type' => 'integer']]
                                    ]
                                ]
                            ]
                        ]
                    ]
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
                            'schema' => ['type' => 'integer']
                        ]
                    ],
                    'requestBody' => [
                        'required' => true,
                        'content' => [
                            'application/json' => [
                                'schema' => ['$ref' => '#/components/schemas/PostInput']
                            ]
                        ]
                    ],
                    'responses' => [
                        '200' => [
                            'description' => 'Post updated',
                            'content' => [
                                'application/json' => [
                                    'schema' => [
                                        'type' => 'object',
                                        'properties' => ['post_id' => ['type' => 'integer']]
                                    ]
                                ]
                            ]
                        ]
                    ]
                ]
            ],
            '/media' => [
                'post' => [
                    'summary' => 'Upload a media file',
                    'operationId' => 'uploadMedia',
                    'requestBody' => [
                        'required' => true,
                        'content' => [
                            'multipart/form-data' => [
                                'schema' => [
                                    'type' => 'object',
                                    'properties' => [
                                        'file' => ['type' => 'string', 'format' => 'binary']
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
                                    'schema' => [
                                        'type' => 'object',
                                        'properties' => [
                                            'attachment_id' => ['type' => 'integer'],
                                            'url' => ['type' => 'string']
                                        ]
                                    ]
                                ]
                            ]
                        ]
                    ]
                ]
            ]
        ]
    ];
    return new WP_REST_Response($schema, 200, ['Content-Type' => 'application/json']);
}


// --- REST: Dynamic ai-plugin.json Manifest Endpoint ---
function gpt_ai_plugin_manifest_handler()
{
    $site_url = get_site_url();
    $plugin_url = $site_url . '/wp-content/plugins/gpt-4-wp-plugin-v1.2';
    $manifest = [
        'schema_version' => 'v1',
        'name_for_human' => 'GPT-4 WP Plugin v1.2',
        'name_for_model' => 'gpt_4_wp_plugin_v1_2',
        'description_for_human' => 'Create, edit, and manage WordPress posts and media via secure API. Version 1.2, single-file, minimal and secure.',
        'description_for_model' => 'A secure, minimal REST API for WordPress (v1.2) that allows GPTs/clients to create, edit, and manage posts and media using API keys and role-based permissions. Supports Webmaster, Publisher, and Editor roles.',
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

// --- AJAX handler for Ping Site button ---
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
