<?php
/*
Plugin Name: GPT-4 WP Plugin
Plugin URI: https://github.com/missmultiverse/gpt-4-wp-plugin
Description: Integrates GPT-4 with WordPress using GitHub auto-update via Git Updater.
Version: 1.0.0
Author: MissMultiverse
Author URI: https://missmultiverse.com
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
GitHub Plugin URI: https://github.com/missmultiverse/gpt-4-wp-plugin
Requires at least: 6.0
Tested up to: 6.7
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
        } catch (Throwable $e) {
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
    if (is_array($keys) && count($keys) > 0) {
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

// Add settings link in plugin list
add_filter('plugin_action_links_' . plugin_basename(__FILE__), function ($links) {
    if (!is_array($links)) {
        $links = [];
    }

    $url = admin_url('tools.php?page=gpt-api-keys');
    $links[] = '<a href="' . esc_url($url) . '">Settings</a>';

    return $links; // ✅ THIS is what was missing
});

// --- Helper: Validate API key and get role ---
function gpt_get_role_for_key($key)
{
    $keys = get_option('gpt_api_keys', []);
    error_log('🧪 [DEBUG] Incoming API key: ' . $key);
    error_log('🧪 [DEBUG] Saved keys: ' . print_r($keys, true));

    if (is_array($keys) && isset($keys[$key])) {
        return $keys[$key]['role'] ?? null;
    }
    return null;
}


//NEW CODE

// --- Helper: Create a GPT User on Registration ---
// --- Helper: Create a GPT User on Registration ---
function create_gpt_user_on_registration($api_key, $role)
{
    // Check if user already exists (perhaps by the label or API key)
    $user = get_user_by('email', $api_key);

    // If user already exists, return their ID
    if ($user) {
        return $user->ID;
    }

    // Otherwise, create the user on registration
    return create_gpt_user($api_key, $role);
}

// --- Helper: Create a GPT User on Post Creation ---
function create_gpt_user($api_key, $role)
{
    // Check if user already exists (perhaps by the label or API key)
    $user = get_user_by('email', $api_key); // Use API key as unique identifier

    // If user doesn't exist, create them
    if (!$user) {
        // Ensure a unique username by appending a unique string if necessary
        $username = 'gpt_' . sanitize_text_field($api_key);
        $existing_user = get_user_by('login', $username); // Check if the username exists

        if ($existing_user) {
            // Append a unique suffix if the username exists
            $username = $username . '_' . uniqid();
        }

        // Set the user display name to be ViraliaGPT or another preferred method
        $display_name = 'ViraliaGPT'; // You can modify this to be dynamic based on the request or other factors.

        // Create a new user for the GPT
        $user_data = [
            'user_login' => $username, // Unique username
            'user_email' => sanitize_email($api_key), // Unique email based on API key
            'user_pass' => wp_generate_password(12, false), // Secure password
            'role' => $role, // Assign the role (e.g., 'gpt_webmaster')
            'first_name' => sanitize_text_field($api_key), // Optional: You can add more info if needed
            'display_name' => $display_name, // Set display name correctly here
        ];

        // Insert the user and check for errors
        $user_id = wp_insert_user($user_data);

        if (is_wp_error($user_id)) {
            error_log('Error creating GPT user: ' . $user_id->get_error_message());
            return false;
        }

        // Optional: You can add extra user meta or fields if necessary
        update_user_meta($user_id, 'gpt_api_key', $api_key);

        return $user_id; // Return user ID if successful
    }

    return $user->ID; // If user exists, return the existing user ID
}


//NEW CODE


// --- Helper: Role-based REST permission check for each route ---
function gpt_rest_permission_check_role($request)
{
    // ✅ Accept both "gpt-api-key" and "Authorization: Bearer" headers
    $key = $request->get_header('gpt-api-key') ?: str_replace('Bearer ', '', $request->get_header('authorization'));

    // 🧪 Optional debug log
    error_log('🔐 [Auth] API key used in permission check: ' . $key);

    $role = gpt_get_role_for_key($key);
    if (!$role) {
        return gpt_error_response('Invalid or missing API key.', 401);
    }

    $request->set_param('gpt_role', $role);

    // Route-specific permission logic
    $route = $request->get_route();

    // Only allow editing for roles with edit capability
    if (preg_match('#^/gpt/v1/post/\\d+$#', $route) && $request->get_method() === 'POST') {
        $id = $request->get_param('id');

        // Fixed is_numeric() call - pass only the value to is_numeric
        if (!is_numeric($id)) {
            return gpt_error_response('Invalid post ID', 400);
        }

        // Additional logic to ensure the user can edit the post based on role
        if ($role === 'gpt_editor' && get_post_status($id) !== 'draft') {
            return gpt_error_response('Editors can only edit drafts', 403);
        }

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
                'validate_callback' => function ($value) {
                    return is_numeric($value);
                },
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
    // ✅ Accept both "gpt-api-key" and "Authorization: Bearer" headers
    $key = $request->get_header('gpt-api-key') ?: str_replace('Bearer ', '', $request->get_header('authorization'));

    // 🧪 Optional debug log
    error_log('🔐 [Auth] API key used in ping: ' . $key);

    $role = gpt_get_role_for_key($key);
    if (!$role) {
        return gpt_error_response('Invalid or missing API key.', 401);
    }

    return new WP_REST_Response([
        'message' => 'Ping successful. WordPress site is reachable and API key is valid.',
        'role' => $role
    ], 200);
}


// --- START --- REST: Create Post ---
function gpt_create_post_endpoint($request)
{
    $role = $request->get_param('gpt_role');
    if (!in_array($role, ['gpt_webmaster', 'gpt_publisher', 'gpt_editor'])) {
        return gpt_error_response('Invalid role', 403);
    }
    $params = $request->get_json_params();

    // --- Debugging Step: Log the start of the post creation process
    error_log("Starting post creation for API key: " . $request->get_header('gpt-api-key'));

    // Get or create the user at this stage of post creation
    $user_id = create_gpt_user($request->get_header('gpt-api-key'), $role); // Create user if necessary

    // --- Debugging Step: Log the user creation process
    if (!$user_id) {
        error_log("Failed to create or retrieve user for API key: " . $request->get_header('gpt-api-key'));
        return gpt_error_response('Failed to create user', 500);
    }

    // --- Debugging Step: Log the user ID after creation
    error_log("User created/retrieved successfully with ID: " . $user_id);

    // Now proceed to create the post
    $post_data = [
        'post_title' => sanitize_text_field($params['title'] ?? ''),
        'post_content' => wp_kses_post($params['content'] ?? ''),
        'post_status' => isset($params['post_status']) ? sanitize_key($params['post_status']) : (($role === 'gpt_editor') ? 'draft' : 'publish'),
        'post_type' => 'post',
        'post_excerpt' => isset($params['excerpt']) ? wp_kses_post($params['excerpt']) : '',
        'post_format' => isset($params['format']) ? sanitize_key($params['format']) : 'standard',
        'post_name' => isset($params['slug']) ? sanitize_title($params['slug']) : '',
        'post_author' => $user_id, // Set the author as the GPT user
        'post_date' => isset($params['post_date']) ? sanitize_text_field($params['post_date']) : '',
    ];

    if ($role === 'gpt_editor') {
        $post_data['post_status'] = 'draft';
    }

    // --- Debugging Step: Log the post data before insertion
    error_log("Inserting post with data: " . print_r($post_data, true));

    $post_id = wp_insert_post($post_data);
    if (is_wp_error($post_id)) {
        error_log("Error inserting post: " . $post_id->get_error_message());
        return $post_id;
    }

    // --- Debugging Step: Log successful post creation
    error_log("Post created successfully with ID: " . $post_id);

    // Additional handling for categories, tags, featured image, and metadata
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

// --- END --- REST: Create Post ---


// --- REST: Edit Post ---
function gpt_edit_post_endpoint($request)
{
    $role = $request->get_param('gpt_role');
    $id = (int) $request->get_param('id');  // Corrected usage of get_param()
    $params = $request->get_json_params();

    error_log("Attempting to edit post ID: $id with role: $role");

    $post = get_post($id);
    if (!$post) {
        error_log("Post not found with ID: $id");
        return gpt_error_response('Post not found', 404);
    }

    // Check user role permissions
    if ($role === 'gpt_editor' && $post->post_status !== 'draft') {
        error_log("Editor role cannot edit published posts. Post ID: $id");
        return gpt_error_response('Editors can only edit drafts', 403);
    }

    // Validate post status
    $allowed_statuses = ['publish', 'draft', 'pending', 'private'];
    if (isset($params['post_status']) && !in_array($params['post_status'], $allowed_statuses)) {
        error_log("Invalid post status: " . $params['post_status']);
        return gpt_error_response('Invalid post status', 400);
    }

    // Post data to update
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

    // Debug log before post update
    error_log("Post update data: " . print_r($update, true));

    // Perform the update
    $result = wp_update_post($update, true);
    if (is_wp_error($result)) {
        error_log("Error updating post: " . $result->get_error_message());
        return gpt_error_response('Failed to update post', 500);
    }

    // Get the updated post to check its status
    $updated_post = get_post($result);
    error_log("Updated post status: " . $updated_post->post_status);

    // Check if the post is published or not
    if ($updated_post->post_status === 'publish') {
        return new WP_REST_Response([
            'post_id' => $result,
            'status' => 'success',
            'message' => 'Post successfully updated and published.'
        ], 200);
    } else {
        return new WP_REST_Response([
            'post_id' => $result,
            'status' => 'pending',
            'message' => 'Post updated, but pending approval for publication.'
        ], 200);
    }

    // Update categories
    if (!empty($params['categories'])) {
        wp_set_post_categories($result, array_map('intval', (array) $params['categories']));
    }
    if (!empty($params['tags'])) {
        wp_set_post_tags($result, (array) $params['tags']);
    }
    if (!empty($params['featured_image'])) {
        set_post_thumbnail($result, intval($params['featured_image']));
    }
    if (!empty($params['meta']) && is_array($params['meta'])) {
        foreach ($params['meta'] as $key => $value) {
            update_post_meta($result, sanitize_key($key), sanitize_text_field($value));
        }
    }

    return ['post_id' => $result];
}



// --- REST: Upload Media ---
function gpt_upload_media_endpoint($request)
{
    $role = $request->get_param('gpt_role');
    if (!in_array($role, ['gpt_webmaster', 'gpt_publisher', 'gpt_editor'])) {
        return gpt_error_response('Invalid role', 403);
    }

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
        if (!filter_var($image_url, FILTER_VALIDATE_URL)) {
            return gpt_error_response('Invalid URL', 400);
        }
        $response = wp_remote_get($image_url, ['timeout' => 15]);
        if (is_wp_error($response)) {
            return gpt_error_response('Unable to download image: ' . $response->get_error_message(), 400);
        }
        $body = wp_remote_retrieve_body($response);
        if (empty($body)) {
            return gpt_error_response('Downloaded image is empty.', 400);
        }
        $file_name = sanitize_file_name(basename(parse_url($image_url, PHP_URL_PATH)));
        $filetype = wp_check_filetype($file_name);
        if (!in_array($filetype['type'], ['image/jpeg', 'image/png', 'image/gif'])) {
            return gpt_error_response('Invalid file type. Only JPEG, PNG, and GIF images are allowed.', 400);
        }
        $tmpfname = wp_tempnam($file_name);
        if (!$tmpfname) {
            return gpt_error_response('Could not create a temporary file.', 500);
        }
        $bytes_written = file_put_contents($tmpfname, $body);
        if ($bytes_written === false) {
            @unlink($tmpfname);
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
            return gpt_error_response($upload['error'], 400);
        }
        $attachment = [
            'post_mime_type' => $upload['type'],
            'post_title' => sanitize_file_name($file_name),
            'post_content' => '',
            'post_status' => 'inherit',
        ];
        $attach_id = wp_insert_attachment($attachment, $upload['file']);
        require_once(ABSPATH . 'wp-admin/includes/image.php');
        $attach_data = wp_generate_attachment_metadata($attach_id, $upload['file']);
        wp_update_attachment_metadata($attach_id, $attach_data);
        return ['attachment_id' => $attach_id, 'url' => wp_get_attachment_url($attach_id)];
    }
    return gpt_error_response('No image URL or file provided', 400);
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

// ==========================================
// --- START --- GPT Universal Action Route
// ==========================================
error_log('✅ [WebMasterGPT] rest_api_init called');

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
// ========================================
// --- END --- GPT Universal Action Route
// ========================================
