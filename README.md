# GPT-4-WP-Plugin v2.0

A clean, modern WordPress plugin providing a secure REST API for GPT-based agents and clients to interact with WordPress. All logic is contained in a single file for easy setup and deployment.

## Features
- **Pre-configured GPTs:** WebMaster.GPT, Linda.GPT (Webmaster); AgentX.GPT, Automatron.GPT, SEO-Inspector.GPT (Publisher); CrownLeads.GPT, Leadsy.GPT, VIRALIA.GPT (Editor) — all auto-linked to all sites, no manual setup needed
- **Site selection:** Admin UI lets you select the current site from a list of 15 supported domains; plugin configures itself dynamically
- **API key management:** Create, assign roles, label, and revoke API keys via the admin UI
- **Role-based access control:** Three roles (Webmaster, Publisher, Editor) with distinct capabilities
- **REST API endpoints:**
  - Create and edit posts
  - Upload media
  - **Full plugin file management for gpt_admin (WebMaster.GPT):**
    - List, read, write, create, and delete files/directories within the plugin folder (for diagnostics, troubleshooting, and advanced support)
- **Dynamic OpenAPI 3.0 schema:** `/wp-json/gpt/v1/openapi`
- **Dynamic ai-plugin.json endpoint:** `/wp-json/gpt/v1/ai-plugin.json`
- **Admin UI includes:**
  - Pre-configured GPTs table (read-only)
  - Site selection dropdown (dynamic config)
  - API key management (generate, list, revoke, assign, label)
  - Site ping test (both GPT→WordPress and WordPress→GPT)
  - REST endpoint diagnostics and status
- **All code in a single file:** Easy to install, portable, and maintainable

---

## Quick Start

1. **Copy the file** `gpt-4-wp-plugin-v2.0.php` into your WordPress `/wp-content/plugins/` directory.
2. **Activate the plugin** in the WordPress admin (Plugins > Installed Plugins).
3. **Go to Tools > GPT API Keys** in the WordPress admin to select your site and view pre-configured GPTs. Generate additional API keys as needed.
4. **Use the API key** as the `gpt-api-key` header in your HTTP requests or GPT/ChatGPT plugin configuration.
5. **Connect GPT/ChatGPT** by providing the dynamic manifest URL: `https://your-site.com/wp-json/gpt/v1/ai-plugin.json`.
6. **Test endpoints** using tools like Postman, curl, or directly from your GPT/ChatGPT plugin.

---

## Admin UI
- **Site Selection:** Choose the current site from a dropdown; plugin configures endpoints and settings dynamically.
- **Pre-configured GPTs Table:** View all built-in GPTs and their roles (auto-linked to all sites).
- **API Key Management:** Generate, label, assign, and revoke API keys for additional GPT agents/clients.
- **Site Ping Test:**
  - **WordPress → GPT:** Ping button in admin UI tests outbound connectivity to the REST API.
  - **GPT → WordPress:** Use the GET `/wp-json/gpt/v1/post` endpoint from your agent to test inbound connectivity and API key validity.
- **REST Endpoint Diagnostics:** Status checks for OpenAPI, ai-plugin.json, permalinks, HTTPS, REST API, PHP extensions, and recent API errors.

---

## REST API Endpoints

All endpoints require the `gpt-api-key` header with a valid API key.

### 1. **Ping (Agent → WordPress)**
- **GET** `/wp-json/gpt/v1/post`
- **Purpose:** Check if the WordPress site and API key are reachable/valid from your agent.
- **Headers:**
  - `gpt-api-key: YOUR_API_KEY`
- **Response (200):**
```json
{
  "message": "Ping successful. WordPress site is reachable and API key is valid.",
  "role": "gpt_publisher"
}
```
- **Response (401):**
```json
{
  "code": "gpt_error",
  "message": "Invalid or missing API key.",
  "data": {"status": 401}
}
```

### 2. **Create Post**
- **POST** `/wp-json/gpt/v1/post`
- **Headers:**
  - `Content-Type: application/json`
  - `gpt-api-key: YOUR_API_KEY`
- **Body:**
```json
{
  "title": "My Article Title",
  "content": "<p>Full HTML content</p>",
  "excerpt": "Short summary",
  "categories": [1, 2],
  "tags": ["tag1", "tag2"],
  "featured_image": 123,
  "format": "standard",
  "slug": "my-article-title",
  "author": 2,
  "post_status": "publish",
  "post_date": "2025-06-26 10:00:00",
  "meta": {
    "_yoast_wpseo_metadesc": "SEO meta description",
    "_rank_math_focus_keyword": "focus keyword"
  }
}
```
- **Response (200):**
```json
{
  "post_id": 1234
}
```
- **Response (error):**
```json
{
  "code": "gpt_error",
  "message": "Invalid role",
  "data": {"status": 403}
}
```

### 3. **Edit Post**
- **POST** `/wp-json/gpt/v1/post/{id}`
- **Headers:**
  - `Content-Type: application/json`
  - `gpt-api-key: YOUR_API_KEY`
- **Body:** (any fields to update)
```json
{
  "title": "Updated Title",
  "content": "Updated content"
}
```
- **Response (200):**
```json
{
  "post_id": 1234
}
```
- **Response (error):**
```json
{
  "code": "gpt_error",
  "message": "Post not found",
  "data": {"status": 404}
}
```

### 4. **Upload Media**
- **POST** `/wp-json/gpt/v1/media`
- **Headers:**
  - `Content-Type: multipart/form-data`
  - `gpt-api-key: YOUR_API_KEY`
- **Body:**
  - `file`: (binary file upload)
- **Response (200):**
```json
{
  "attachment_id": 5678,
  "url": "https://your-site.com/wp-content/uploads/2025/06/image.png"
}
```
- **Response (error):**
```json
{
  "code": "gpt_error",
  "message": "No file uploaded",
  "data": {"status": 400}
}
```

### 5. **Plugin File Management (gpt_admin only)**
> **Note:** These endpoints are only available to API keys with the `gpt_admin` role (e.g. WebMaster.GPT). All file/folder access is strictly limited to the plugin directory for security.

- **List files/directories**
  - **GET** `/wp-json/gpt/v1/ls?path=relative/path`
  - **Description:** Recursively lists all files and directories under the given path (relative to the plugin root). If `path` is omitted, lists the plugin root.
  - **Response:**
```json
{
  "path": "",
  "files": [
    { "type": "file", "name": "README.md", "path": "README.md", "size": 1234 },
    { "type": "dir", "name": "subdir", "path": "subdir", "children": [ ... ] }
  ]
}
```

- **Read file**
  - **GET** `/wp-json/gpt/v1/file?path=relative/path/to/file.php`
  - **Description:** Reads the contents of a file within the plugin directory.
  - **Response:**
```json
{
  "path": "gpt-4-wp-plugin-v2.0.php",
  "content": "<?php ... ?>"
}
```

- **Write file**
  - **POST** `/wp-json/gpt/v1/file`
  - **Body:**
```json
{
  "path": "relative/path/to/file.php",
  "content": "new file contents"
}
```
  - **Description:** Creates or overwrites a file within the plugin directory.
  - **Response:**
```json
{
  "path": "relative/path/to/file.php",
  "bytes_written": 123
}
```

- **Delete file or directory**
  - **DELETE** `/wp-json/gpt/v1/file?path=relative/path`
  - **Description:** Deletes a file or directory (recursively for directories) within the plugin directory.
  - **Response:**
```json
{
  "path": "relative/path",
  "deleted": true,
  "type": "file" // or "dir"
}
```

- **Create directory**
  - **POST** `/wp-json/gpt/v1/dir`
  - **Body:**
```json
{
  "path": "relative/path/to/newdir"
}
```
  - **Description:** Creates a new directory within the plugin directory.
  - **Response:**
```json
{
  "path": "relative/path/to/newdir",
  "created": true
}
```

---

## OpenAPI & Manifest
- **OpenAPI 3.0 schema:** `https://your-site.com/wp-json/gpt/v1/openapi`
- **ai-plugin.json manifest:** `https://your-site.com/wp-json/gpt/v1/ai-plugin.json`

---

## Role Capabilities
- **Webmaster:** Full access to all endpoints and actions (including plugin file management)
- **Publisher:** Can create, edit, and publish posts/media
- **Editor:** Can create and edit drafts, upload media (no publishing)

---

## Security
- All endpoints require a valid API key with an assigned role
- Role-based permission checks for every action
- API keys are never exposed in logs or responses
- Pre-configured GPTs are always available and cannot be removed (for security and simplicity)
- **File management endpoints are strictly limited to the plugin directory and only available to gpt_admin**

---

## Troubleshooting & Diagnostics
- Use the admin UI (Tools > GPT API Keys) for:
  - Site selection and dynamic config
  - Pre-configured GPTs table
  - API key management
  - Site ping test (both directions)
  - REST endpoint diagnostics and error logs
- Use the plugin file management endpoints for advanced diagnostics, troubleshooting, and self-repair (gpt_admin only).
- If you encounter errors, ensure the plugin is activated and you are using a valid API key.
- Use the dynamic manifest and OpenAPI endpoints—do not use or create static ai-plugin.json or openapi.yaml files.
- For debugging, enable WordPress debug mode or check your server logs.

---

## Development
- All logic is in `gpt-4-wp-plugin-v2.0.php`
- No external dependencies
- Dynamic ai-plugin.json and OpenAPI endpoints for easy multi-site deployment

## License
MIT
