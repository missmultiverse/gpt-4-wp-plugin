# Copilot Instructions for GPT-4-WP-Plugin v2.0

## Overview
This plugin provides secure REST API access for GPTs/clients to WordPress, with three custom roles, pre-configured GPTs, site selection, and simple API key management. All logic is in `gpt-4-wp-plugin-v2.0.php`.

## Guidelines for Future Development
- **Keep it minimal:** Avoid legacy WordPress bloat and unnecessary features.
- **Roles:** Only three roles (Webmaster, Publisher, Editor) with clear, distinct capabilities.
- **Pre-configured GPTs:** WebMaster.GPT, Linda.GPT, AgentX.GPT, Automatron.GPT, SEO-Inspector.GPT, CrownLeads.GPT, Leadsy.GPT, VIRALIA.GPT are always present and auto-linked to all sites.
- **Site Selection:** Admin UI provides a dropdown to select the current site; plugin configures itself dynamically for 15 supported domains.
- **API Keys:** All API key logic (generate, list, revoke, assign) should remain simple and secure.
- **REST API:** Endpoints must always check API key and enforce role-based permissions.
- **Admin UI:** Should remain under Tools > GPT API Keys, minimal and user-friendly, with pre-configured GPTs table and site selection.
- **Security:** Never expose API keys in logs or responses. Always validate input.
- **Scalability:** Design for use on multiple sites and with multiple GPTs/clients.

## File Structure
- `gpt-4-wp-plugin-v2.0.php`: All plugin logic (roles, API keys, REST API, admin UI, pre-configured GPTs, site selection)
- `README.md`: User and developer documentation
- `.github/copilot-instructions.md`: This file

## Best Practices
- Use WordPress core functions and hooks
- Sanitize and validate all input/output
- Document new functions and endpoints clearly
- Test in a real WordPress environment

## Do Not
- Add legacy role/capability logic
- Add features outside the scope of secure API access and key management
- Add external dependencies unless absolutely necessary

---
For any new features, always check with the user for approval before implementation.
