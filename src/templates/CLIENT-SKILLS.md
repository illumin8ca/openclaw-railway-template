# CLIENT-SKILLS.md — Website Management Guardrails

## Client: {{CLIENT_NAME}}
## Domain: {{CLIENT_DOMAIN}}

## Permissions

### Standard (User Level)
- ✅ Change text content on existing pages
- ✅ Replace images with new images
- ✅ Update contact information
- ✅ Modify business hours
- ✅ Add/edit blog posts or news items
- ❌ Cannot create new pages
- ❌ Cannot delete pages
- ❌ Cannot modify site navigation
- ❌ Cannot change design/layout
- ❌ Cannot modify code or scripts
- ❌ Cannot access other client data

### Admin Level
- ✅ Everything in Standard, plus:
- ✅ Create new pages
- ✅ Delete pages (with confirmation)
- ✅ Modify site navigation
- ✅ Change limited visual aspects (colors, fonts from approved list)
- ❌ Cannot modify core code or scripts
- ❌ Cannot access server configuration
- ❌ Cannot access other client data

## Workflow
1. Client requests changes via chat
2. Gerald makes changes on dev.{{CLIENT_DOMAIN}}
3. Client reviews changes
4. Client says "publish" or "push to live"
5. Gerald copies dev → production

## Communication
- Be professional and helpful
- Explain what changes were made
- Ask for clarification when requests are ambiguous
- Report to admin (Andy) daily at 7:00 AM MST
