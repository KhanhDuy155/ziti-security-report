# Stored Cross-Site Scripting (XSS) in Ziti Admin Console (ZAC)
Vulnerability Type: Stored Cross-Site Scripting (XSS) – CWE-79
Affected Component: Role attributes rendered in AG-Grid data tables
Affected Pages: /zac/services, /zac/identities, /zac/routers, /zac/service-policies, /zac/edge-router-policies, /zac/service-edge-router-policies
Severity: Low
Status: Vulnerability confirmed, not patched (at time of writing)
Tested Version: ZAC 4.3.0 / Controller 2.0.0

## 1. Summary
A Stored Cross-Site Scripting (XSS) vulnerability exists in Ziti Admin Console (ZAC) within the role attribute rendering feature.
When an administrator creates or modifies an entity (Service, Identity, Edge Router, Policy) and assigns a role attribute containing an XSS payload, the value is stored without any input validation or output encoding.
Later, when any administrator views the entity list page, the role attribute is concatenated directly into an HTML string by a string-based AG-Grid cell renderer and rendered as live DOM without sanitization, causing automatic JavaScript execution in the victim's browser.
This issue can be used to execute arbitrary JavaScript in the context of an authenticated admin session.

## 2. Affected Products
Ziti Admin Console (ZAC) – openziti/ziti-console version 4.3.0
Ziti Controller – openziti/ziti version 2.0.0
Possibly earlier versions that share the same rolesRenderer pattern.

## 3. Vulnerability Details
### 3.1 Root Cause
ZAC uses string-based AG-Grid cell renderers to display role attributes in data tables. These renderers concatenate user-controlled role attribute names directly into HTML strings without HTML entity escaping.

The vulnerable pattern appears in 3 files:

```javascript
// services-page.service.ts — line 98
roles += '<div class="hashtag">' + attr + '</div>';
```

```javascript
// edge-routers-page.service.ts — line 106
roles += '<div class="hashtag">' + attr + '</div>';
```

```javascript
// list-page-service.class.ts — line 114
roles += '<div><div class="' + className + '">' + attr.name + '</div></div>';
```

The Controller API stores role attribute values as-is without any server-side validation or sanitization of HTML special characters.

### 3.2 Vulnerable Endpoints
```
POST /edge/management/v1/services           → roleAttributes
POST /edge/management/v1/identities         → roleAttributes
POST /edge/management/v1/edge-routers       → roleAttributes
POST /edge/management/v1/service-policies   → serviceRoles, identityRoles, postureCheckRoles
POST /edge/management/v1/edge-router-policies → edgeRouterRoles, identityRoles
POST /edge/management/v1/service-edge-router-policies → serviceRoles, edgeRouterRoles
```

The vulnerability is triggered when a previously stored malicious role attribute is returned by the API and rendered as HTML by the AG-Grid rolesRenderer on the following pages:

/zac/services
/zac/identities
/zac/routers
/zac/service-policies
/zac/edge-router-policies
/zac/service-edge-router-policies

## 4. Steps to Reproduce
### Step 1 – Login as Administrator
Navigate to the login page and log in using admin credentials.


### Step 2 – Create a Service with Malicious Role Attribute
Inject the following payload into the roleAttributes field:

Payload: `<img src=1 onerror=alert(document.domain)>`

<img width="1918" height="944" alt="image" src="https://github.com/user-attachments/assets/314820fa-5cc5-4369-9eff-f3611a458f77" />


### Step 3 – Persistence of Payload
The application stores the malicious roleAttributes value in the database without sanitization.

Verify via GET: `/edge/management/v1/service-role-attributes?limit=100&offset=0&sort=name%20asc`

<img width="1562" height="793" alt="image" src="https://github.com/user-attachments/assets/f491f22a-34d2-46a8-a737-18bdf962e887" />


### Step 4 – Trigger the Stored XSS
Navigate to the Services list page.

The `alert(document.domain)` dialog appears, showing the target domain "ziti.local", confirming the Stored XSS.

<img width="1914" height="1023" alt="image" src="https://github.com/user-attachments/assets/a9a6aeab-74b1-43ce-8334-4e64763e56cf" />


Inspecting the DOM shows the injected `<img>` elements rendered as live HTML:

```html
<img src="1" onerror="alert(document.domain)">
```

6 such `<img>` elements were found in the page, all inside `.hashtag` and `.tag-name` div containers.

## 5. Impact
A successful exploitation of this vulnerability allows an administrator with management API access to execute arbitrary JavaScript in the browser of another administrator who views the affected list page.

Possible impacts include:

- Theft of session cookies or API tokens of another administrator.
- Modification of identities, services, routers, and policies.
- Persistent injection of malicious content into the ZAC UI.
- Use of XSS as a pivot point for more advanced attacks.

Because this is stored XSS, any administrator who navigates to the Services, Identities, Routers, or Policy list pages can be affected.

Note: The attacker must already possess admin-level API credentials. The vulnerability does not allow privilege escalation from an unauthenticated position.

## 6. Proof of Concept (PoC)
### Malicious Payload

```
<img src=1 onerror=alert(document.domain)>
```

### Affected Versions
Confirmed: ZAC 4.3.0 / Controller 2.0.0

### 13 Affected Code Locations

| # | File | Line | Column |
|---|------|------|--------|
| 1 | pages/services/services-page.service.ts | 98-103 | roleAttributes |
| 2 | pages/edge-routers/edge-routers-page.service.ts | 106-111 | roleAttributes |
| 3 | shared/list-page-service.class.ts | 114-123 | roleAttributes (shared) |
| 4 | pages/services/services-page.service.ts | 170 | roleAttributes |
| 5 | pages/edge-routers/edge-routers-page.service.ts | 208 | roleAttributes |
| 6 | pages/identities/identities-page.service.ts | 267 | roleAttributes |
| 7 | pages/edge-router-policies/edge-router-policies-page.service.ts | 270 | edgeRouterRoles |
| 8 | pages/edge-router-policies/edge-router-policies-page.service.ts | 289 | identityRoles |
| 9 | pages/service-policies/service-policies-page.service.ts | 272 | serviceRoles |
| 10 | pages/service-policies/service-policies-page.service.ts | 291 | identityRoles |
| 11 | pages/service-policies/service-policies-page.service.ts | 310 | postureCheckRoles |
| 12 | pages/service-edge-router-policies/service-edge-router-policies-page.service.ts | 238 | serviceRoles |
| 13 | pages/service-edge-router-policies/service-edge-router-policies-page.service.ts | 257 | edgeRouterRoles |

## Credits
Discovered by: Nguyễn Khánh Duy
Date: June 23, 2026
Reported to: security@openziti.org
