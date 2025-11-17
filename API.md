# Magic Link Service API Documentation

## Overview

The Magic Link Service provides RESTful APIs for passwordless authentication with multi-step form processing.

## Base URL

```
http://localhost:8080
```

## Authentication

The magic link token is passed as a query parameter for all endpoints.

---

## API Endpoints

### 1. Get Form Configuration

Retrieve the form configuration and validate the magic link token.

**Endpoint:** `GET /api/magic-link/form`

**Query Parameters:**
- `token` (required) - The magic link token from the email

**Response (200 OK):**
```json
{
  "email": "user@example.com",
  "token": "abc-123-def-456",
  "title": "Complete Your Profile",
  "description": "Hi user@example.com, please complete your profile to continue.",
  "submitButtonText": "Complete Setup",
  "tokenExpiresIn": 850,
  "fields": [
    {
      "name": "name",
      "label": "Full Name",
      "type": "text",
      "required": true,
      "placeholder": "Enter your full name",
      "options": null
    },
    {
      "name": "company",
      "label": "Company",
      "type": "text",
      "required": false,
      "placeholder": "Enter your company name (optional)",
      "options": null
    },
    {
      "name": "role",
      "label": "Role",
      "type": "select",
      "required": false,
      "options": [
        {
          "value": "",
          "label": "Select your role (optional)"
        },
        {
          "value": "developer",
          "label": "Developer"
        },
        {
          "value": "designer",
          "label": "Designer"
        },
        {
          "value": "manager",
          "label": "Manager"
        },
        {
          "value": "other",
          "label": "Other"
        }
      ]
    }
  ]
}
```

**Error Response (401 Unauthorized):**
```json
{
  "status": "error",
  "message": "Invalid or expired token",
  "code": "INVALID_TOKEN"
}
```

**Example:**
```bash
curl "http://localhost:8080/api/magic-link/form?token=abc-123-def-456"
```

---

### 2. Submit Form Data

Submit the completed form data for background processing.

**Endpoint:** `POST /api/magic-link/process-form`

**Query Parameters:**
- `token` (required) - The magic link token

**Request Body:**
```json
{
  "name": "John Doe",
  "company": "Acme Inc",
  "role": "developer"
}
```

**Response (200 OK):**
```json
{
  "status": "success",
  "message": "Form data received, processing in background"
}
```

**Error Response (401 Unauthorized):**
```json
{
  "status": "error",
  "message": "Invalid or expired token",
  "code": "INVALID_TOKEN"
}
```

**Example:**
```bash
curl -X POST "http://localhost:8080/api/magic-link/process-form?token=abc-123-def-456" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "company": "Acme Inc",
    "role": "developer"
  }'
```

---

### 3. Check Processing Status

Poll the processing status after form submission.

**Endpoint:** `GET /api/magic-link/check-status`

**Query Parameters:**
- `token` (required) - The magic link token

**Response (200 OK) - Processing:**
```json
{
  "status": "processing",
  "progress": 60,
  "message": "Processing in progress"
}
```

**Response (200 OK) - Completed:**
```json
{
  "status": "completed",
  "progress": 100,
  "nextStep": "/",
  "message": "Processing completed successfully"
}
```

**Response (200 OK) - Failed:**
```json
{
  "status": "failed",
  "message": "Error message here",
  "code": "PROCESSING_FAILED"
}
```

**Error Response (404 Not Found):**
```json
{
  "status": "error",
  "message": "Processing status not found",
  "code": "STATUS_NOT_FOUND"
}
```

**Example:**
```bash
curl "http://localhost:8080/api/magic-link/check-status?token=abc-123-def-456"
```

---

## Complete Workflow

### Step 1: User Requests Magic Link
```bash
POST /login/ott/generate
username=user@example.com
```

### Step 2: User Clicks Magic Link Email
The email contains a link like:
```
http://localhost:8080/login/ott?token=abc-123-def-456
```

### Step 3: Get Form Configuration
```bash
curl "http://localhost:8080/api/magic-link/form?token=abc-123-def-456"
```

### Step 4: Submit Form Data
```bash
curl -X POST "http://localhost:8080/api/magic-link/process-form?token=abc-123-def-456" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "company": "Acme Inc",
    "role": "developer"
  }'
```

### Step 5: Poll Processing Status (every 2 seconds)
```bash
# Poll until status is "completed"
curl "http://localhost:8080/api/magic-link/check-status?token=abc-123-def-456"
```

### Step 6: User is Authenticated
Once processing is complete, the user is automatically authenticated and can access protected resources.

---

## Field Types

### Text Field
```json
{
  "name": "fieldName",
  "label": "Field Label",
  "type": "text",
  "required": true,
  "placeholder": "Enter text here"
}
```

### Select Field
```json
{
  "name": "fieldName",
  "label": "Field Label",
  "type": "select",
  "required": false,
  "options": [
    { "value": "option1", "label": "Option 1" },
    { "value": "option2", "label": "Option 2" }
  ]
}
```

---

## Token Expiration

- Magic link tokens expire after **15 minutes** (configurable)
- The `tokenExpiresIn` field in the form config shows remaining seconds
- Expired tokens return a 401 Unauthorized error

---

## Error Codes

| Code | Description |
|------|-------------|
| `INVALID_TOKEN` | Token is invalid, expired, or already used |
| `STATUS_NOT_FOUND` | Processing status not found for token |
| `PROCESSING_FAILED` | Form processing encountered an error |

---

## Swagger UI

Interactive API documentation available at:
```
http://localhost:8080/swagger-ui.html
```

OpenAPI JSON specification:
```
http://localhost:8080/v3/api-docs
```
