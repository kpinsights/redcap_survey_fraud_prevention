# Survey Fraud Prevention Module

A REDCap External Module for preventing fraudulent survey responses through multi-layer verification (IP, reCAPTCHA V3 and OTP).

## Overview

Public REDCap surveys are vulnerable to fraudulent responses from bots, click farms, and participants gaming incentive systems. This module addresses these issues by verifying that respondents are real people accessing from expected geographic locations.

## How It Works

The module implements three verification layers. All are optional and can be configured independently per project.

### Layer 1: IP Verification

When a participant opens a survey link, the module checks their IP address automatically in the background. No user interaction is required. The check includes:

- Country detection (is the participant in an allowed region?)
- VPN and proxy detection
- Datacenter IP detection (commonly used by bots)

If any check fails, the participant sees a block page and cannot proceed to the survey.

### Layer 2: Google reCAPTCHA v3 (Bot Detection)

The module can run invisible bot detection using Google reCAPTCHA v3. This runs automatically in the background with no user interaction:

- Google analyzes user behavior patterns invisibly
- Returns a score from 0.0 (likely bot) to 1.0 (likely human)
- Scores below the configured threshold are blocked
- Legitimate users pass through without seeing anything

### Layer 3: Phone Verification

If previous layers pass (or are not enabled), the participant sees a phone verification overlay:

1. Participant enters their phone number with country code
2. They receive an SMS with a 6-digit verification code
3. They enter the code
4. The overlay disappears and the survey loads

## Privacy

This module is designed with privacy in mind:

- IP addresses are used only for the verification check and immediately discarded
- Phone numbers are used only to send the verification code and immediately discarded
- When phone reuse prevention is enabled, only a one-way SHA-256 hash is stored in REDCap's module log (not in project data tables). This hash cannot be reversed to recover the original phone number—it only allows the system to check "has this phone been used before?"
- Verification state exists only in the PHP session for the duration of the survey

## Requirements

- REDCap 15.0.0 or higher
- PHP 7.4 or higher
- Twilio account with Verify service enabled (for phone verification)
- Twilio Lookup API access (for VoIP blocking, optional)
- Google reCAPTCHA v3 site key and secret key (for bot detection, optional)

## Installation

1. Download or clone this repository
2. Place the folder in your REDCap modules directory
3. Enable the module in Control Center > External Modules
4. Configure the system settings (Twilio credentials, IP geolocation service)
5. Enable the module on specific projects as needed

## Configuration

### System Settings (REDCap Administrators)

These settings are configured once and apply globally to all projects.

**Twilio API Credentials**
- Account SID (starts with AC)
- Auth Token
- Verify Service SID (starts with VA)

These credentials can be found in your Twilio Console under Verify > Services.

**IP Geolocation Service**
- ip-api.com: Free tier with 45 requests per minute limit
- ipinfo.io: Paid service requiring an API token
- Disabled: No IP verification available

**IP API Failure Mode**
- Fail Open: Allow survey access if the geolocation API is unavailable
- Fail Closed: Block survey access if the geolocation API is unavailable

**Google reCAPTCHA v3**
- Site Key: Public key for the reCAPTCHA widget
- Secret Key: Private key for server-side verification

To obtain reCAPTCHA keys, visit https://www.google.com/recaptcha/admin and register your domain.

### Project Settings

Project administrators can configure the following options:

**General**
- Select which instruments require verification

**IP Verification (Layer 1)**
- Enable or disable IP verification
- Select allowed countries
- Enable VPN/proxy blocking
- Enable datacenter IP blocking
- Customize block messages

**reCAPTCHA v3 (Layer 2)**
- Enable or disable reCAPTCHA bot detection
- When to run reCAPTCHA:
  - **On Page Load** (default): Runs after IP check passes—bots blocked by IP never trigger reCAPTCHA
  - **When Clicking 'Send Code'**: Runs when user clicks Send Code button
  - **On Survey Submit**: Runs when user submits the survey
- Set minimum score threshold (0.3 lenient to 0.9 strict, default 0.5)
- Configure failure mode (fail open or closed)
- Customize the bot detection block message

**Phone Verification (Layer 3)**
- Enable or disable phone OTP
- Select allowed countries for phone numbers
- Configure North American (+1) number handling (accept both CA/US or match IP)
- Prevent phone number reuse (one phone per instrument)
- Block VoIP numbers using Twilio Lookup API (optional, costs extra)
- Customize the verification message

**Rate Limiting**
- Maximum OTP requests per hour (default: 5)
- OTP expiration time in minutes (default: 10)

**Privacy Notice**
- Show or hide privacy notice on verification screen
- Customize privacy notice text

## Supported Countries

The module currently supports verification for the following countries:

- North America: Canada, United States
- Europe: United Kingdom, Ireland, Germany, France, Netherlands
- Asia Pacific: Australia, New Zealand, India
- Latin America: Mexico, Brazil
- Africa: South Africa

To add more countries, edit `countries.php`. Changes automatically apply to all dropdowns and validation logic.

For Canadian and American phone numbers (both use +1 country code), the default behavior accepts any +1 number if either Canada or US is in the allowed list.

## Accessibility

The verification interface includes:

- ARIA live regions for screen reader announcements
- Full keyboard navigation support
- High contrast colors meeting WCAG AA standards
- Icons paired with text (no color-only indicators)

## Costs

### Twilio Verify (SMS OTP)
- Twilio Verify charges per verification. See https://www.twilio.com/en-us/verify/pricing for current pricing.

### Twilio Lookup (VoIP Blocking)
- Line Type Intelligence: **$0.008 per request**
- Only charged when VoIP blocking is enabled
- See the VoIP Blocking section below for details

### Google reCAPTCHA v3
- **Free tier:** Up to 10,000 assessments per month
- **Standard tier:** Up to 100,000 assessments for $8/month
- **Enterprise tier:** $1 per 1,000 assessments beyond 100,000/month

### IP Geolocation
- ip-api.com: Free (45 requests/minute limit)
- ipinfo.io: Paid service (see https://ipinfo.io/pricing)

## File Structure

```
SurveyFraudPrevention.php    Main module class
config.json            Module configuration and settings
countries.php          Country definitions (edit here to add countries)
ajax_handler.php       AJAX endpoint for verification requests
js/verification.js     Frontend verification interface
LICENSE                MIT License
README.md              This file
```

## Technical Details

### Verification Flow

1. The `redcap_survey_page_top` hook fires when a survey page loads
2. The module checks if the current instrument requires verification
3. If IP verification is enabled, the geolocation API is called
4. If the IP check fails, a block page is displayed and execution stops
5. If reCAPTCHA is enabled with "page load" timing, verification runs immediately via AJAX
6. If phone verification is enabled:
   - The underlying REDCap form is disabled (action changed, inputs disabled)
   - The verification overlay is displayed
7. If reCAPTCHA uses "send code" timing, it runs when the user clicks Send Code
8. The Twilio Verify API handles SMS delivery and code validation
9. Upon successful verification, the form is re-enabled and the overlay removed
10. If reCAPTCHA uses "survey submit" timing, it runs when the user submits the survey
11. Verification status is stored in the PHP session

### Form Protection

When phone verification is enabled, the module disables the underlying REDCap form until verification completes:

- Form action is changed to `javascript:void(0)`
- All form inputs are disabled
- Submit events are blocked by an event listener
- Only after successful phone verification is the form restored

This prevents bypass attempts where an attacker removes the verification overlay using browser developer tools.

### Phone Number Reuse Prevention

When enabled, the module prevents the same phone number from being used to submit multiple responses to the same instrument. This works by storing a one-way hash of the phone number (not the actual number) after successful verification.

The logic is per-instrument:
- Same phone + same instrument = blocked
- Same phone + different instrument = allowed (supports longitudinal studies)

The phone number itself is never stored. Only a SHA-256 hash (which includes the project ID and instrument name) is saved to REDCap's module log table.

### VoIP Blocking

The module can optionally block VoIP numbers (internet-based phone numbers commonly used for fraud). This feature uses Twilio's Lookup API with Line Type Intelligence.

**Line Types Detected:**
- `mobile` - Mobile phone numbers
- `landline` - Landline numbers (cannot receive SMS)
- `fixedVoip` - Fixed VoIP (e.g., Comcast, Vonage)
- `nonFixedVoip` - Non-fixed VoIP (e.g., Google Voice, TextNow)
- `tollFree`, `premium`, `voicemail`, `pager`, `unknown` - Other types

**VoIP Blocking Options:**
- Disabled: Allow all phone types (default)
- Block Non-Fixed VoIP Only: Blocks Google Voice, TextNow, etc.
- Block All VoIP: Blocks all internet-based numbers

**Cost:** $0.008 per Lookup API request.

**Canadian Phone Numbers:**

Line type lookup for Canadian phone numbers requires authorization from the Canadian Local Number Portability Consortium (CLNPC). Without this authorization, Twilio returns error code 60601 and VoIP blocking will not work for Canadian numbers.

To apply for CLNPC authorization, see: https://help.twilio.com/articles/360004563433

### Rate Limiting

The module can limit OTP requests per session. The default is 5 requests per hour. This prevents repeated code requests.

### Session Management

Verification status is stored in the PHP session using SHA-256 hashed keys derived from the survey hash. This means:

- Refreshing the page will not trigger re-verification
- Opening the survey in a new browser or after session expiration will require re-verification

## Authors

- Kshitiz Pokhrel, Toronto Metropolitan University
- Ryan McRonald, University of Victoria

Developed at the CERC in Health Equity & Community Well-Being.

## License

MIT License. See LICENSE file for details.
