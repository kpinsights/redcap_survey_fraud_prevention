<?php
/**
 * Survey Fraud Prevention - REDCap External Module
 *
 * Provides multi-layer verification for REDCap surveys to prevent fraudulent responses.
 * Supports IP geolocation checking, Google reCAPTCHA v3 bot detection, and SMS OTP.
 *
 *
 * @package    CERCHECW\SurveyFraudPrevention
 * @author     Kshitiz Pokhrel <kpokhrel@torontomu.ca>
 * @author     Ryan McRonald <rmcronald@uvic.ca>
 * @copyright  2026 CERC in Health Equity & Community Well-Being
 * @license    MIT
 */

namespace CERCHECW\SurveyFraudPrevention;

use ExternalModules\AbstractExternalModule;

class SurveyFraudPrevention extends AbstractExternalModule
{
    /** @var string Twilio Verify API base URL */
    private const TWILIO_API = 'https://verify.twilio.com/v2/Services/';

    /** @var string ip-api.com endpoint for geolocation */
    private const IPAPI_ENDPOINT = 'http://ip-api.com/json/';

    /** @var string ipinfo.io endpoint for geolocation */
    private const IPINFO_ENDPOINT = 'https://ipinfo.io/';

    /** @var string Google reCAPTCHA verification endpoint */
    private const RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify';

    /** @var string Twilio Lookup API base URL */
    private const TWILIO_LOOKUP_API = 'https://lookups.twilio.com/v2/PhoneNumbers/';

    /** @var string Session key prefix for IP verification status */
    private const IP_SESSION = 'ip_verified_';

    /** @var string Session key prefix for reCAPTCHA verification status */
    private const RECAPTCHA_SESSION = 'recaptcha_verified_';

    /** @var string Session key prefix for OTP verification status */
    private const OTP_SESSION = 'otp_verified_';

    /** @var int Rate limit window in hours */
    private const RATE_LIMIT_HOURS = 1;

    /** @var string Prefix for phone hash log entries */
    private const PHONE_HASH_PREFIX = 'phone_hash:';

    /** @var array|null Cached country configuration */
    private $countries = null;

    /**
     * Load country configuration from external file
     *
     * @return array Country definitions keyed by ISO code
     */
    private function getCountries()
    {
        if ($this->countries === null) {
            $this->countries = require __DIR__ . '/countries.php';
        }
        return $this->countries;
    }

    /**
     * Populate country dropdown choices from countries.php
     *
     * REDCap hook that fires when configuration settings are loaded.
     * Dynamically builds the country selection lists so administrators
     * only need to edit countries.php to add or remove supported countries.
     *
     * @param int $project_id Current project ID (null for system settings)
     * @param array $settings Module configuration settings
     * @return array Modified settings with populated country choices
     */
    public function redcap_module_configuration_settings($project_id, $settings)
    {
        $countries = $this->getCountries();

        // Build choices for IP countries (just name)
        $ipChoices = [];
        foreach ($countries as $code => $info) {
            $ipChoices[] = ['value' => $code, 'name' => $info['name']];
        }

        // Build choices for phone countries (name + phone code)
        $phoneChoices = [];
        foreach ($countries as $code => $info) {
            $phoneChoices[] = ['value' => $code, 'name' => $info['name'] . ' (' . $info['phone'] . ')'];
        }

        // Update the settings array
        foreach ($settings as &$setting) {
            if ($setting['key'] === 'ip-allowed-countries') {
                $setting['choices'] = $ipChoices;
            }
            if ($setting['key'] === 'phone-allowed-countries') {
                $setting['choices'] = $phoneChoices;
            }
        }

        return $settings;
    }

    /**
     * Main entry point for survey verification
     *
     * REDCap hook that fires when a survey page loads. Implements the
     * three-layer verification flow: IP geolocation, reCAPTCHA bot detection,
     * and phone OTP verification. Each layer is optional and configurable.
     *
     * @param int $project_id Current project ID
     * @param string|null $record Record ID (may be null for new records)
     * @param string $instrument Form/instrument name
     * @param int $event_id Event ID for longitudinal projects
     * @param int|null $group_id Data Access Group ID
     * @param string $survey_hash Unique survey identifier
     * @param int|null $response_id Survey response ID
     * @param int $repeat_instance Repeating instance number
     */
    public function redcap_survey_page_top($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance)
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        // Skip if this form doesn't need verification
        if (!$this->needsVerification($instrument)) {
            return;
        }

        // Build a stable session seed from instrument identity (not survey_hash,
        // which changes on each page of a multi-page instrument and would
        // re-trigger verification when navigating between pages).
        $sessionSeed = $project_id . '_' . $instrument . '_' . $event_id;

        // Store context for ajax calls
        $_SESSION['otp_survey_context'] = [
            'project_id' => $project_id,
            'record' => $record,
            'instrument' => $instrument,
            'event_id' => $event_id,
            'survey_hash' => $survey_hash,
            'session_seed' => $sessionSeed,
            'response_id' => $response_id,
            'repeat_instance' => $repeat_instance
        ];

        // Layer 1: IP check
        if ($this->getProjectSetting('enable-ip-verification')) {
            $ipKey = self::IP_SESSION . hash('sha256', $sessionSeed . '_ip');

            if (empty($_SESSION[$ipKey])) {
                $ipCheck = $this->checkIPLocation($sessionSeed);

                if (!$ipCheck['ok']) {
                    $this->showIPBlockPage($ipCheck['reason'], $ipCheck['country'] ?? '');
                    return;
                }
            }
        }

        // Layer 2: reCAPTCHA v3 (invisible bot detection)
        // Only run here if timing is set to "page_load"
        // Other timings (send_code, survey_submit) are handled in JS/ajax
        if ($this->getProjectSetting('enable-recaptcha') && $this->hasRecaptchaCredentials()) {
            $recaptchaTiming = $this->getProjectSetting('recaptcha-timing') ?: 'page_load';
            $recaptchaKey = self::RECAPTCHA_SESSION . hash('sha256', $sessionSeed . '_recaptcha');

            if ($recaptchaTiming === 'page_load' && empty($_SESSION[$recaptchaKey])) {
                // Inject reCAPTCHA script and handle verification via AJAX immediately
                $this->injectRecaptchaScript($survey_hash, 'page_load');
            }
        }

        // Layer 3: Phone OTP
        if ($this->getProjectSetting('enable-phone-otp') && $this->hasTwilioCredentials()) {
            $otpKey = self::OTP_SESSION . hash('sha256', $sessionSeed . '_otp');

            if (empty($_SESSION[$otpKey])) {
                $this->showPhoneVerification($survey_hash);
                return;
            }
        }

        // reCAPTCHA on survey submit (runs after all other layers pass)
        if ($this->getProjectSetting('enable-recaptcha') && $this->hasRecaptchaCredentials()) {
            $recaptchaTiming = $this->getProjectSetting('recaptcha-timing') ?: 'page_load';

            if ($recaptchaTiming === 'survey_submit') {
                $this->injectRecaptchaOnSubmit($survey_hash);
            }
        }
    }


    // =========================================================================
    // IP Verification
    // =========================================================================

    /**
     * Determine the client's real IP address
     *
     * Checks common proxy headers in priority order to find the originating
     * client IP when behind load balancers, CDNs, or reverse proxies.
     *
     * @return string Client IP address
     */
    private function getClientIP()
    {
        $headers = [
            'HTTP_CF_CONNECTING_IP',  // Cloudflare
            'HTTP_X_FORWARDED_FOR',   // Generic proxy
            'HTTP_X_REAL_IP',         // nginx
            'HTTP_CLIENT_IP',
            'REMOTE_ADDR'
        ];

        foreach ($headers as $h) {
            if (!empty($_SERVER[$h])) {
                // X-Forwarded-For can have multiple IPs, grab the first one
                $ip = trim(explode(',', $_SERVER[$h])[0]);

                // Make sure it's a real public IP
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    /**
     * Verify client IP against location and security rules
     *
     * Performs geolocation lookup and checks against project settings:
     * country whitelist, VPN/proxy blocking, and datacenter IP blocking.
     * The IP address is used transiently and never stored.
     *
     * @param string $surveyHash Survey identifier for session storage
     * @return array Result with 'ok' (bool), 'country' (string), 'reason' (string)
     */
    public function checkIPLocation($surveyHash)
    {
        $geoService = $this->getSystemSetting('ip-geolocation-service');

        if ($geoService === 'disabled') {
            $this->saveIPStatus($surveyHash, true, '');
            return ['ok' => true, 'country' => '', 'reason' => 'geo_disabled'];
        }

        // Lookup geolocation data, then discard the IP
        $clientIP = $this->getClientIP();
        $geo = $this->lookupIP($clientIP);
        unset($clientIP);

        if (!$geo['success']) {
            $failMode = $this->getSystemSetting('ip-api-failure-mode') ?: 'fail-open';

            if ($failMode === 'fail-open') {
                $this->logEvent('IP check skipped - API down, fail-open policy');
                $this->saveIPStatus($surveyHash, true, '');
                return ['ok' => true, 'country' => '', 'reason' => 'api_down'];
            }

            $this->logEvent('IP check blocked - API down, fail-closed policy');
            return ['ok' => false, 'country' => '', 'reason' => 'service_unavailable'];
        }

        if ($this->getProjectSetting('block-vpn') && $geo['vpn']) {
            $this->logEvent('Blocked: VPN/proxy detected');
            return ['ok' => false, 'country' => $geo['country'], 'reason' => 'vpn_detected'];
        }

        if ($this->getProjectSetting('block-datacenter') && $geo['hosting']) {
            $this->logEvent('Blocked: Datacenter IP');
            return ['ok' => false, 'country' => $geo['country'], 'reason' => 'datacenter_detected'];
        }

        $allowed = $this->getProjectSetting('ip-allowed-countries') ?: [];
        if (!is_array($allowed)) $allowed = [$allowed];
        $allowed = array_filter($allowed);

        if (!empty($allowed) && !in_array($geo['country'], $allowed)) {
            $this->logEvent('Blocked: Country ' . $geo['country'] . ' not in allowed list');
            return ['ok' => false, 'country' => $geo['country'], 'reason' => 'country_not_allowed'];
        }

        $this->logEvent('IP check passed - Country: ' . $geo['country']);
        $this->saveIPStatus($surveyHash, true, $geo['country']);

        return ['ok' => true, 'country' => $geo['country'], 'reason' => 'verified'];
    }

    /**
     * Route IP lookup to configured geolocation service
     *
     * @param string $ip IP address to look up
     * @return array Normalized result with success, country, vpn, and hosting flags
     */
    private function lookupIP($ip)
    {
        $service = $this->getSystemSetting('ip-geolocation-service') ?: 'ip-api';

        return ($service === 'ipinfo') ? $this->callIPInfo($ip) : $this->callIPApi($ip);
    }

    /**
     * Query ip-api.com for geolocation data
     *
     * Free tier supports 45 requests per minute. Returns country code
     * and proxy/hosting detection flags.
     *
     * @param string $ip IP address to look up
     * @return array Lookup result
     */
    private function callIPApi($ip)
    {
        $url = self::IPAPI_ENDPOINT . $ip . '?fields=status,countryCode,proxy,hosting';

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10
        ]);

        $resp = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        if ($code !== 200 || empty($resp)) {
            return ['success' => false];
        }

        $data = json_decode($resp, true);

        if (($data['status'] ?? '') !== 'success') {
            return ['success' => false];
        }

        return [
            'success' => true,
            'country' => $data['countryCode'] ?? '',
            'vpn' => !empty($data['proxy']),
            'hosting' => !empty($data['hosting'])
        ];
    }

    /**
     * Query ipinfo.io for geolocation data
     *
     * Paid service with higher limits and privacy detection via
     * the Privacy Detection add-on. Requires API token.
     *
     * @param string $ip IP address to look up
     * @return array Lookup result
     */
    private function callIPInfo($ip)
    {
        $token = $this->getSystemSetting('ipinfo-api-token');
        if (empty($token)) {
            return ['success' => false];
        }

        $url = self::IPINFO_ENDPOINT . $ip . '?token=' . $token;

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10
        ]);

        $resp = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        if ($code !== 200 || empty($resp)) {
            return ['success' => false];
        }

        $data = json_decode($resp, true);
        $priv = $data['privacy'] ?? [];

        return [
            'success' => true,
            'country' => $data['country'] ?? '',
            'vpn' => !empty($priv['vpn']) || !empty($priv['proxy']) || !empty($priv['tor']),
            'hosting' => !empty($priv['hosting'])
        ];
    }

    // =========================================================================
    // reCAPTCHA v3 Verification
    // =========================================================================

    /**
     * Check if reCAPTCHA credentials are configured at system level
     *
     * @return bool True if both site key and secret key are set
     */
    private function hasRecaptchaCredentials()
    {
        return !empty($this->getSystemSetting('recaptcha-site-key'))
            && !empty($this->getSystemSetting('recaptcha-secret-key'));
    }

    /**
     * Verify reCAPTCHA v3 token with Google's API
     *
     * Sends the token to Google for verification and compares the returned
     * score against the configured threshold. Scores range from 0.0 (bot)
     * to 1.0 (human).
     *
     * @param string $token reCAPTCHA response token from client
     * @param string $surveyHash Survey identifier for session storage
     * @return array Result with 'success', 'score', and 'error' or 'reason'
     */
    public function verifyRecaptcha($token, $surveyHash)
    {
        $secretKey = $this->getSystemSetting('recaptcha-secret-key');
        $minScore = (float)($this->getProjectSetting('recaptcha-min-score') ?: '0.5');
        $failMode = $this->getProjectSetting('recaptcha-failure-mode') ?: 'fail-open';

        // Use stable session seed for session keys
        $ctx = $_SESSION['otp_survey_context'] ?? [];
        $sessionSeed = $ctx['session_seed'] ?? $surveyHash;

        if (empty($token)) {
            $this->logEvent('reCAPTCHA failed - no token provided');
            return ['success' => false, 'error' => 'Verification failed. Please refresh and try again.'];
        }

        // Call Google's verification API
        $ch = curl_init(self::RECAPTCHA_VERIFY_URL);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query([
                'secret' => $secretKey,
                'response' => $token
            ]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10
        ]);

        $resp = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);

        if ($curlError || $httpCode !== 200 || empty($resp)) {
            $this->logEvent('reCAPTCHA API error: ' . ($curlError ?: "HTTP $httpCode"));

            if ($failMode === 'fail-open') {
                $this->logEvent('reCAPTCHA skipped - API error, fail-open policy');
                $this->saveRecaptchaStatus($sessionSeed, true);
                return ['success' => true, 'score' => null, 'reason' => 'api_error_failopen'];
            }

            return ['success' => false, 'error' => 'Verification service unavailable. Please try again later.'];
        }

        $data = json_decode($resp, true);

        if (empty($data['success'])) {
            $errors = $data['error-codes'] ?? [];
            $this->logEvent('reCAPTCHA verification failed: ' . implode(', ', $errors));
            return ['success' => false, 'error' => 'Verification failed. Please refresh and try again.'];
        }

        $score = $data['score'] ?? 0;
        $this->logEvent("reCAPTCHA score: $score (threshold: $minScore)");

        if ($score < $minScore) {
            $this->logEvent("reCAPTCHA blocked - score $score below threshold $minScore");
            return [
                'success' => false,
                'score' => $score,
                'error' => $this->getProjectSetting('recaptcha-block-message')
                    ?: 'Our system detected unusual activity. Please try again or contact the survey administrator.'
            ];
        }

        $this->saveRecaptchaStatus($sessionSeed, true);
        $this->logEvent("reCAPTCHA passed - score: $score");

        return ['success' => true, 'score' => $score, 'reason' => 'verified'];
    }

    /**
     * Store reCAPTCHA verification status in session
     *
     * @param string $seed Session seed for key derivation
     * @param bool $verified Verification status
     */
    private function saveRecaptchaStatus($seed, $verified)
    {
        $key = self::RECAPTCHA_SESSION . hash('sha256', $seed . '_recaptcha');
        $_SESSION[$key] = $verified;
    }

    /**
     * Output reCAPTCHA JavaScript to the page
     *
     * Loads the Google reCAPTCHA v3 library and optionally executes
     * verification immediately on page load.
     *
     * @param string $surveyHash Survey identifier for verification callback
     * @param string $timing Execution mode: 'page_load' runs immediately
     */
    private function injectRecaptchaScript($surveyHash, $timing = 'page_load')
    {
        $siteKey = $this->getSystemSetting('recaptcha-site-key');
        $ajaxUrl = $this->getUrl('ajax_handler.php', true, true);
        $csrfToken = $this->getCSRFToken();
        ?>
        <script src="https://www.google.com/recaptcha/api.js?render=<?= htmlspecialchars($siteKey) ?>"></script>
        <?php if ($timing === 'page_load'): ?>
        <script>
        (function() {
            // Run reCAPTCHA verification automatically when page loads
            grecaptcha.ready(function() {
                grecaptcha.execute(<?= json_encode($siteKey) ?>, {action: 'survey_access'}).then(function(token) {
                    // Send token to server for verification
                    fetch(<?= json_encode($ajaxUrl) ?>, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                        body: 'action=verify_recaptcha&recaptcha_token=' + encodeURIComponent(token) +
                              '&survey_hash=' + encodeURIComponent(<?= json_encode($surveyHash) ?>) +
                              '&redcap_csrf_token=' + encodeURIComponent(<?= json_encode($csrfToken) ?>) +
                              '&survey_session_id=' + encodeURIComponent(<?= json_encode(session_id()) ?>) +
                              '&session_seed=' + encodeURIComponent(<?= json_encode($_SESSION['otp_survey_context']['session_seed'] ?? '') ?>)
                    })
                    .then(function(response) { return response.json(); })
                    .then(function(data) {
                        if (data.success) {
                            // reCAPTCHA passed - session is marked, no reload needed
                            console.log('reCAPTCHA verified (page_load)');
                        } else {
                            // Show block message
                            document.body.innerHTML = '<div style="position:fixed;inset:0;background:rgba(0,0,0,.9);display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif">' +
                                '<div style="background:#fff;border-radius:12px;padding:40px;max-width:480px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.3)">' +
                                '<h2 style="color:#dc2626;margin:0 0 15px">Verification Failed</h2>' +
                                '<p style="color:#4b5563;line-height:1.6;margin-bottom:25px">' + (data.error || 'Unable to verify. Please try again.') + '</p>' +
                                '<button onclick="location.reload()" style="padding:12px 30px;background:#4a90d9;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer">Try Again</button>' +
                                '</div></div>';
                        }
                    })
                    .catch(function(err) {
                        console.error('reCAPTCHA verification error:', err);
                        // On network error, continue anyway (fail-open for UX)
                    });
                });
            });
        })();
        </script>
        <?php endif; ?>
        <?php
    }

    /**
     * Output reCAPTCHA JavaScript that triggers on form submission
     *
     * This timing option provides Google with the most behavioral data
     * since it observes the entire survey interaction before verification.
     *
     * @param string $surveyHash Survey identifier for verification callback
     */
    private function injectRecaptchaOnSubmit($surveyHash)
    {
        $siteKey = $this->getSystemSetting('recaptcha-site-key');
        $ajaxUrl = $this->getUrl('ajax_handler.php', true, true);
        $csrfToken = $this->getCSRFToken();
        ?>
        <script src="https://www.google.com/recaptcha/api.js?render=<?= htmlspecialchars($siteKey) ?>"></script>
        <script>
        (function() {
            // Find the survey form and intercept submit
            var form = document.querySelector('form[name="form"]') || document.querySelector('form#form');
            if (!form) return;

            var originalSubmit = form.onsubmit;
            var recaptchaVerified = false;

            form.addEventListener('submit', function(e) {
                // If already verified, let submit proceed
                if (recaptchaVerified) return true;

                e.preventDefault();
                e.stopPropagation();

                // Show a subtle loading indicator
                var submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
                var originalText = submitBtn ? (submitBtn.value || submitBtn.textContent) : '';
                if (submitBtn) {
                    if (submitBtn.tagName === 'INPUT') submitBtn.value = 'Verifying...';
                    else submitBtn.textContent = 'Verifying...';
                    submitBtn.disabled = true;
                }

                grecaptcha.ready(function() {
                    grecaptcha.execute(<?= json_encode($siteKey) ?>, {action: 'survey_submit'}).then(function(token) {
                        fetch(<?= json_encode($ajaxUrl) ?>, {
                            method: 'POST',
                            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                            body: 'action=verify_recaptcha&recaptcha_token=' + encodeURIComponent(token) +
                                  '&survey_hash=' + encodeURIComponent(<?= json_encode($surveyHash) ?>) +
                                  '&redcap_csrf_token=' + encodeURIComponent(<?= json_encode($csrfToken) ?>) +
                                  '&survey_session_id=' + encodeURIComponent(<?= json_encode(session_id()) ?>) +
                                  '&session_seed=' + encodeURIComponent(<?= json_encode($_SESSION['otp_survey_context']['session_seed'] ?? '') ?>)
                        })
                        .then(function(response) { return response.json(); })
                        .then(function(data) {
                            if (data.success) {
                                // reCAPTCHA passed, submit form
                                recaptchaVerified = true;
                                if (submitBtn) {
                                    submitBtn.disabled = false;
                                    if (submitBtn.tagName === 'INPUT') submitBtn.value = originalText;
                                    else submitBtn.textContent = originalText;
                                }
                                form.submit();
                            } else {
                                // Show error
                                alert(data.error || 'Verification failed. Please try again.');
                                if (submitBtn) {
                                    submitBtn.disabled = false;
                                    if (submitBtn.tagName === 'INPUT') submitBtn.value = originalText;
                                    else submitBtn.textContent = originalText;
                                }
                            }
                        })
                        .catch(function(err) {
                            console.error('reCAPTCHA error:', err);
                            // On error, allow submit (fail-open behavior for UX)
                            recaptchaVerified = true;
                            if (submitBtn) {
                                submitBtn.disabled = false;
                                if (submitBtn.tagName === 'INPUT') submitBtn.value = originalText;
                                else submitBtn.textContent = originalText;
                            }
                            form.submit();
                        });
                    });
                });

                return false;
            }, true);
        })();
        </script>
        <?php
    }

    // =========================================================================
    // Phone Verification
    // =========================================================================

    /**
     * Validate phone number against allowed countries
     *
     * Extracts the country from the phone prefix and checks against the
     * project's allowed country list. North American numbers (+1) receive
     * special handling since Canada and US share the same prefix.
     *
     * @param string $phone Phone number in E.164 format
     * @param string $surveyHash Survey identifier for NANP resolution
     * @return array Result with 'valid', 'country_code', and 'error'
     */
    public function validatePhoneCountry($phone, $surveyHash)
    {
        // Use stable session seed for IP country lookup
        $ctx = $_SESSION['otp_survey_context'] ?? [];
        $sessionSeed = $ctx['session_seed'] ?? $surveyHash;

        $phoneCountry = $this->getCountryFromPhonePrefix($phone);

        if (empty($phoneCountry)) {
            return [
                'valid' => false,
                'country_code' => '',
                'error' => 'Unable to determine country. Please include the country code (e.g., +1, +44).'
            ];
        }

        $allowed = $this->getProjectSetting('phone-allowed-countries') ?: [];
        if (!is_array($allowed)) $allowed = [$allowed];
        $allowed = array_filter($allowed);

        // Special handling for +1 (NANP - North American Numbering Plan)
        // Canada and US share the +1 prefix, so we use the canada-us-distinction setting
        if ($phoneCountry === 'NANP') {
            $phoneCountry = $this->resolveNANPCountry($sessionSeed, $allowed);
        }

        if (!empty($allowed) && !in_array($phoneCountry, $allowed)) {
            $name = $this->countryName($phoneCountry);
            return [
                'valid' => false,
                'country_code' => $phoneCountry,
                'error' => "Phone numbers from {$name} are not accepted for this survey."
            ];
        }

        return ['valid' => true, 'country_code' => $phoneCountry, 'error' => ''];
    }

    /**
     * Extract country code from phone number prefix
     *
     * Matches the phone number against known country prefixes from the
     * configuration. Returns 'NANP' for +1 numbers since Canada and US
     * share this prefix and require additional resolution.
     *
     * @param string $phone Phone number in E.164 format
     * @return string ISO country code, 'NANP', or empty string if unknown
     */
    private function getCountryFromPhonePrefix($phone)
    {
        $digits = ltrim($phone, '+');
        $countries = $this->getCountries();

        // Build prefix map from countries config, sorted by prefix length (longer first)
        $prefixMap = [];
        foreach ($countries as $code => $info) {
            // Skip CA/US - they share +1 and are handled as NANP
            if ($code === 'CA' || $code === 'US') continue;
            $prefixMap[$info['prefix']] = $code;
        }

        // Sort by prefix length descending (longer prefixes first for accurate matching)
        uksort($prefixMap, function($a, $b) {
            return strlen($b) - strlen($a);
        });

        // Add NANP last (shortest prefix, catches all +1 numbers)
        $prefixMap['1'] = 'NANP';

        foreach ($prefixMap as $prefix => $country) {
            if (strpos($digits, $prefix) === 0) {
                return $country;
            }
        }

        return '';
    }

    /**
     * Resolve North American (+1) number to specific country
     *
     * Canada and US share the +1 prefix, making reliable distinction difficult
     * without a comprehensive area code database. Two resolution strategies:
     *
     * - accept_both (default): Accept any +1 number if CA or US is allowed.
     *   Accommodates travelers with phones from either country.
     *
     * - ip_match: Use the detected IP country. More restrictive but may
     *   block legitimate users traveling between countries.
     *
     * @param string $sessionSeed Session seed for IP country lookup
     * @param array $allowedCountries List of allowed country codes
     * @return string Resolved country code (CA, US, or NANP if neither allowed)
     */
    private function resolveNANPCountry($sessionSeed, $allowedCountries)
    {
        $method = $this->getProjectSetting('canada-us-distinction') ?: 'accept_both';

        $caAllowed = in_array('CA', $allowedCountries);
        $usAllowed = in_array('US', $allowedCountries);

        if ($method === 'accept_both') {
            if ($caAllowed) return 'CA';
            if ($usAllowed) return 'US';
            return 'NANP';
        }

        if ($method === 'ip_match') {
            $ipCountry = $this->getIPCountry($sessionSeed);

            if ($ipCountry === 'CA' || $ipCountry === 'US') {
                return $ipCountry;
            }

            if ($caAllowed) return 'CA';
            if ($usAllowed) return 'US';
        }

        return $caAllowed ? 'CA' : ($usAllowed ? 'US' : 'NANP');
    }

    /**
     * Send verification code via Twilio Verify API
     *
     * Validates the phone number format and country, checks for reuse,
     * enforces rate limits, then sends the SMS. The phone number is stored
     * temporarily in the session for verification but never persisted.
     *
     * @param string $phone Phone number in E.164 format
     * @param string|null $surveyHash Survey identifier (falls back to session)
     * @return array Result with 'success', 'message' or 'error', and 'country_code'
     */
    public function sendOTP($phone, $surveyHash = null)
    {
        // Use provided hash or fall back to session
        if (!$surveyHash) {
            $surveyHash = $_SESSION['otp_survey_context']['survey_hash'] ?? '';
        }

        if (!preg_match('/^\+[1-9]\d{6,14}$/', $phone)) {
            return ['success' => false, 'error' => 'Invalid phone format. Use international format like +12345678900'];
        }

        $validation = $this->validatePhoneCountry($phone, $surveyHash);
        if (!$validation['valid']) {
            return ['success' => false, 'error' => $validation['error']];
        }

        if ($this->getProjectSetting('prevent-phone-reuse')) {
            $ctx = $_SESSION['otp_survey_context'] ?? [];
            $record = $ctx['record'] ?? null;

            $reuseCheck = $this->checkPhoneReuse($phone, $record);
            if (!$reuseCheck['allowed']) {
                return ['success' => false, 'error' => $reuseCheck['error']];
            }
        }

        // Check line type (VoIP/landline blocking)
        $lineTypeCheck = $this->checkLineType($phone);
        if (!$lineTypeCheck['allowed']) {
            return ['success' => false, 'error' => $lineTypeCheck['error']];
        }

        if ($this->getProjectSetting('enable-rate-limiting') && !$this->checkRateLimit()) {
            return ['success' => false, 'error' => 'Too many attempts. Please wait before trying again.'];
        }

        $sid = $this->getSystemSetting('twilio-account-sid');
        $token = $this->getSystemSetting('twilio-auth-token');
        $serviceSid = $this->getSystemSetting('twilio-verify-service-sid');

        if (empty($sid) || empty($token) || empty($serviceSid)) {
            $this->logEvent('OTP send failed - Twilio not configured');
            return ['success' => false, 'error' => 'Verification service not set up. Contact the survey admin.'];
        }

        $url = self::TWILIO_API . $serviceSid . '/Verifications';
        $result = $this->twilioRequest($url, ['To' => $phone, 'Channel' => 'sms'], $sid, $token);

        if ($result['success']) {
            $_SESSION['otp_pending_phone'] = $phone;
            $_SESSION['otp_pending_country'] = $validation['country_code'];

            $this->bumpRateLimit();
            $this->logEvent('OTP sent - Country: ' . $validation['country_code']);

            return [
                'success' => true,
                'message' => 'Code sent! Check your phone.',
                'country_code' => $validation['country_code']
            ];
        }

        $this->logEvent('OTP send failed - Twilio error');
        return ['success' => false, 'error' => $this->friendlyTwilioError($result['error'] ?? '')];
    }

    /**
     * Verify the submitted OTP code via Twilio Verify API
     *
     * Checks the code against Twilio's verification service. On success,
     * marks the session as verified and optionally binds the phone hash
     * to prevent reuse. The actual phone number is then cleared from session.
     *
     * @param string $phone Phone number that received the code
     * @param string $code Six-digit verification code
     * @param string $surveyHash Survey identifier for session key
     * @return array Result with 'success' and 'message' or 'error'
     */
    public function verifyOTP($phone, $code, $surveyHash)
    {
        if (!preg_match('/^\d{6}$/', $code)) {
            return ['success' => false, 'error' => 'Please enter the 6-digit code.'];
        }

        $pendingPhone = $_SESSION['otp_pending_phone'] ?? '';
        if ($phone !== $pendingPhone) {
            return ['success' => false, 'error' => 'Phone mismatch. Please try again.'];
        }

        $sid = $this->getSystemSetting('twilio-account-sid');
        $token = $this->getSystemSetting('twilio-auth-token');
        $serviceSid = $this->getSystemSetting('twilio-verify-service-sid');

        $url = self::TWILIO_API . $serviceSid . '/VerificationCheck';
        $result = $this->twilioRequest($url, ['To' => $phone, 'Code' => $code], $sid, $token);

        if ($result['success'] && ($result['data']['status'] ?? '') === 'approved') {
            // Use stable session seed for session key
            $ctx = $_SESSION['otp_survey_context'] ?? [];
            $sessionSeed = $ctx['session_seed'] ?? $surveyHash;
            $key = self::OTP_SESSION . hash('sha256', $sessionSeed . '_otp');
            $_SESSION[$key] = true;

            if ($this->getProjectSetting('prevent-phone-reuse')) {
                $ctx = $_SESSION['otp_survey_context'] ?? [];
                $record = $ctx['record'] ?? null;
                $instrument = $ctx['instrument'] ?? null;

                $this->logEvent("Binding phone - record: " . ($record ?: 'none') . ", instrument: " . ($instrument ?: 'none'));

                $bindRecord = $record ?: 'anonymous_' . time();
                $this->bindPhoneToRecord($phone, $bindRecord);
            }

            unset($_SESSION['otp_pending_phone']);

            $this->logEvent('OTP verified successfully');
            return ['success' => true, 'message' => 'Verified!'];
        }

        $this->logEvent('OTP verification failed - wrong code');
        return ['success' => false, 'error' => 'Wrong code or it expired. Try again.'];
    }

    /**
     * Execute HTTP request to Twilio API
     *
     * @param string $url Twilio API endpoint
     * @param array $data POST parameters
     * @param string $sid Twilio Account SID
     * @param string $token Twilio Auth Token
     * @return array Result with 'success', 'data' or 'error'
     */
    private function twilioRequest($url, $data, $sid, $token)
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($data),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_USERPWD => $sid . ':' . $token,
            CURLOPT_TIMEOUT => 30
        ]);

        $resp = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        
        if ($err) {
            return ['success' => false, 'error' => 'Network error'];
        }

        $body = json_decode($resp, true);

        if ($code >= 200 && $code < 300) {
            return ['success' => true, 'data' => $body];
        }

        return [
            'success' => false,
            'error' => $body['message'] ?? $body['error_message'] ?? 'Unknown error'
        ];
    }

    /**
     * Convert Twilio error messages to user-friendly text
     *
     * @param string $msg Raw error message from Twilio
     * @return string User-friendly error message
     */
    private function friendlyTwilioError($msg)
    {
        $map = [
            'Invalid parameter `To`' => 'That phone number doesn\'t look right.',
            'Max send attempts reached' => 'Too many tries. Wait a few minutes.',
            'Invalid phone number' => 'Invalid phone number. Use format like +12345678900',
            'Rate limit exceeded' => 'Slow down! Wait a minute and try again.',
        ];

        foreach ($map as $pattern => $friendly) {
            if (stripos($msg, $pattern) !== false) {
                return $friendly;
            }
        }

        return 'Couldn\'t send the code. Try again or contact the survey admin.';
    }

    /**
     * Check phone line type via Twilio Lookup API
     *
     * Uses Twilio's Lookup v2 API to determine if the phone number is
     * mobile, landline, or VoIP. This has per-request costs (~$0.005).
     *
     * @param string $phone Phone number in E.164 format
     * @return array Result with 'success', 'line_type', and 'carrier'
     */
    private function lookupLineType($phone)
    {
        $sid = $this->getSystemSetting('twilio-account-sid');
        $token = $this->getSystemSetting('twilio-auth-token');

        if (empty($sid) || empty($token)) {
            return ['success' => false, 'error' => 'Twilio credentials not configured'];
        }

        // Phone is already validated via regex in sendOTP() before reaching here.
        // Sending to Twilio Lookup API is the intended behavior for VoIP detection.
        $url = self::TWILIO_LOOKUP_API . urlencode($phone) . '?Fields=line_type_intelligence';

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_USERPWD => $sid . ':' . $token,
            CURLOPT_TIMEOUT => 10
        ]);

        $resp = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        
        if ($err || $httpCode !== 200 || empty($resp)) {
            $this->logEvent('Twilio Lookup failed: ' . ($err ?: "HTTP $httpCode"));
            return ['success' => false, 'error' => 'Lookup service unavailable'];
        }

        $data = json_decode($resp, true);
        $lineTypeData = $data['line_type_intelligence'] ?? [];
        $lineType = $lineTypeData['type'] ?? null;
        $carrier = $lineTypeData['carrier_name'] ?? '';
        $errorCode = $lineTypeData['error_code'] ?? null;

        // Handle known error codes
        if ($errorCode === 60601) {
            // Canadian numbers require CLNPC authorization
            $this->logEvent('Line type lookup: unavailable for Canadian numbers (CLNPC authorization required)');
            return ['success' => false, 'error' => 'CLNPC authorization required for Canadian numbers'];
        }

        if ($errorCode) {
            $this->logEvent("Line type lookup error: code $errorCode");
            return ['success' => false, 'error' => "Lookup error: $errorCode"];
        }

        $typeDisplay = $lineType ?: 'unknown';
        $this->logEvent("Line type lookup: $typeDisplay" . ($carrier ? " ($carrier)" : ''));

        return [
            'success' => true,
            'line_type' => $lineType,
            'carrier' => $carrier
        ];
    }

    /**
     * Check if phone line type is allowed
     *
     * @param string $phone Phone number in E.164 format
     * @return array Result with 'allowed' (bool) and 'error' (string)
     */
    private function checkLineType($phone)
    {
        $blockVoip = $this->getProjectSetting('block-voip');

        if (empty($blockVoip)) {
            return ['allowed' => true, 'error' => ''];
        }

        $lookup = $this->lookupLineType($phone);

        if (!$lookup['success']) {
            // Fail open if lookup fails - don't block users due to API issues
            $this->logEvent('Line type check skipped - lookup failed');
            return ['allowed' => true, 'error' => ''];
        }

        $lineType = strtolower($lookup['line_type'] ?? '');

        // VoIP blocking logic
        if (!empty($blockVoip)) {
            $isVoip = false;

            if ($blockVoip === 'non-fixed') {
                // Block only non-fixed VoIP (Google Voice, TextNow, etc.)
                $isVoip = ($lineType === 'nonfixedvoip');
            } elseif ($blockVoip === 'all') {
                // Block all VoIP types
                $isVoip = in_array($lineType, ['voip', 'nonfixedvoip', 'fixedvoip']);
            }

            if ($isVoip) {
                $msg = $this->getProjectSetting('voip-block-message')
                    ?: 'Internet-based phone numbers (VoIP) are not accepted. Please use a mobile phone number.';
                $this->logEvent('Blocked: VoIP number detected (' . $lineType . ') - ' . ($lookup['carrier'] ?? 'unknown carrier'));
                return ['allowed' => false, 'error' => $msg];
            }
        }

        return ['allowed' => true, 'error' => ''];
    }

    // =========================================================================
    // Phone Reuse Prevention
    // =========================================================================

    /**
     * Generate one-way hash for phone reuse detection
     *
     * Creates a SHA-256 hash of phone number combined with project ID and
     * instrument name. This allows detecting reuse while ensuring the actual
     * phone number cannot be recovered from stored data.
     *
     * The instrument is included so the same phone can be used across different
     * instruments in longitudinal studies while preventing duplicate submissions
     * to the same instrument.
     *
     * @param string $phone Phone number
     * @param string|null $instrument Instrument name (falls back to session)
     * @return string SHA-256 hash
     */
    private function generatePhoneHash($phone, $instrument = null)
    {
        $projectId = $this->getProjectId();

        // Get instrument from parameter or session context
        if (!$instrument) {
            $ctx = $_SESSION['otp_survey_context'] ?? [];
            $instrument = $ctx['instrument'] ?? '';
        }

        return hash('sha256', $phone . '|' . $projectId . '|' . $instrument);
    }

    /**
     * Check if phone number was previously used for this instrument
     *
     * Queries the module log for an existing phone hash entry. The hash
     * is scoped to project + instrument, so:
     * - Same phone on same instrument = blocked (prevents duplicates)
     * - Same phone on different instrument = allowed (longitudinal studies)
     *
     * @param string $phone Phone number to check
     * @param string|null $currentRecord Current record ID (not used in current logic)
     * @return array Result with 'allowed' (bool) and 'error' (string)
     */
    private function checkPhoneReuse($phone, $currentRecord)
    {
        $ctx = $_SESSION['otp_survey_context'] ?? [];
        $instrument = $ctx['instrument'] ?? '';

        $phoneHash = $this->generatePhoneHash($phone, $instrument);
        $searchMsg = self::PHONE_HASH_PREFIX . $phoneHash;

        $this->logEvent("Phone reuse check - instrument: " . $instrument . ", hash: " . substr($phoneHash, 0, 16) . "...");

        $sql = "SELECT record WHERE message = ?";
        $result = $this->queryLogs($sql, [$searchMsg]);

        $foundCount = $result->num_rows;
        $this->logEvent("Phone reuse check - found " . $foundCount . " existing entries");

        if ($foundCount === 0) {
            return ['allowed' => true, 'error' => ''];
        }

        $row = $result->fetch_assoc();
        $existingRecord = $row['record'];

        $this->logEvent("Phone reuse BLOCKED - already used for instrument '$instrument' by record: " . $existingRecord);

        return [
            'allowed' => false,
            'error' => 'This phone number has already been used for this survey.'
        ];
    }

    /**
     * Check if a record exists in the database
     *
     * @param string $record Record ID to check
     * @return bool True if record has any data
     */
    private function recordHasData($record)
    {
        if (empty($record)) {
            return false;
        }

        $projectId = $this->getProjectId();
        $dataTable = \REDCap::getDataTable($projectId);
        $sql = "SELECT 1 FROM `$dataTable` WHERE project_id = ? AND record = ? LIMIT 1";
        $result = $this->query($sql, [$projectId, $record]);

        return $result->num_rows > 0;
    }

    /**
     * Store phone hash to prevent reuse on this instrument
     *
     * Saves only the SHA-256 hash (not the actual phone number) to the
     * module log. The hash is scoped to project + instrument to allow
     * the same phone for different instruments while blocking duplicates.
     *
     * @param string $phone Phone number (used only for hashing)
     * @param string $record Record ID to associate with the hash
     */
    private function bindPhoneToRecord($phone, $record)
    {
        $ctx = $_SESSION['otp_survey_context'] ?? [];
        $instrument = $ctx['instrument'] ?? '';

        $phoneHash = $this->generatePhoneHash($phone, $instrument);
        $searchMsg = self::PHONE_HASH_PREFIX . $phoneHash;

        $sql = "SELECT 1 WHERE message = ?";
        $result = $this->queryLogs($sql, [$searchMsg]);

        if ($result->num_rows === 0) {
            $this->log($searchMsg, ['record' => $record]);
            $this->logEvent("Phone hash saved for instrument '$instrument' (record: $record)");
        } else {
            $this->logEvent("Phone hash already exists for instrument '$instrument' - skipping save");
        }
    }

    // =========================================================================
    // Session & Rate Limiting
    // =========================================================================

    /**
     * Store IP verification status in session
     *
     * @param string $seed Session seed for key derivation
     * @param bool $verified Verification status
     * @param string $country Detected country code
     */
    private function saveIPStatus($seed, $verified, $country)
    {
        $key = self::IP_SESSION . hash('sha256', $seed . '_ip');
        $_SESSION[$key] = $verified;
        $_SESSION[$key . '_country'] = $country;
    }

    /**
     * Retrieve stored IP country from session
     *
     * @param string $seed Session seed for key derivation
     * @return string Country code or empty string
     */
    public function getIPCountry($seed)
    {
        $key = self::IP_SESSION . hash('sha256', $seed . '_ip');
        return $_SESSION[$key . '_country'] ?? '';
    }

    /**
     * Check if OTP request is within rate limit
     *
     * @return bool True if request is allowed
     */
    private function checkRateLimit()
    {
        $max = (int)($this->getProjectSetting('max-otp-requests') ?: 5);
        $key = 'otp_rate_limit';
        $now = time();
        $window = self::RATE_LIMIT_HOURS * 3600;

        if (!isset($_SESSION[$key])) return true;

        $_SESSION[$key] = array_filter($_SESSION[$key], fn($t) => ($now - $t) < $window);

        return count($_SESSION[$key]) < $max;
    }

    /**
     * Record an OTP request for rate limiting
     */
    private function bumpRateLimit()
    {
        $key = 'otp_rate_limit';
        if (!isset($_SESSION[$key])) $_SESSION[$key] = [];
        $_SESSION[$key][] = time();
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Check if instrument requires verification
     *
     * @param string $instrument Instrument name
     * @return bool True if verification is required
     */
    private function needsVerification($instrument)
    {
        $forms = $this->getProjectSetting('verification-instruments') ?: [];
        if (!is_array($forms)) $forms = [$forms];
        return in_array($instrument, $forms);
    }

    /**
     * Check if Twilio credentials are configured at system level
     *
     * @return bool True if all required credentials are set
     */
    private function hasTwilioCredentials()
    {
        return !empty($this->getSystemSetting('twilio-account-sid'))
            && !empty($this->getSystemSetting('twilio-auth-token'))
            && !empty($this->getSystemSetting('twilio-verify-service-sid'));
    }

    /**
     * Get human-readable country name from ISO code
     *
     * @param string $code ISO country code
     * @return string Country name or the code itself if not found
     */
    private function countryName($code)
    {
        $countries = $this->getCountries();
        return $countries[$code]['name'] ?? $code;
    }

    /**
     * Write entry to module log
     *
     * All logged messages are privacy-safe and contain no IP addresses
     * or phone numbers. Includes record/instrument context when available.
     *
     * @param string $msg Log message
     */
    private function logEvent($msg)
    {
        if (!$this->getSystemSetting('global-enable-logging')) return;

        $ctx = $_SESSION['otp_survey_context'] ?? [];
        $this->log($msg, [
            'record' => $ctx['record'] ?? null,
            'instrument' => $ctx['instrument'] ?? null,
            'event_id' => $ctx['event_id'] ?? null
        ]);
    }

    // =========================================================================
    // UI - Block Pages & Overlays
    // =========================================================================

    /**
     * Display IP verification failure page
     *
     * @param string $reason Failure reason code
     * @param string $country Detected country code (if available)
     */
    private function showIPBlockPage($reason, $country)
    {
        $messages = [
            'vpn_detected' => $this->getProjectSetting('ip-block-message-vpn')
                ?: 'Looks like you\'re using a VPN. Please disable it and refresh to continue.',
            'datacenter_detected' => 'It looks like you\'re connecting from a VPN, proxy, or cloud service. Please disable it and try again.',
            'country_not_allowed' => $this->getProjectSetting('ip-block-message-country')
                ?: 'This survey is only available in certain regions, and your location isn\'t eligible.',
            'service_unavailable' => 'Verification service is temporarily down. Please try again later.'
        ];

        $title = ($reason === 'service_unavailable') ? 'Service Unavailable' : 'Access Restricted';
        $msg = $messages[$reason] ?? 'Access not available from your current connection.';
        $showRetry = in_array($reason, ['vpn_detected', 'datacenter_detected', 'service_unavailable']);
        ?>
        <style>
            .block-overlay{position:fixed;inset:0;background:rgba(0,0,0,.9);z-index:9999;display:flex;align-items:center;justify-content:center;font-family:system-ui,-apple-system,sans-serif}
            .block-box{background:#fff;border-radius:12px;padding:40px;max-width:480px;width:90%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.3)}
            .block-box h2{color:#dc2626;margin:0 0 15px}
            .block-box p{color:#4b5563;line-height:1.6;margin-bottom:25px}
            .block-box button{padding:12px 30px;background:#4a90d9;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer}
            .block-box button:hover{background:#3a7bc8}
        </style>
        <div class="block-overlay">
            <div class="block-box">
                <h2><?= htmlspecialchars($title) ?></h2>
                <p><?= htmlspecialchars($msg) ?></p>
                <?php if ($showRetry): ?>
                    <button onclick="location.reload()">Try Again</button>
                <?php endif; ?>
            </div>
        </div>
        <?php
    }

    /**
     * Display phone verification overlay
     *
     * Renders the verification UI with phone input, code entry, and all
     * necessary JavaScript. Includes accessibility features (ARIA labels,
     * keyboard navigation) and passes configuration to the frontend.
     *
     * @param string $surveyHash Survey identifier for AJAX requests
     */
    private function showPhoneVerification($surveyHash)
    {
        $ajaxUrl = $this->getUrl('ajax_handler.php', true, true);
        $jsUrl = $this->getUrl('js/verification.js');

        // Get CSRF token for AJAX requests
        $csrfToken = $this->getCSRFToken();

        $customMsg = $this->getProjectSetting('phone-custom-message')
            ?: 'To make sure you\'re a real person, please verify your phone number.';
        $expiry = (int)($this->getProjectSetting('otp-expiration-minutes') ?: 10);
        $showPrivacy = $this->getProjectSetting('show-privacy-notice');
        $privacyText = $this->getProjectSetting('custom-privacy-notice')
            ?: 'We don\'t store your phone number. It\'s only used to send the verification code.';

        $allowedCountries = $this->getProjectSetting('phone-allowed-countries') ?: [];
        if (!is_array($allowedCountries)) $allowedCountries = [$allowedCountries];
        $allowedCountries = array_filter($allowedCountries);
        $ctx = $_SESSION['otp_survey_context'] ?? [];
        $sessionSeed = $ctx['session_seed'] ?? $surveyHash;
        $ipCountry = $this->getIPCountry($sessionSeed);

        // Build country labels from config
        $countryLabels = [];
        foreach ($this->getCountries() as $code => $info) {
            $countryLabels[$code] = $info['name'] . ' (' . $info['phone'] . ')';
        }
        ?>
        <style>
            /* Accessibility: High contrast colors meeting WCAG AA standards */
            /* Colorblind-safe: No red/green only indicators - always paired with icons/text */
            .otp-overlay{position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:9999;display:flex;align-items:center;justify-content:center;font-family:system-ui,-apple-system,sans-serif}
            .otp-box{background:#fff;border-radius:12px;padding:40px;max-width:400px;width:90%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.3)}
            .otp-box h2{margin:0 0 10px;font-size:22px;color:#1a1a2e}
            .otp-box .subtitle{color:#555;font-size:14px;margin-bottom:20px;line-height:1.5}
            .otp-box .form-group{margin-bottom:20px;text-align:left}
            .otp-box label{display:block;margin-bottom:8px;color:#222;font-weight:600;font-size:14px}
            .otp-box input{width:100%;padding:14px;border:2px solid #666;border-radius:8px;font-size:18px;box-sizing:border-box}
            .otp-box input:focus{outline:3px solid #005fcc;outline-offset:2px;border-color:#005fcc}
            .otp-box .btn{width:100%;padding:14px;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;background:#005fcc;color:#fff}
            .otp-box .btn:hover:not(:disabled){background:#004299}
            .otp-box .btn:focus{outline:3px solid #005fcc;outline-offset:2px}
            .otp-box .btn:disabled{opacity:.6;cursor:not-allowed}
            .otp-box .message{padding:12px;border-radius:8px;margin-bottom:20px;font-size:14px;display:none;font-weight:500}
            .otp-box .message.error{display:block;background:#fef2f2;color:#b91c1c;border:2px solid #b91c1c}
            .otp-box .message.error::before{content:"⚠ ";font-size:16px}
            .otp-box .message.success{display:block;background:#f0fdf4;color:#166534;border:2px solid #166534}
            .otp-box .message.success::before{content:"✓ ";font-size:16px}
            .otp-step{display:none}.otp-step.active{display:block}
            .phone-display{background:#f1f5f9;padding:12px;border-radius:6px;margin-bottom:20px;font-family:monospace;font-size:16px;border:1px solid #cbd5e1}
            .country-hint{font-size:13px;color:#444;margin-top:8px;padding:10px;background:#e0f2fe;border-radius:6px;border:1px solid #7dd3fc}
            .privacy-note{font-size:12px;color:#555;margin-top:20px;padding:12px;background:#f8fafc;border-radius:6px;border:1px solid #e2e8f0}
            .timer{font-size:14px;color:#444;margin-top:15px;font-weight:500}
            .timer.warning{color:#b91c1c;font-weight:700}
            .timer.warning::before{content:"⚠ "}
            .link{color:#005fcc;cursor:pointer;text-decoration:underline;font-weight:500}.link:hover{color:#004299}
            .link:focus{outline:2px solid #005fcc;outline-offset:2px}
            .link.disabled{color:#666;cursor:not-allowed;text-decoration:none}
            /* Screen reader only - visually hidden but accessible */
            .sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
        </style>

        <script>
        // Disable form to prevent direct POST bypass
        (function() {
            var form = document.querySelector('form#form') || document.querySelector('form[name="form"]');
            if (form) {
                // Store original action and remove it
                window.__originalFormAction = form.action;
                form.action = 'javascript:void(0)';
                form.setAttribute('data-verification-pending', 'true');

                // Disable all inputs
                var inputs = form.querySelectorAll('input, select, textarea, button');
                for (var i = 0; i < inputs.length; i++) {
                    inputs[i].disabled = true;
                    inputs[i].setAttribute('data-was-enabled', 'true');
                }

                // Block form submit event
                form.addEventListener('submit', function(e) {
                    if (form.getAttribute('data-verification-pending') === 'true') {
                        e.preventDefault();
                        e.stopPropagation();
                        return false;
                    }
                }, true);
            }

            // Function to re-enable form after verification (called from verification.js)
            window.__enableFormAfterVerification = function() {
                var form = document.querySelector('form#form') || document.querySelector('form[name="form"]');
                if (form && window.__originalFormAction) {
                    form.action = window.__originalFormAction;
                    form.removeAttribute('data-verification-pending');

                    var inputs = form.querySelectorAll('[data-was-enabled="true"]');
                    for (var i = 0; i < inputs.length; i++) {
                        inputs[i].disabled = false;
                        inputs[i].removeAttribute('data-was-enabled');
                    }
                }
            };
        })();
        </script>

        <!-- ARIA live region for screen reader announcements -->
        <div id="otp-live-region" class="sr-only" aria-live="polite" aria-atomic="true"></div>

        <div class="otp-overlay" id="verification-overlay" role="dialog" aria-modal="true" aria-labelledby="otp-title" aria-describedby="otp-subtitle">
            <div class="otp-box" id="verification-box">
                <h2 id="otp-title">Phone Verification</h2>
                <p id="otp-subtitle" class="subtitle"><?= htmlspecialchars($customMsg) ?></p>

                <div id="otp-message" class="message" aria-live="assertive"></div>

                <div id="otp-step-phone" class="otp-step active">
                    <div class="form-group">
                        <label for="otp-phone">Phone Number</label>
                        <input type="tel" id="otp-phone" placeholder="+1 234 567 8900" autocomplete="tel" aria-describedby="phone-hint" aria-required="true">
                        <?php if ($allowedCountries): ?>
                            <div id="phone-hint" class="country-hint">
                                Accepted: <?= implode(', ', array_map(function($c) use ($countryLabels) { return $countryLabels[$c] ?? $c; }, $allowedCountries)) ?>
                            </div>
                        <?php endif; ?>
                    </div>
                    <button type="button" class="btn" id="btn-send-otp" aria-busy="false">Send Code</button>
                </div>

                <div id="otp-step-verify" class="otp-step">
                    <p id="code-sent-label" style="font-size:14px;color:#555;margin-bottom:15px">Code sent to:</p>
                    <div class="phone-display" id="display-phone" aria-labelledby="code-sent-label"></div>
                    <div class="form-group">
                        <label for="otp-code">6-Digit Verification Code</label>
                        <input type="text" id="otp-code" placeholder="Enter code" maxlength="6" inputmode="numeric" pattern="[0-9]*" aria-describedby="timer-info" aria-required="true" autocomplete="one-time-code">
                    </div>
                    <button type="button" class="btn" id="btn-verify-otp" aria-busy="false">Verify</button>
                    <div id="timer-info" class="timer" aria-live="polite">Expires in <span id="timer-countdown"><?= $expiry ?>:00</span></div>
                    <div style="margin-top:15px;font-size:14px">
                        Didn't get it? <button type="button" class="link" id="btn-resend-otp" aria-disabled="false" style="background:none;border:none;padding:0;font:inherit">Resend code</button>
                    </div>
                    <div style="margin-top:10px">
                        <button type="button" class="link" id="btn-change-number" style="font-size:13px;background:none;border:none;padding:0;font:inherit">Use different number</button>
                    </div>
                </div>

                <?php if ($showPrivacy): ?>
                    <div class="privacy-note" role="note"><?= htmlspecialchars($privacyText) ?></div>
                <?php endif; ?>
            </div>
        </div>

        <?php
        // reCAPTCHA config for "send_code" timing
        $recaptchaEnabled = $this->getProjectSetting('enable-recaptcha') && $this->hasRecaptchaCredentials();
        $recaptchaTiming = $this->getProjectSetting('recaptcha-timing') ?: 'page_load';
        $recaptchaSiteKey = $this->getSystemSetting('recaptcha-site-key');

        // Load reCAPTCHA script if timing is send_code (so it can observe form interaction)
        if ($recaptchaEnabled && $recaptchaTiming === 'send_code'):
        ?>
        <script src="https://www.google.com/recaptcha/api.js?render=<?= htmlspecialchars($recaptchaSiteKey) ?>"></script>
        <?php endif; ?>

        <script>
            window.OTP_CONFIG = {
                verifyUrl: <?= json_encode($ajaxUrl) ?>,
                csrfToken: <?= json_encode($csrfToken) ?>,
                surveyHash: <?= json_encode($surveyHash) ?>,
                sessionSeed: <?= json_encode($sessionSeed) ?>,
                surveySessionId: <?= json_encode(session_id()) ?>,
                otpExpiration: <?= $expiry ?>,
                allowedCountries: <?= json_encode($allowedCountries) ?>,
                ipCountry: <?= json_encode($ipCountry) ?>,
                recaptcha: {
                    enabled: <?= json_encode($recaptchaEnabled && $recaptchaTiming === 'send_code') ?>,
                    siteKey: <?= json_encode($recaptchaSiteKey) ?>
                }
            };
        </script>
        <script src="<?= $jsUrl ?>"></script>
        <?php
    }

}
