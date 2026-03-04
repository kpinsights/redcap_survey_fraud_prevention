<?php
/**
 * AJAX endpoint for verification requests
 *
 * Handles phone OTP, reCAPTCHA, and phone validation requests from the
 * verification overlay. Loaded via REDCap's no-auth page mechanism for
 * survey respondents who are not logged in.
 *
 * Note: The AJAX endpoint runs in a different PHP session than the survey
 * page. After successful verification, we write the status flag to the
 * survey page's session (identified by survey_session_id) so the hook
 * can read it on subsequent page loads.
 *
 * @package    CERCHECW\SurveyFraudPrevention
 */

namespace CERCHECW\SurveyFraudPrevention;

/**
 * Send JSON response and terminate
 *
 * @param array $data Response data
 */
function respond($data) {
    header('Content-Type: application/json');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($data);
    exit;
}

/**
 * Write a verification flag to the survey page's PHP session.
 *
 * The AJAX handler runs in a separate session from the survey page.
 * This function closes the current session, opens the survey page's
 * session by ID, writes the key, then restores the original session.
 *
 * @param string $surveySessionId The survey page's PHP session ID
 * @param string $key Session key to set
 * @param mixed $value Value to store
 */
function writeSurveySession($surveySessionId, $key, $value) {
    if (empty($surveySessionId)) return;

    // Save current session ID and close it
    $currentSessionId = session_id();
    session_write_close();

    // Open the survey page's session
    session_id($surveySessionId);
    session_start();
    $_SESSION[$key] = $value;
    session_write_close();

    // Restore the AJAX session
    session_id($currentSessionId);
    session_start();
}

set_error_handler(function($severity, $message, $file, $line) {
    throw new \ErrorException($message, 0, $severity, $file, $line);
});

try {
    if (!defined("NOAUTH")) define("NOAUTH", true);

    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    header('Content-Type: application/json');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('X-Content-Type-Options: nosniff');

    // Sanitize inputs with length limits to prevent oversized payloads
    $action = substr($_POST['action'] ?? '', 0, 20);
    // Phone is sanitized to digits/+ only, then sent to Twilio API for verification (intended behavior)
    $phone = substr(preg_replace('/[^\d\+]/', '', $_POST['phone'] ?? ''), 0, 20);
    $code = substr(preg_replace('/\D/', '', $_POST['code'] ?? ''), 0, 10);
    $hash = substr(preg_replace('/[^a-zA-Z0-9]/', '', $_POST['survey_hash'] ?? ''), 0, 128);
    $recaptchaToken = substr($_POST['recaptcha_token'] ?? '', 0, 4096);
    $surveySessionId = substr(preg_replace('/[^a-zA-Z0-9,-]/', '', $_POST['survey_session_id'] ?? ''), 0, 128);
    $sessionSeed = substr(preg_replace('/[^a-zA-Z0-9_]/', '', $_POST['session_seed'] ?? ''), 0, 256);
    $nonce = substr($_POST['sfp_nonce'] ?? '', 0, 128);

    if (!$action) {
        respond(['success' => false, 'error' => 'No action specified']);
    }

    // Validate nonce against the survey page's session.
    // This replaces the previous no-op CSRF block and ensures requests
    // originate from our rendered page (CSRF protection for no-auth endpoints).
    if (empty($nonce) || empty($surveySessionId)) {
        respond(['success' => false, 'error' => 'Invalid request. Please refresh the page.']);
    }

    // Read nonce and survey context from the survey page's session
    // (the AJAX handler runs in a separate session, so these values
    // only exist in the survey page's session, not ours)
    $storedNonce = null;
    $surveyContext = null;
    $currentSid = session_id();
    session_write_close();
    session_id($surveySessionId);
    session_start();
    $storedNonce = $_SESSION['sfp_ajax_nonce'] ?? null;
    $surveyContext = $_SESSION['otp_survey_context'] ?? null;
    session_write_close();
    session_id($currentSid);
    session_start();

    if (!$storedNonce || !hash_equals($storedNonce, $nonce)) {
        respond(['success' => false, 'error' => 'Invalid request. Please refresh the page.']);
    }

    // Require survey context for all actions except validate_phone.
    // This ensures requests are tied to an active survey session and
    // prevents external callers from triggering OTP sends or verifications.
    if (!$surveyContext && $action !== 'validate_phone') {
        respond(['success' => false, 'error' => 'Invalid session. Please refresh the page and try again.']);
    }

    switch ($action) {
        case 'send_otp':
            if (!$phone) {
                respond(['success' => false, 'error' => 'Phone number required']);
            }
            $surveyHash = $surveyContext['survey_hash'] ?? '';
            respond($module->sendOTP($phone, $surveyHash));
            break;

        case 'verify_otp':
            if (!$phone) {
                respond(['success' => false, 'error' => 'Phone number required']);
            }
            if (!$code) {
                respond(['success' => false, 'error' => 'Code required']);
            }
            $surveyHash = $surveyContext['survey_hash'] ?? '';
            if (!$surveyHash) {
                respond(['success' => false, 'error' => 'Survey context missing. Please refresh the page.']);
            }
            $result = $module->verifyOTP($phone, $code, $surveyHash);

            // On success, write the OTP verified flag to the survey page's session
            if ($result['success'] && $surveySessionId && $sessionSeed) {
                $otpKey = 'otp_verified_' . hash('sha256', $sessionSeed . '_otp');
                writeSurveySession($surveySessionId, $otpKey, true);
            }

            respond($result);
            break;

        case 'validate_phone':
            if (!$phone) {
                respond(['success' => false, 'error' => 'Phone number required']);
            }
            $surveyHash = $hash ?: ($surveyContext['survey_hash'] ?? '');
            $result = $module->validatePhoneCountry($phone, $surveyHash);
            respond($result['valid']
                ? ['success' => true, 'country_code' => $result['country_code']]
                : ['success' => false, 'error' => $result['error']]
            );
            break;

        case 'verify_recaptcha':
            if (!$recaptchaToken) {
                respond(['success' => false, 'error' => 'reCAPTCHA token required']);
            }
            $surveyHash = $surveyContext['survey_hash'] ?? '';
            if (!$surveyHash) {
                respond(['success' => false, 'error' => 'Survey context missing. Please refresh the page.']);
            }
            $result = $module->verifyRecaptcha($recaptchaToken, $surveyHash);

            // On success, write the reCAPTCHA verified flag to the survey page's session
            if ($result['success'] && $surveySessionId && $sessionSeed) {
                $recaptchaKey = 'recaptcha_verified_' . hash('sha256', $sessionSeed . '_recaptcha');
                writeSurveySession($surveySessionId, $recaptchaKey, true);
            }

            respond($result);
            break;

        default:
            respond(['success' => false, 'error' => 'Unknown action']);
    }

} catch (\Throwable $e) {
    header('Content-Type: application/json');
    header('X-Content-Type-Options: nosniff');
    // Log the full error for administrators but don't expose details to users
    error_log('SurveyFraudPrevention AJAX error: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
    echo json_encode([
        'success' => false,
        'error' => 'A server error occurred. Please try again or contact the survey administrator.'
    ]);
    exit;
}
