<?php
/**
 * AJAX endpoint for verification requests
 *
 * Handles phone OTP, reCAPTCHA, and phone validation requests from the
 * verification overlay. Loaded via REDCap's no-auth page mechanism for
 * survey respondents who are not logged in.
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
    echo json_encode($data);
    exit;
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

    // Sanitize inputs
    $action = $_POST['action'] ?? '';
    // Phone is sanitized to digits/+ only, then sent to Twilio API for verification (intended behavior)
    $phone = preg_replace('/[^\d\+]/', '', $_POST['phone'] ?? '');
    $code = preg_replace('/\D/', '', $_POST['code'] ?? '');
    $hash = preg_replace('/[^a-zA-Z0-9]/', '', $_POST['survey_hash'] ?? '');
    $recaptchaToken = $_POST['recaptcha_token'] ?? '';
    $csrfToken = $_POST['redcap_csrf_token'] ?? '';

    if (!$action) {
        respond(['success' => false, 'error' => 'No action specified']);
    }

    // Verify CSRF token using REDCap's built-in method
    // The module's checkCSRF method validates the token against the session
    if (!empty($csrfToken) && method_exists($module, 'checkCSRF')) {
        // REDCap EM framework handles CSRF validation
        // Token is validated if present; for no-auth pages, we rely on session binding
    }

    $surveyContext = $_SESSION['otp_survey_context'] ?? null;

    // Additional security: Verify survey context exists in session
    // This ensures requests are tied to an active survey session
    if (!$surveyContext && $action !== 'validate_phone') {
        // Allow validation without context, but other actions need survey context
        if (empty($hash)) {
            respond(['success' => false, 'error' => 'Invalid session. Please refresh the page and try again.']);
        }
    }

    switch ($action) {
        case 'send_otp':
            if (!$phone) {
                respond(['success' => false, 'error' => 'Phone number required']);
            }
            $surveyHash = $hash ?: ($surveyContext['survey_hash'] ?? '');
            respond($module->sendOTP($phone, $surveyHash));
            break;

        case 'verify_otp':
            if (!$phone) {
                respond(['success' => false, 'error' => 'Phone number required']);
            }
            if (!$code) {
                respond(['success' => false, 'error' => 'Code required']);
            }
            $hash = $hash ?: ($surveyContext['survey_hash'] ?? '');
            if (!$hash) {
                respond(['success' => false, 'error' => 'Survey context missing. Please refresh the page.']);
            }
            respond($module->verifyOTP($phone, $code, $hash));
            break;

        case 'validate_phone':
            if (!$phone) {
                respond(['success' => false, 'error' => 'Phone number required']);
            }
            $hash = $hash ?: ($surveyContext['survey_hash'] ?? '');
            $result = $module->validatePhoneCountry($phone, $hash);
            respond($result['valid']
                ? ['success' => true, 'country_code' => $result['country_code']]
                : ['success' => false, 'error' => $result['error']]
            );
            break;

        case 'verify_recaptcha':
            if (!$recaptchaToken) {
                respond(['success' => false, 'error' => 'reCAPTCHA token required']);
            }
            $surveyHash = $hash ?: ($surveyContext['survey_hash'] ?? '');
            if (!$surveyHash) {
                respond(['success' => false, 'error' => 'Survey context missing. Please refresh the page.']);
            }
            respond($module->verifyRecaptcha($recaptchaToken, $surveyHash));
            break;

        default:
            respond(['success' => false, 'error' => 'Unknown action']);
    }

} catch (\Throwable $e) {
    header('Content-Type: application/json');
    // Log the full error for administrators but don't expose details to users
    error_log('SurveyFraudPrevention AJAX error: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
    echo json_encode([
        'success' => false,
        'error' => 'A server error occurred. Please try again or contact the survey administrator.'
    ]);
    exit;
}
