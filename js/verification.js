/**
 * Phone Verification UI
 *
 * Handles the verification overlay for REDCap surveys. Manages phone input,
 * OTP code entry, countdown timer, and optional reCAPTCHA integration.
 *
 * Accessibility:
 * - ARIA live regions for screen reader announcements
 * - Full keyboard navigation support
 * - WCAG AA compliant color contrast
 * - Icons paired with text for status indicators
 *
 * @package CERCHECW\SurveyFraudPrevention
 */

(function() {
    'use strict';

    const config = window.OTP_CONFIG || {};
    let phone = '';
    let countdown = null;
    let canResend = true;
    let busy = false;

    const $ = function(id) { return document.getElementById(id); };
    const overlay = $('verification-overlay');
    const phoneStep = $('otp-step-phone');
    const verifyStep = $('otp-step-verify');
    const phoneInput = $('otp-phone');
    const codeInput = $('otp-code');
    const phoneDisplay = $('display-phone');
    const msgBox = $('otp-message');
    const sendBtn = $('btn-send-otp');
    const verifyBtn = $('btn-verify-otp');
    const resendBtn = $('btn-resend-otp');
    const changeBtn = $('btn-change-number');
    const timerSpan = $('timer-countdown');
    const liveRegion = $('otp-live-region');

    /**
     * Initialize the verification UI
     */
    function init() {
        if (!overlay || !phoneInput) return;

        if (sendBtn) sendBtn.addEventListener('click', sendCode);
        if (verifyBtn) verifyBtn.addEventListener('click', checkCode);
        if (resendBtn) resendBtn.addEventListener('click', resend);
        if (changeBtn) changeBtn.addEventListener('click', goBack);

        if (phoneInput) {
            phoneInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') { e.preventDefault(); sendCode(); }
            });
        }

        if (codeInput) {
            codeInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') { e.preventDefault(); checkCode(); }
            });

            codeInput.addEventListener('input', function() {
                this.value = this.value.replace(/\D/g, '');
                if (this.value.length === 6) checkCode();
            });
        }

        setupPhoneInput();
        prefillCountry();
        phoneInput.focus();
        announce('Phone verification required. Please enter your phone number to receive a verification code.');
    }

    /**
     * Configure phone input formatting
     */
    function setupPhoneInput() {
        if (!phoneInput) return;

        phoneInput.addEventListener('input', function() {
            var val = this.value.replace(/[^\d+]/g, '');
            if (val && !val.startsWith('+')) val = '+' + val.replace(/\+/g, '');
            this.value = val;
            hideMsg();
        });

        phoneInput.addEventListener('focus', function() {
            if (!this.value) this.value = '+';
        });
    }

    /**
     * Pre-fill country code based on IP detection or allowed countries
     */
    function prefillCountry() {
        if (!phoneInput || phoneInput.value.length > 1) return;

        var codes = {
            CA: '+1', US: '+1', UK: '+44', AU: '+61', DE: '+49',
            FR: '+33', NL: '+31', IE: '+353', NZ: '+64', IN: '+91',
            MX: '+52', BR: '+55', ZA: '+27'
        };

        if (config.ipCountry && codes[config.ipCountry]) {
            phoneInput.value = codes[config.ipCountry];
        } else if (config.allowedCountries && config.allowedCountries.length) {
            var first = config.allowedCountries[0];
            if (codes[first]) phoneInput.value = codes[first];
        }
    }

    /**
     * Announce message to screen readers via ARIA live region
     */
    function announce(message) {
        if (!liveRegion) return;
        liveRegion.textContent = '';
        setTimeout(function() {
            liveRegion.textContent = message;
        }, 50);
    }

    /**
     * Send verification code to phone number
     */
    function sendCode() {
        if (busy) return;

        var num = phoneInput.value.trim();
        if (!/^\+[1-9]\d{6,14}$/.test(num)) {
            showMsg('Enter a valid phone number with country code (e.g., +12345678900)', 'error');
            phoneInput.focus();
            announce('Error: Please enter a valid phone number with country code.');
            return;
        }

        busy = true;
        sendBtn.disabled = true;
        sendBtn.textContent = 'Verifying...';
        sendBtn.setAttribute('aria-busy', 'true');
        hideMsg();

        if (config.recaptcha && config.recaptcha.enabled && typeof grecaptcha !== 'undefined') {
            announce('Verifying. Please wait.');

            grecaptcha.ready(function() {
                grecaptcha.execute(config.recaptcha.siteKey, {action: 'send_otp'})
                    .then(function(token) {
                        // Verify reCAPTCHA token with server
                        return moduleAjax('verify_recaptcha', {
                            recaptcha_token: token,
                            survey_hash: config.surveyHash
                        });
                    })
                    .then(function(resp) {
                        if (resp.success) {
                            sendBtn.textContent = 'Sending...';
                            announce('Sending verification code. Please wait.');
                            return doSendOTP(num);
                        } else {
                            showMsg(resp.error || 'Verification failed. Please try again.', 'error');
                            announce('Error: ' + (resp.error || 'Verification failed.'));
                            resetSendBtn();
                        }
                    })
                    .catch(function(e) {
                        console.error('reCAPTCHA error:', e);
                        showMsg('Verification error - please try again', 'error');
                        announce('Verification error. Please try again.');
                        resetSendBtn();
                    });
            });
        } else {
            sendBtn.textContent = 'Sending...';
            announce('Sending verification code. Please wait.');
            doSendOTP(num);
        }
    }

    /**
     * Execute OTP send request
     */
    function doSendOTP(num) {
        return moduleAjax('send_otp', { phone: num, survey_hash: config.surveyHash })
            .then(function(resp) {
                if (resp.success) {
                    phone = num;
                    showVerifyUI();
                    startTimer();
                    showMsg(resp.message || 'Code sent!', 'success');
                    announce('Code sent successfully. Please check your phone and enter the 6-digit code.');
                } else {
                    showMsg(resp.error || 'Failed to send code', 'error');
                    phoneInput.focus();
                    announce('Error: ' + (resp.error || 'Failed to send code'));
                }
                resetSendBtn();
            })
            .catch(function(e) {
                console.error('AJAX error:', e);
                showMsg('Network error - check your connection', 'error');
                announce('Network error. Please check your connection and try again.');
                resetSendBtn();
            });
    }

    function resetSendBtn() {
        busy = false;
        sendBtn.disabled = false;
        sendBtn.textContent = 'Send Code';
        sendBtn.setAttribute('aria-busy', 'false');
    }

    /**
     * Verify the entered code
     */
    function checkCode() {
        if (busy) return;

        var code = codeInput.value.trim();
        if (!/^\d{6}$/.test(code)) {
            showMsg('Enter the 6-digit code', 'error');
            codeInput.focus();
            announce('Error: Please enter the 6-digit code from your phone.');
            return;
        }

        busy = true;
        verifyBtn.disabled = true;
        verifyBtn.textContent = 'Checking...';
        verifyBtn.setAttribute('aria-busy', 'true');
        hideMsg();
        announce('Verifying code. Please wait.');

        moduleAjax('verify_otp', {
            phone: phone,
            code: code,
            survey_hash: config.surveyHash
        })
            .then(function(resp) {
                if (resp.success) {
                    showMsg(resp.message || 'Verified!', 'success');
                    clearInterval(countdown);
                    announce('Verification successful! Loading survey.');

                    verifyBtn.textContent = '✓ Verified';
                    verifyBtn.style.background = '#16a34a';

                    // Re-enable the form now that verification passed
                    if (typeof window.__enableFormAfterVerification === 'function') {
                        window.__enableFormAfterVerification();
                    }

                    setTimeout(function() {
                        overlay.style.transition = 'opacity .3s';
                        overlay.style.opacity = '0';
                        setTimeout(function() { overlay.remove(); }, 300);
                    }, 1000);
                } else {
                    showMsg(resp.error || 'Wrong code', 'error');
                    codeInput.value = '';
                    codeInput.focus();
                    announce('Error: ' + (resp.error || 'Incorrect code. Please try again.'));
                }
            })
            .catch(function(e) {
                console.error('AJAX error:', e);
                showMsg('Network error', 'error');
                announce('Network error. Please try again.');
            })
            .finally(function() {
                busy = false;
                if (verifyBtn.textContent !== '✓ Verified') {
                    verifyBtn.disabled = false;
                    verifyBtn.textContent = 'Verify';
                    verifyBtn.setAttribute('aria-busy', 'false');
                }
            });
    }

    /**
     * Resend verification code
     */
    function resend() {
        if (!canResend || busy) return;

        canResend = false;
        resendBtn.classList.add('disabled');
        resendBtn.textContent = 'Sending...';
        resendBtn.setAttribute('aria-disabled', 'true');
        announce('Resending verification code.');

        moduleAjax('send_otp', { phone: phone, survey_hash: config.surveyHash })
            .then(function(resp) {
                if (resp.success) {
                    showMsg('New code sent!', 'success');
                    codeInput.value = '';
                    codeInput.focus();
                    startTimer();
                    announce('New code sent. Please check your phone.');

                    var sec = 30;
                    resendBtn.textContent = 'Wait ' + sec + 's';
                    var iv = setInterval(function() {
                        sec--;
                        if (sec <= 0) {
                            clearInterval(iv);
                            canResend = true;
                            resendBtn.classList.remove('disabled');
                            resendBtn.textContent = 'Resend';
                            resendBtn.setAttribute('aria-disabled', 'false');
                        } else {
                            resendBtn.textContent = 'Wait ' + sec + 's';
                        }
                    }, 1000);
                } else {
                    showMsg(resp.error || 'Failed', 'error');
                    resetResend();
                    announce('Error: ' + (resp.error || 'Failed to resend code.'));
                }
            })
            .catch(function(e) {
                console.error('AJAX error:', e);
                showMsg('Network error', 'error');
                resetResend();
                announce('Network error. Please try again.');
            });
    }

    function resetResend() {
        canResend = true;
        resendBtn.classList.remove('disabled');
        resendBtn.textContent = 'Resend';
        resendBtn.setAttribute('aria-disabled', 'false');
    }

    /**
     * Return to phone number entry step
     */
    function goBack() {
        clearInterval(countdown);
        phone = '';
        codeInput.value = '';
        resetResend();
        if (timerSpan && timerSpan.parentElement) {
            timerSpan.parentElement.classList.remove('warning');
        }

        verifyStep.classList.remove('active');
        phoneStep.classList.add('active');
        hideMsg();
        phoneInput.focus();
        announce('Returned to phone number entry. Please enter your phone number.');
    }

    /**
     * Switch to code verification step
     */
    function showVerifyUI() {
        phoneStep.classList.remove('active');
        verifyStep.classList.add('active');

        phoneDisplay.textContent = phone.length >= 8
            ? phone.slice(0, 4) + ' **** ' + phone.slice(-4)
            : phone;

        if (timerSpan && timerSpan.parentElement) {
            timerSpan.parentElement.classList.remove('warning');
        }

        setTimeout(function() { codeInput.focus(); }, 100);
    }

    /**
     * Start the OTP expiration countdown
     */
    function startTimer() {
        clearInterval(countdown);

        var secs = (config.otpExpiration || 10) * 60;
        updateTimer(secs);

        countdown = setInterval(function() {
            secs--;
            if (secs <= 0) {
                clearInterval(countdown);
                timerSpan.textContent = 'Expired';
                if (timerSpan.parentElement) timerSpan.parentElement.classList.add('warning');
                showMsg('Code expired - request a new one', 'error');
                announce('Your verification code has expired. Please request a new one.');
            } else {
                updateTimer(secs);
                if (secs <= 60 && timerSpan.parentElement) {
                    timerSpan.parentElement.classList.add('warning');
                }
                if (secs === 60) {
                    announce('One minute remaining before code expires.');
                }
            }
        }, 1000);
    }

    function updateTimer(secs) {
        if (!timerSpan) return;
        var m = Math.floor(secs / 60);
        var s = secs % 60;
        timerSpan.textContent = m + ':' + (s < 10 ? '0' : '') + s;
    }

    /**
     * Send AJAX request to module endpoint
     */
    function moduleAjax(action, data) {
        var form = new FormData();
        form.append('action', action);

        if (config.csrfToken) {
            form.append('redcap_csrf_token', config.csrfToken);
        }

        // Pass survey page session info so AJAX handler can write to the correct session
        if (config.surveySessionId) {
            form.append('survey_session_id', config.surveySessionId);
        }
        if (config.sessionSeed) {
            form.append('session_seed', config.sessionSeed);
        }

        for (var k in data) {
            if (data.hasOwnProperty(k)) {
                form.append(k, data[k]);
            }
        }

        return fetch(config.verifyUrl, {
            method: 'POST',
            body: form,
            credentials: 'same-origin'
        })
        .then(function(resp) {
            if (!resp.ok) throw new Error('HTTP ' + resp.status);
            return resp.json();
        });
    }

    /**
     * Display status message
     */
    function showMsg(txt, type) {
        if (!msgBox) return;
        msgBox.textContent = txt;
        msgBox.className = 'message ' + type;
        msgBox.setAttribute('role', type === 'error' ? 'alert' : 'status');
    }

    /**
     * Clear status message
     */
    function hideMsg() {
        if (!msgBox) return;
        msgBox.className = 'message';
        msgBox.textContent = '';
        msgBox.removeAttribute('role');
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
