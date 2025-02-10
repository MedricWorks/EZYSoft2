document.addEventListener("DOMContentLoaded", function () {
    console.log("✅ DOM Loaded - Script is running!");  // Debugging Log

    const form = document.getElementById("registerForm");
    if (!form) return; // ✅ Exit if form does not exist (prevents errors on non-registration pages)

    const passwordInput = document.getElementById("Password");
    const confirmPasswordInput = document.getElementById("ConfirmPassword");
    const strengthBar = document.getElementById("strengthBar");
    const passwordRequirementsText = document.getElementById("passwordRequirementsText");
    const emailInput = document.getElementById("Email");
    const emailError = document.getElementById("emailError");
    const resumeInput = document.getElementById("Resume");
    const resumeError = document.getElementById("resumeError");

    const siteKey = document.getElementById("g-recaptcha-response") ? form.getAttribute("data-recaptcha-sitekey") : null;
    if (!siteKey) {
        console.warn("⚠️ reCAPTCHA site key is missing or not set.");
    }

    // ✅ Email Validation: Live Validation for Special Characters
    if (emailInput) {
        emailInput.addEventListener("input", function () {
            let email = emailInput.value;
            let emailPattern = /^[a-zA-Z0-9@.]+$/;
            emailError.textContent = emailPattern.test(email) ? "" : "Email can only contain letters, numbers, and '@'.";
        });
    }

    // ✅ Password Strength Meter + Missing Requirements Tracking
    if (passwordInput && strengthBar && passwordRequirementsText) {
        passwordInput.addEventListener("input", function () {
            const password = passwordInput.value;
            const strength = checkPasswordStrength(password);
            const remainingRequirements = getRemainingRequirements(password);

            let barColor = ["red", "red", "orange", "yellow", "green"][strength - 1] || "red";
            let barWidth = ["10%", "20%", "40%", "60%", "80%", "100%"][strength] || "10%";

            strengthBar.style.width = barWidth;
            strengthBar.style.backgroundColor = barColor;

            passwordRequirementsText.textContent =
                remainingRequirements.length > 0
                    ? "Missing: " + remainingRequirements.join(", ")
                    : "✅ All password requirements met!";
            passwordRequirementsText.classList.toggle("text-danger", remainingRequirements.length > 0);
            passwordRequirementsText.classList.toggle("text-success", remainingRequirements.length === 0);
        });
    }

    // ✅ Confirm Password Match
    if (passwordInput && confirmPasswordInput) {
        confirmPasswordInput.addEventListener("input", function () {
            confirmPasswordInput.setCustomValidity(
                passwordInput.value === confirmPasswordInput.value ? "" : "Passwords do not match."
            );
        });
    }

    // ✅ Resume File Validation
    if (resumeInput && resumeError) {
        resumeInput.addEventListener("change", function () {
            let file = resumeInput.value;
            let allowedExtensions = [".pdf", ".docx"];
            let fileExtension = file.substring(file.lastIndexOf('.')).toLowerCase();

            resumeError.textContent = file && !allowedExtensions.includes(fileExtension)
                ? "Only PDF and DOCX files are allowed."
                : "";
        });
    }

    // ✅ Prevent Form Submission If Errors Exist
    form.addEventListener("submit", function (event) {
        let emailErrorText = emailError.textContent.trim();
        let passwordWeak = passwordRequirementsText.classList.contains("text-danger");
        let resumeErrorText = resumeError.textContent.trim();

        let hasErrors = emailErrorText !== "" || passwordWeak || resumeErrorText !== "";

        console.log("📧 Email Error:", emailErrorText ? emailErrorText : "✅ No error");
        console.log("🔐 Password Weak?", passwordWeak ? "⚠️ Yes" : "✅ No");
        console.log("📄 Resume Error:", resumeErrorText ? resumeErrorText : "✅ No error");
        console.log("⚠️ hasErrors:", hasErrors);

        if (hasErrors) {
            event.preventDefault(); // Stop form submission if errors exist
            console.warn("⚠️ Form submission prevented due to validation errors.");
            return;
        }

        console.log("✅ No errors detected. Proceeding to submission...");

        if (siteKey) {
            console.log("🔹 reCAPTCHA is enabled. Triggering token request...");

            event.preventDefault(); // Prevent immediate form submission to handle reCAPTCHA

            grecaptcha.ready(function () {
                console.log("🔹 reCAPTCHA ready. Requesting token...");

                grecaptcha.execute(siteKey, { action: "register" })
                    .then(function (token) {
                        console.log("✅ reCAPTCHA token received:", token);
                        document.getElementById("g-recaptcha-response").value = token;

                        console.log("🔹 Submitting form now...");
                        form.submit();  // 🔥 Force form submission after reCAPTCHA validation
                    })
                    .catch(function (error) {
                        console.error("❌ reCAPTCHA error:", error);
                    });
            });

        } else {
            console.log("⚠️ No reCAPTCHA site key detected. Submitting form normally.");
            form.submit();  // 🔥 If no reCAPTCHA, submit form immediately
        }
    });

    // ✅ Function to check password strength
    function checkPasswordStrength(password) {
        return [
            password.length >= 12,
            /[A-Z]/.test(password),
            /[a-z]/.test(password),
            /\d/.test(password),
            /[@$!%*?&]/.test(password)
        ].reduce((score, criteria) => score + (criteria ? 1 : 0), 0);
    }

    // ✅ Function to return the list of missing password requirements
    function getRemainingRequirements(password) {
        return [
            password.length < 12 ? "At least 12 characters" : null,
            !/[A-Z]/.test(password) ? "One uppercase letter" : null,
            !/[a-z]/.test(password) ? "One lowercase letter" : null,
            !/\d/.test(password) ? "One number" : null,
            !/[@$!%*?&]/.test(password) ? "One special character" : null
        ].filter(Boolean);
    }
});
