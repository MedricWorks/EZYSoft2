document.addEventListener("DOMContentLoaded", function () {
    const passwordInput = document.getElementById("Password");
    const strengthBar = document.getElementById("strengthBar");
    const passwordRequirementsText = document.getElementById("passwordRequirementsText");

    // Live password validation and requirement tracking
    passwordInput.addEventListener("input", function () {
        const password = passwordInput.value;
        const strength = checkPasswordStrength(password);
        const remainingRequirements = getRemainingRequirements(password);

        let barColor = "red";
        let barWidth = "10%";

        if (strength >= 5) {
            barColor = "green";
            barWidth = "100%";
        } else if (strength === 4) {
            barColor = "yellow";
            barWidth = "80%";
        } else if (strength === 3) {
            barColor = "orange";
            barWidth = "60%";
        } else if (strength === 2) {
            barColor = "red";
            barWidth = "40%";
        } else {
            barColor = "red";
            barWidth = "20%";
        }

        strengthBar.style.width = barWidth;
        strengthBar.style.backgroundColor = barColor;

        // Update the password requirements dynamically
        if (remainingRequirements.length > 0) {
            passwordRequirementsText.textContent = "Missing: " + remainingRequirements.join(", ");
            passwordRequirementsText.classList.remove("text-success");
            passwordRequirementsText.classList.add("text-danger");
        } else {
            passwordRequirementsText.textContent = "✅ All password requirements met!";
            passwordRequirementsText.classList.remove("text-danger");
            passwordRequirementsText.classList.add("text-success");
        }
    });

    // Function to check password strength
    function checkPasswordStrength(password) {
        let strength = 0;
        if (password.length >= 12) strength++;
        if (/[A-Z]/.test(password)) strength++; // Has uppercase
        if (/[a-z]/.test(password)) strength++; // Has lowercase
        if (/\d/.test(password)) strength++; // Has number
        if (/[@$!%*?&]/.test(password)) strength++; // Has special character
        return strength;
    }

    // Function to return the list of missing password requirements
    function getRemainingRequirements(password) {
        let remaining = [];
        if (password.length < 12) remaining.push("At least 12 characters");
        if (!/[A-Z]/.test(password)) remaining.push("One uppercase letter");
        if (!/[a-z]/.test(password)) remaining.push("One lowercase letter");
        if (!/\d/.test(password)) remaining.push("One number");
        if (!/[@$!%*?&]/.test(password)) remaining.push("One special character");
        return remaining;
    }
});
