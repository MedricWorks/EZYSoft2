using EZYSoft2.Models;
using EZYSoft2.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using EZYSoft2.Helpers;
using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using reCAPTCHA.AspNetCore;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Identity.UI.Services; // ✅ Use correct IEmailSender interface
using System.Text.Encodings.Web;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.AspNetCore.Authorization;

namespace EZYSoft2.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly ApplicationDbContext _dbContext;
        private readonly ILogger<AccountController> _logger;
        private readonly ReCaptchaSettings _reCaptchaSettings;
        private readonly IEmailSender _emailSender; // ✅ No need for custom interface
        private readonly UrlEncoder _urlEncoder;
        private readonly SessionHelper _sessionHelper;

        public AccountController(
            UserManager<User> userManager,
            SignInManager<User> signInManager,
            ApplicationDbContext dbContext,
            ILogger<AccountController> logger,
            IOptions<ReCaptchaSettings> reCaptchaSettings,
            IOptions<EmailSettings> emailSettings,
            IEmailSender emailSender,
            UrlEncoder urlEncoder,
            SessionHelper sessionHelper) // ✅ Inject Email Service

        {
            _userManager = userManager;
            _signInManager = signInManager;
            _dbContext = dbContext;
            _logger = logger;
            _reCaptchaSettings = reCaptchaSettings.Value;
            _emailSender = emailSender; // ✅ No need for ILogger<EmailSender>
            _urlEncoder = urlEncoder;
            _sessionHelper = sessionHelper;
        }

        // 🔹 Helper method to log user actions into AuditLog table
        private async Task LogAction(string userId, string action)
        {
            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("⚠️ Attempted to log an action without a valid user ID.");
                return;
            }

            var log = new AuditLog
            {
                UserId = userId,
                Action = action,
                Timestamp = DateTime.UtcNow,
                IPAddress = Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
            };

            _dbContext.AuditLogs.Add(log);
            await _dbContext.SaveChangesAsync();
        }

        [HttpGet]
        public IActionResult Register()
        {
            if (string.IsNullOrEmpty(_reCaptchaSettings.SiteKey))
            {
                _logger.LogError("⚠️ reCAPTCHA Site Key is missing from appsettings.json!");
            }
            else
            {
                _logger.LogInformation($"🔹 reCAPTCHA Site Key Loaded: {_reCaptchaSettings.SiteKey}");
            }
            ViewData["RecaptchaSiteKey"] = _reCaptchaSettings.SiteKey;
            ViewBag.ReCaptchaSiteKey = _reCaptchaSettings.SiteKey; // Ensure Site Key is passed
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    _logger.LogWarning("Registration failed: Invalid model state.");
                    foreach (var state in ModelState)
                    {
                        foreach (var error in state.Value.Errors)
                        {
                            _logger.LogWarning($"Validation error in {state.Key}: {error.ErrorMessage}");
                        }
                    }
                    return View(model);
                }
                if (model.DateOfBirth >= DateTime.UtcNow.Date)
                {
                    ModelState.AddModelError(nameof(model.DateOfBirth), "Date of Birth cannot be today or in the future.");
                    return View(model);
                }
                // 🔹 Sanitize input before saving
                model.FirstName = SanitizationHelper.SanitizeInput(model.FirstName);
                model.LastName = SanitizationHelper.SanitizeInput(model.LastName);
                model.Email = SanitizationHelper.SanitizeInput(model.Email);
                model.NRIC = SanitizationHelper.SanitizeInput(model.NRIC);
                model.WhoAmI = SanitizationHelper.SanitizeInput(model.WhoAmI);

                _logger.LogInformation($"🔍 Received reCAPTCHA Token: {model.RecaptchaToken ?? "None"}");
                if (model.DateOfBirth == null)
                {
                    _logger.LogWarning("Registration failed: Date of Birth is invalid.");
                    return View(model);
                }
                if (!System.Text.RegularExpressions.Regex.IsMatch(model.NRIC, @"^[a-zA-Z0-9]+$"))
                {
                    ModelState.AddModelError(nameof(model.NRIC), "NRIC must only contain letters and numbers.");
                    return View(model);
                }

                // 🔹 reCAPTCHA Validation
                bool captchaValid = await VerifyReCaptcha(model.RecaptchaToken);
                if (!captchaValid)
                {
                    ModelState.AddModelError("RecaptchaToken", "reCAPTCHA verification failed. Please try again.");
                    _logger.LogWarning("🚨 reCAPTCHA verification failed.");
                    return View(model);
                }

                // 🔹 Email Format Validation
                if (!System.Text.RegularExpressions.Regex.IsMatch(model.Email, @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"))
                {
                    ModelState.AddModelError(nameof(model.Email), "Invalid email format. Please enter a valid email.");
                    return View(model);
                }

                // 🔹 Check for existing email
                var existingUser = await _userManager.FindByEmailAsync(model.Email);
                if (existingUser != null)
                {
                    ModelState.AddModelError(nameof(model.Email), "This email is already registered.");
                    return View(model);
                }

                // 🔹 Encrypt NRIC
                string encryptedNRIC = EncryptionHelper.EncryptData(model.NRIC);

                // 🔹 Save resume file
                var filePath = await SaveResumeFile(model.Resume);
                var sessionToken = Guid.NewGuid().ToString();

                var user = new User
                {
                    UserName = model.Email,
                    Email = model.Email,
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    Gender = model.Gender,
                    DateOfBirth = model.DateOfBirth,
                    NRIC = encryptedNRIC,
                    WhoAmI = model.WhoAmI,
                    ResumePath = filePath,
                    SessionToken = sessionToken,
                    LastPasswordChange = DateTime.UtcNow // ✅ Track password creation date
                };

                // ✅ Hash the initial password
                var hashedPassword = _userManager.PasswordHasher.HashPassword(user, model.Password);
                user.PreviousPasswords = JsonConvert.SerializeObject(new List<string> { hashedPassword });

                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    Response.Cookies.Append("SessionToken", sessionToken, new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = true,
                        Expires = DateTime.UtcNow.AddMinutes(30)
                    });

                    await _signInManager.SignInAsync(user, isPersistent: false);
                    await LogAction(user.Id, "User Registered");
                    return RedirectToAction("Index", "Home");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                    _logger.LogWarning($"Registration error: {error.Description}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"🚨 Unexpected Error During Registration: {ex.Message}");
                return RedirectToAction("Error", "Home");
            }

            return View(model);
        }


        private async Task<bool> VerifyReCaptcha(string gRecaptchaResponse)
        {
            using var client = new HttpClient();
            var response = await client.GetStringAsync(
                $"https://www.google.com/recaptcha/api/siteverify?secret={_reCaptchaSettings.SecretKey}&response={gRecaptchaResponse}");
            _logger.LogInformation($"🔍 Google reCAPTCHA Response: {response}"); // Log Google’s response

            var captchaResult = JsonConvert.DeserializeObject<ReCaptchaVerificationResponse>(response);

            if (!captchaResult.Success || captchaResult.Score < 0.5)
            {
                _logger.LogWarning($"reCAPTCHA failed: Score = {captchaResult.Score}");
                return false;
            }

            return true;
        }
        private async Task<string> SaveResumeFile(IFormFile resume)
        {
            if (resume == null || resume.Length == 0)
            {
                _logger.LogWarning("Resume upload failed: No file provided.");
                return null;
            }

            var allowedExtensions = new[] { ".pdf", ".docx" };
            var extension = Path.GetExtension(resume.FileName).ToLower();

            if (!allowedExtensions.Contains(extension))
            {
                ModelState.AddModelError("Resume", "Invalid file type. Only PDF and DOCX files are allowed.");
                _logger.LogWarning($"Invalid resume file type: {extension}");
                return null;
            }

            var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "uploads");
            if (!Directory.Exists(uploadsFolder))
            {
                Directory.CreateDirectory(uploadsFolder);
            }

            var filePath = Path.Combine(uploadsFolder, Guid.NewGuid().ToString() + extension);
            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await resume.CopyToAsync(stream);
            }

            _logger.LogInformation($"Resume uploaded successfully: {filePath}");
            return filePath;
        }

        [HttpGet]
        public IActionResult Login()
        {
            _logger.LogInformation("User accessed the Login page.");
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string overrideSession = "false")
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError("", "Invalid email or password.");
                return View(model);
            }

            // ✅ Verify password before deciding if it's expired
            var passwordCheck = await _signInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: true);
            if (!passwordCheck.Succeeded)
            {
                if (passwordCheck.IsLockedOut)
                {
                    ModelState.AddModelError("", "This account is locked. Try again later.");
                }
                else
                {
                    int failedAttempts = await _userManager.GetAccessFailedCountAsync(user);
                    ModelState.AddModelError("", $"Invalid email or password. Attempts left: {3 - failedAttempts}");

                    _logger.LogWarning($"Failed login attempt {failedAttempts}/3 for {user.Email}");
                }
                return View(model);
            }

            // ✅ Check if Password Has Expired (AFTER verifying password is correct)
            bool passwordExpired = user.LastPasswordChange == null || DateTime.UtcNow > user.LastPasswordChange.AddDays(30);
            if (passwordExpired)
            {
                _logger.LogWarning($"🔹 Password expired for user {user.Email}. Redirecting to Change Password.");

                // ✅ Store Expired User Email so ChangePassword knows who they are
                HttpContext.Session.SetString("PasswordExpired", "true");
                HttpContext.Session.SetString("ExpiredUserEmail", user.Email);

                return RedirectToAction("ChangePassword");
            }

            // ✅ Proceed with normal login
            var result = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, lockoutOnFailure: true);
            if (result.Succeeded)
            {
                await _userManager.ResetAccessFailedCountAsync(user);
                string newSessionToken = Guid.NewGuid().ToString();
                user.SessionToken = newSessionToken;
                await _userManager.UpdateAsync(user);

                Response.Cookies.Append("SessionToken", newSessionToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    Expires = DateTime.UtcNow.AddMinutes(30)
                });

                if (await _userManager.GetTwoFactorEnabledAsync(user))
                {
                    HttpContext.Session.SetString("2FA_UserId", user.Id);
                    return RedirectToAction("VerifyTwoFactorAuth");
                }
                await LogAction(user.Id, "Login Success");
                HttpContext.Session.Remove("PasswordExpired"); // ✅ Clear the flag after password reset
                return RedirectToAction("Index", "Home");
            }
            else if (result.RequiresTwoFactor)
            {
                HttpContext.Session.SetString("2FA_UserId", user.Id);
                return RedirectToAction("VerifyTwoFactorAuth");
            }
            else if (result.IsLockedOut)
            {
                await LogAction(user.Id, "Account Locked Out");
                ModelState.AddModelError("", "This account is locked. Try again later.");
            }
            else
            {
                int failedAttempts = await _userManager.GetAccessFailedCountAsync(user);
                ModelState.AddModelError("", $"Invalid email or password. Attempts left: {3 - failedAttempts}");
                _logger.LogWarning($"Failed login attempt {failedAttempts}/3 for {user.Email}");
                await LogAction(user.Id, $"{failedAttempts} failed login attempt");
            }

            return View(model);
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var user = await _sessionHelper.GetValidatedUser(this);
            if (user != null)
            {
                await LogAction(user.Id, "Logged Out");
                _logger.LogInformation($"User {user.Email} logged out.");

                // 🔹 Get the session token stored in cookies
                Request.Cookies.TryGetValue("SessionToken", out string currentSessionToken);

                // ✅ Only invalidate the session if the token matches the one stored in the DB
                if (!string.IsNullOrEmpty(user.SessionToken) && user.SessionToken == currentSessionToken)
                {
                    user.SessionToken = null; // ✅ Invalidate session only if it matches the current browser
                    await _userManager.UpdateAsync(user);
                }
            }

            await _signInManager.SignOutAsync();
            Response.Cookies.Delete("SessionToken");

            return RedirectToAction("Login", "Account");
        }
        public class ReCaptchaVerificationResponse
        {
            [JsonProperty("success")]
            public bool Success { get; set; }

            [JsonProperty("score")]
            public float Score { get; set; }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            bool isExpiredPassword = HttpContext.Session.GetString("PasswordExpired") == "true";
            var user = await _sessionHelper.GetValidatedUser(this);
            bool isAuthenticated = user != null;

            if (!isAuthenticated)
            {
                if (!isExpiredPassword)
                {
                    _logger.LogWarning($"🔴 SessionHelper failed to retrieve a valid user. Redirecting to Login.");
                    return RedirectToAction("Login");
                }

                // 🔹 Retrieve Expired User from Session
                string expiredUserEmail = HttpContext.Session.GetString("ExpiredUserEmail");
                if (string.IsNullOrEmpty(expiredUserEmail))
                {
                    ModelState.AddModelError("", "Invalid request. Please log in again.");
                    return RedirectToAction("Login");
                }

                user = await _userManager.FindByEmailAsync(expiredUserEmail);
                if (user == null)
                {
                    ModelState.AddModelError("", "Invalid user.");
                    return View(model);
                }
            }

            if (isExpiredPassword)
            {
                _logger.LogInformation($"🔹 Expired password reset initiated for user {user.Email}");

                // ✅ Prevent Password Reuse
                var previousPasswords = JsonConvert.DeserializeObject<List<string>>(user.PreviousPasswords ?? "[]");
                foreach (var oldPassword in previousPasswords)
                {
                    if (_userManager.PasswordHasher.VerifyHashedPassword(user, oldPassword, model.NewPassword) == PasswordVerificationResult.Success)
                    {
                        ModelState.AddModelError("NewPassword", "You cannot reuse your last 2 passwords.");
                        await LogAction(user.Id, "Failed Change Password (Reused Password)");
                        return View(model);
                    }
                }

                // ✅ Reset Password
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var resetResult = await _userManager.ResetPasswordAsync(user, token, model.NewPassword);

                if (!resetResult.Succeeded)
                {
                    foreach (var error in resetResult.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    await LogAction(user.Id, "Failed Change Password (Reset Error)");
                    return View(model);
                }

                user.LastPasswordChange = DateTime.UtcNow;
                previousPasswords.Insert(0, _userManager.PasswordHasher.HashPassword(user, model.NewPassword));
                if (previousPasswords.Count > 2) previousPasswords.RemoveAt(2);
                user.PreviousPasswords = JsonConvert.SerializeObject(previousPasswords);
                await _userManager.UpdateAsync(user);

                HttpContext.Session.Remove("PasswordExpired");
                HttpContext.Session.Remove("ExpiredUserEmail");
                await LogAction(user.Id, "Changed Password Successful for Expired Password");
                _logger.LogInformation($"✅ Expired password successfully reset for user {user.Email}");
                return RedirectToAction("Login");
            }

            // ✅ Normal Change Password Flow
            if (user.LastPasswordChange != null && DateTime.UtcNow < user.LastPasswordChange.AddMinutes(5))
            {
                ModelState.AddModelError("NewPassword", "You cannot change your password so soon. Try again later.");
                await LogAction(user.Id, "Failed Change Password (Too Soon)");
                return View(model);
            }

            var prevPasswords = JsonConvert.DeserializeObject<List<string>>(user.PreviousPasswords ?? "[]");
            foreach (var oldPassword in prevPasswords)
            {
                if (_userManager.PasswordHasher.VerifyHashedPassword(user, oldPassword, model.NewPassword) == PasswordVerificationResult.Success)
                {
                    ModelState.AddModelError("NewPassword", "You cannot reuse your last 2 passwords.");
                    await LogAction(user.Id, "Failed Change Password (Reused Password)");
                    return View(model);
                }
            }

            var changeResult = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (!changeResult.Succeeded)
            {
                if (changeResult.Errors.Any(e => e.Code == "PasswordMismatch"))
                {
                    ModelState.AddModelError("OldPassword", "The old password you entered is incorrect.");
                    await LogAction(user.Id, "Failed Change Password (Incorrect Old Password)");
                }
                else
                {
                    foreach (var error in changeResult.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    await LogAction(user.Id, "Failed Change Password (General Error)");

                }
                return View(model);
            }

            user.LastPasswordChange = DateTime.UtcNow;
            prevPasswords.Insert(0, _userManager.PasswordHasher.HashPassword(user, model.NewPassword));
            if (prevPasswords.Count > 2) prevPasswords.RemoveAt(2);
            user.PreviousPasswords = JsonConvert.SerializeObject(prevPasswords);
            await _userManager.UpdateAsync(user);

            await _signInManager.RefreshSignInAsync(user);
            await LogAction(user.Id, "Changed Password");

            _logger.LogInformation($"✅ Password successfully changed for user {user.Email}");

            return RedirectToAction("Index", "Home");
        }


        [HttpGet]
        public async Task<IActionResult> ChangePassword()
        {
            // 🔹 Check if the password expired flag is set
            if (HttpContext.Session.GetString("PasswordExpired") == "true")
            {
                return View(); // ✅ Allow access only if redirected due to password expiration
            }

            // 🔹 Otherwise, enforce standard authentication
            var user = await _sessionHelper.GetValidatedUser(this);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            return View();
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            await LogAction(model.Email, "Forgot Password Requested");

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return View("ForgotPasswordConfirmation");
            }

            // Check password change restrictions
            if (user.LastPasswordChange != null)
            {
                if (DateTime.UtcNow < user.LastPasswordChange.AddMinutes(5))
                {
                    ModelState.AddModelError("Email", "You cannot reset your password so soon after the last change. Try again later.");
                    return View(model);
                }

                if (DateTime.UtcNow > user.LastPasswordChange.AddDays(30))
                {
                    ModelState.AddModelError("Email", "Your password has expired. You must reset it now.");
                }
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = Url.Action("ResetPassword", "Account", new { token, email = user.Email }, Request.Scheme);

            // ✅ Use _emailSender to send reset link
            await _emailSender.SendEmailAsync(user.Email, "Password Reset",
                $"Click <a href='{resetLink}'>here</a> to reset your password.");

            return View("ForgotPasswordConfirmation");
        }

        [HttpGet]
        public IActionResult ResetPassword(string token, string email)
        {
            if (token == null || email == null)
            {
                return RedirectToAction("Login");
            }

            return View(new ResetPasswordViewModel { Token = token, Email = email });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("🚨 Reset password failed: Model state invalid.");
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                _logger.LogWarning($"🚨 Reset password failed: User {model.Email} not found.");
                return RedirectToAction("Login"); // Do NOT reveal user existence
            }

            // 🔹 Attempt to reset the password with the token
            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);

            if (result.Succeeded)
            {
                await LogAction(user.Id, "Reset Password Success");
                _logger.LogInformation($"✅ Password reset successful for {user.Email}");
                return RedirectToAction("Login");
            }

            // 🔹 Detect if token is invalid or expired
            bool isTokenExpired = result.Errors.Any(e => e.Code == "InvalidToken");
            if (isTokenExpired)
            {
                await LogAction(user.Id, "Password Reset Failed: Expired Token");
                _logger.LogWarning("🚨 Reset password failed: Token expired or invalid.");
                ModelState.AddModelError("", "The password reset link has expired or is invalid. Please request a new one.");
                return View(model);
            }

            // 🔹 Handle other errors (e.g., password policy violations)
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
                _logger.LogWarning($"🚨 Password reset error: {error.Description}");
            }

            return View(model);
        }


        [Authorize]
        [HttpGet]
        public async Task<IActionResult> EnableTwoFactorAuth()
        {
        var user = await _sessionHelper.GetValidatedUser(this);
            if (user == null) return NotFound("User not found.");

            var key = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(key))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                key = await _userManager.GetAuthenticatorKeyAsync(user);
            }
            await LogAction(user.Id, "Enabled 2FA");
            string authenticatorUri = GenerateQrCodeUrl(user.Email, key);
            Console.WriteLine($"Generated QR Code URL: {authenticatorUri}");
            user.TwoFactorEnabled = true;
            await _userManager.UpdateAsync(user); // 🔹 Save the changes
            var model = new EnableTwoFactorAuthViewModel
            {
                SharedKey = key,
                AuthenticatorUri = authenticatorUri
            };

            return View(model);
        }


        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DisableTwoFactorAuth()
        {
        var user = await _sessionHelper.GetValidatedUser(this);
            if (user == null)
            {
                return RedirectToAction("Login");
            }
            await LogAction(user.Id, "Disabled 2FA");
            await _userManager.SetTwoFactorEnabledAsync(user, false);
            return RedirectToAction("Manage", "Account");
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ConfirmEnableTwoFactorAuth(string code)
        {
        var user = await _sessionHelper.GetValidatedUser(this);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, "Authenticator", code);

            if (!isValid)
            {
                ModelState.AddModelError("", "Invalid authentication code.");
                return View("EnableTwoFactorAuth");
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            return RedirectToAction("Manage", "Account");
        }
        private string GenerateQrCodeUrl(string email, string key)
        {
            string appName = "EZYSoft";
            string issuer = "EZYSoft";
            return $"otpauth://totp/{appName}:{email}?secret={key}&issuer={issuer}&algorithm=SHA1&digits=6&period=30";
        }
        [HttpGet]
        public IActionResult VerifyTwoFactorAuth()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyTwoFactorAuth(string code)
        {
            var userId = HttpContext.Session.GetString("2FA_UserId");
            if (userId == null)
            {
                return RedirectToAction("Login");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(code, isPersistent: false, rememberClient: false);

            if (result.Succeeded)
            {
                HttpContext.Session.Remove("2FA_UserId");

                // 🔹 Generate new session token on 2FA success
                string newSessionToken = Guid.NewGuid().ToString();
                user.SessionToken = newSessionToken;
                await _userManager.UpdateAsync(user);

                Response.Cookies.Append("SessionToken", newSessionToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    Expires = DateTime.UtcNow.AddMinutes(30)
                });
                await LogAction(user.Id, "Successful 2FA Attempt");

                _logger.LogInformation($"✅ 2FA successful for {user.Email}, session token updated.");

                return RedirectToAction("Index", "Home");
            }
            else
            {
                await LogAction(user.Id, "Failed 2FA Attempt");

                ModelState.AddModelError(string.Empty, "Invalid authentication code. Please try again.");
                return View();
            }
        }

        [Authorize]
        [HttpGet]
        public async Task<IActionResult> Manage()
        {
        var user = await _sessionHelper.GetValidatedUser(this);
            if (user == null)
            {
                return RedirectToAction("Login");
            }
            await LogAction(user.Id, "Accessed Manage Page");

            ViewBag.TwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            return View();
        }   
    }
}
