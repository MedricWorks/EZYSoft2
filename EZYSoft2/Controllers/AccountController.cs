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


        public AccountController(
            UserManager<User> userManager,
            SignInManager<User> signInManager,
            ApplicationDbContext dbContext,
            ILogger<AccountController> logger,
            IOptions<ReCaptchaSettings> reCaptchaSettings,
            IOptions<EmailSettings> emailSettings,
            IEmailSender emailSender,
            UrlEncoder urlEncoder) // ✅ Inject Email Service

        {
            _userManager = userManager;
            _signInManager = signInManager;
            _dbContext = dbContext;
            _logger = logger;
            _reCaptchaSettings = reCaptchaSettings.Value;
            _emailSender = emailSender; // ✅ No need for ILogger<EmailSender>
            _urlEncoder = urlEncoder;
        }

        // 🔹 Helper method to log user actions into AuditLog table
        private async Task LogAction(string userId, string action)
        {
            var log = new AuditLog
            {
                UserId = userId,
                Action = action,
                Timestamp = DateTime.UtcNow,
                IPAddress = Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
            };

            _dbContext.AuditLogs.Add(log);
            await _dbContext.SaveChangesAsync();
            _logger.LogInformation($"Audit Log: {action} by {userId}");
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
                    _logger.LogWarning($"Registration failed: Invalid email format {model.Email}.");
                    return View(model);
                }

                // 🔹 Check for existing email
                var existingUser = await _userManager.FindByEmailAsync(model.Email);
                if (existingUser != null)
                {
                    ModelState.AddModelError(nameof(model.Email), "This email is already registered.");
                    _logger.LogWarning($"Registration failed: Email {model.Email} is already registered.");
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
                    _logger.LogInformation($"User {user.Email} successfully registered.");
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

            // ✅ Check if Password Has Expired (Redirect to Change Password)
            if (user.LastPasswordChange != null && DateTime.UtcNow > user.LastPasswordChange.AddDays(30))
            {
                ModelState.AddModelError("", "Your password has expired. Please reset your password.");
                return RedirectToAction("ChangePassword");
            }

            // 🔹 Generate a new session token
            string newSessionToken = Guid.NewGuid().ToString();

            // 🔹 Retrieve the session token from the user's cookies
            Request.Cookies.TryGetValue("SessionToken", out string existingSessionToken);

            // ✅ Check if another session is already active
            if (!string.IsNullOrEmpty(user.SessionToken) && user.SessionToken != existingSessionToken)
            {
                if (overrideSession != "true") // 🔹 Prompt user if they haven't confirmed override
                {
                    ViewBag.ShowSessionOverridePrompt = true;
                    return View(model);
                }

                user.SessionToken = null;
                await _userManager.UpdateAsync(user);
                await _signInManager.SignOutAsync();

                // ✅ FORCE LOGOUT OLD SESSION BY INVALIDATING ITS COOKIE
                Response.Cookies.Delete("SessionToken");

                await Task.Delay(500); // ✅ Small delay to ensure session invalidation is applied
            }

            // ✅ Enforce failed login attempt limit (Max 3 attempts)
            var result = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                // ✅ Reset failed login attempts on success
                await _userManager.ResetAccessFailedCountAsync(user);

                // ✅ Set session token only after successful login
                user.SessionToken = newSessionToken;
                await _userManager.UpdateAsync(user);

                // ✅ Store session token in a secure cookie
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

                return RedirectToAction("Index", "Home");
            }
            else if (result.RequiresTwoFactor)
            {
                HttpContext.Session.SetString("2FA_UserId", user.Id);
                return RedirectToAction("VerifyTwoFactorAuth");
            }
            else if (result.IsLockedOut)
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


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
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

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            // ✅ Enforce Minimum Password Age
            if (user.LastPasswordChange != null && DateTime.UtcNow < user.LastPasswordChange.AddMinutes(5))
            {
                ModelState.AddModelError("NewPassword", "You cannot change your password so soon. Try again later.");
                return View(model);
            }

            // ✅ Enforce Maximum Password Age
            if (user.LastPasswordChange != null && DateTime.UtcNow > user.LastPasswordChange.AddDays(30))
            {
                ModelState.AddModelError("OldPassword", "Your password has expired. Please set a new password.");
            }

            // ✅ Retrieve and Deserialize Previous Passwords
            var previousPasswords = JsonConvert.DeserializeObject<List<string>>(user.PreviousPasswords ?? "[]");

            // ✅ Debugging Log (Check if previous passwords are correctly stored)
            _logger.LogInformation($"User {user.Email} is attempting to change password. Stored previous passwords: {user.PreviousPasswords}");

            // ✅ Verify that the new password is NOT the same as the last 2 passwords
            foreach (var oldPassword in previousPasswords)
            {
                if (_userManager.PasswordHasher.VerifyHashedPassword(user, oldPassword, model.NewPassword) == PasswordVerificationResult.Success)
                {
                    ModelState.AddModelError("NewPassword", "You cannot reuse your last 2 passwords.");
                    return View(model);
                }
            }

            // ✅ Change Password
            var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (!result.Succeeded)
            {
                // ✅ NEW: Check for incorrect old password and provide feedback
                if (result.Errors.Any(e => e.Code == "PasswordMismatch"))
                {
                    ModelState.AddModelError("OldPassword", "The old password you entered is incorrect.");
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                }
                return View(model);
            }

            // ✅ Update Last Password Change Timestamp
            user.LastPasswordChange = DateTime.UtcNow;

            // ✅ Store New Password in History (Keep Last 2 Passwords)
            previousPasswords.Insert(0, _userManager.PasswordHasher.HashPassword(user, model.NewPassword));
            if (previousPasswords.Count > 2) previousPasswords.RemoveAt(2); // Keep only last 2

            user.PreviousPasswords = JsonConvert.SerializeObject(previousPasswords);
            await _userManager.UpdateAsync(user);

            await _signInManager.SignInAsync(user, isPersistent: false);
            return RedirectToAction("Index", "Home");
        }




        [HttpGet]
        public IActionResult ChangePassword()
        {
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

            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
            if (result.Succeeded)
            {
                _logger.LogInformation($"✅ Password reset successful for {user.Email}");
                return RedirectToAction("Login");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
                _logger.LogWarning($"🚨 Password reset error: {error.Description}");
            }

            return View(model);
        }
        [HttpGet]
        public async Task<IActionResult> EnableTwoFactorAuth()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return NotFound("User not found.");

            var key = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(key))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                key = await _userManager.GetAuthenticatorKeyAsync(user);
            }

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


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DisableTwoFactorAuth()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            await _userManager.SetTwoFactorEnabledAsync(user, false);
            return RedirectToAction("Manage", "Account");
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ConfirmEnableTwoFactorAuth(string code)
        {
            var user = await _userManager.GetUserAsync(User);
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
                HttpContext.Session.Remove("2FA_UserId"); // ✅ Clear session after successful login
                return RedirectToAction("Index", "Home");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid authentication code. Please try again.");
                return View();
            }
        }
        [HttpGet]
        public async Task<IActionResult> Manage()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            ViewBag.TwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            return View();
        }   
    }
}
