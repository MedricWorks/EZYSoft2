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

namespace EZYSoft2.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly ApplicationDbContext _dbContext;
        private readonly ILogger<AccountController> _logger;
        private readonly ReCaptchaSettings _reCaptchaSettings;

        public AccountController(
            UserManager<User> userManager,
            SignInManager<User> signInManager,
            ApplicationDbContext dbContext,
            ILogger<AccountController> logger,
            IOptions<ReCaptchaSettings> reCaptchaSettings)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _dbContext = dbContext;
            _logger = logger;
            _reCaptchaSettings = reCaptchaSettings.Value;

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
            _logger.LogInformation($"🔍 Received reCAPTCHA Token: {model.RecaptchaToken ?? "None"}");
            // 🔹 Use existing VerifyReCaptcha() function instead of repeating the logic
            bool captchaValid = await VerifyReCaptcha(model.RecaptchaToken);
            if (!captchaValid)
            {
                ModelState.AddModelError("RecaptchaToken", "reCAPTCHA verification failed. Please try again.");
                _logger.LogWarning("🚨 reCAPTCHA verification failed.");
                return View(model);
            }

            // 🔹 Check for duplicate email before continuing registration
            var existingUser = await _userManager.FindByEmailAsync(model.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError("Email", "This email is already registered.");
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
                NRIC = encryptedNRIC, // Store encrypted NRIC
                WhoAmI = model.WhoAmI,
                ResumePath = filePath,
                SessionToken = sessionToken // ✅ Store session token in DB

            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {

                Response.Cookies.Append("SessionToken", sessionToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    Expires = DateTime.UtcNow.AddMinutes(30) // Adjust as needed
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
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Login failed: Invalid model state.");
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError("", "Invalid email or password.");
                _logger.LogWarning($"Login failed: User {model.Email} not found.");
                return View(model);
            }

            var newSessionToken = Guid.NewGuid().ToString();
            var result = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                user.SessionToken = newSessionToken;
                await _userManager.UpdateAsync(user);

                Response.Cookies.Append("SessionToken", newSessionToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    Expires = DateTime.UtcNow.AddMinutes(30)
                });

                await LogAction(user.Id, "Login Successful");
                _logger.LogInformation($"User {user.Email} logged in successfully.");
                return RedirectToAction("Index", "Home");
            }
            else if (result.IsLockedOut)
            {
                await LogAction(user.Id, "Account Locked");
                ModelState.AddModelError("", "This account has been locked due to multiple failed login attempts.");
                _logger.LogWarning($"User {user.Email} account locked due to failed attempts.");
            }
            else
            {
                await LogAction(user.Id, "Failed Login Attempt");
                ModelState.AddModelError("", "Invalid email or password.");
                _logger.LogWarning($"Invalid login attempt for user {user.Email}.");
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
                user.SessionToken = null;
                await _userManager.UpdateAsync(user);
                await LogAction(user.Id, "Logout");
                _logger.LogInformation($"User {user.Email} logged out.");
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
    }
}
