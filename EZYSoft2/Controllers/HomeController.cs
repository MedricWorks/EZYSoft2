using EZYSoft2.Helpers;
using EZYSoft2.Models;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Threading.Tasks;

namespace EZYSoft2.Controllers
{
    public class HomeController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly ILogger<HomeController> _logger;

        public HomeController(UserManager<User> userManager, SignInManager<User> signInManager, ILogger<HomeController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        public async Task<IActionResult> Index()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                _logger.LogInformation($"User {user.Email} accessed the home page.");

                // 🔹 Get stored session token from the browser cookies
                Request.Cookies.TryGetValue("SessionToken", out string storedSessionToken);

                // ✅ Ensure session token is still valid (DO NOT create a new one automatically)
                if (string.IsNullOrEmpty(user.SessionToken))
                {
                    _logger.LogWarning($"❌ Session token missing for {user.Email}. Logging out.");
                    await _signInManager.SignOutAsync();
                    Response.Cookies.Delete("SessionToken");
                    return RedirectToAction("Login", "Account");
                }
                else if (user.SessionToken != storedSessionToken)
                {
                    _logger.LogWarning($"Session token mismatch detected for {user.Email}. Checking recent login.");

                    // ✅ Allow login if the user recently completed 2FA (Token just got updated)
                    if (HttpContext.Session.GetString("2FA_UserId") == user.Id)
                    {
                        _logger.LogInformation($"✅ Allowing session for {user.Email} as they just completed 2FA.");
                        HttpContext.Session.Remove("2FA_UserId"); // Clear flag
                    }
                    else
                    {
                        await _signInManager.SignOutAsync();
                        Response.Cookies.Delete("SessionToken");
                        return RedirectToAction("Login", "Account");
                    }
                }


                // 🔹 Decrypt NRIC before sending to the view
                if (!string.IsNullOrEmpty(user.NRIC))
                {
                    try
                    {
                        user.NRIC = EncryptionHelper.DecryptData(user.NRIC);
                        _logger.LogInformation($"NRIC decrypted for user {user.Email}.");
                    }
                    catch
                    {
                        _logger.LogError($"Failed to decrypt NRIC for user {user.Email}.");
                        user.NRIC = "[Decryption Error]";
                    }
                }
            }
            else
            {
                _logger.LogWarning("Anonymous user attempted to access the home page.");
                return RedirectToAction("Login", "Account");
            }

            return View(user);
        }

        [Route("Home/Error")]
        public IActionResult Error(int? statusCode = null)
        {
            var exceptionFeature = HttpContext.Features.Get<IExceptionHandlerFeature>();

            if (statusCode.HasValue)
            {
                _logger.LogWarning($"⚠ Error {statusCode}: {Request.Path}");
                ViewData["StatusCode"] = statusCode;
                ViewData["ErrorMessage"] = $"An error occurred (Status Code: {statusCode}).";
            }
            else if (exceptionFeature != null)
            {
                _logger.LogError($"🚨 Unhandled Exception: {exceptionFeature.Error.Message}");

                ViewData["StatusCode"] = 500; // Internal Server Error
                ViewData["ErrorMessage"] = "An unexpected error occurred.";
                ViewData["ErrorDetails"] = "Please contact support if the issue persists.";
            }
            else
            {
                _logger.LogError("🚨 Unknown error encountered.");
                ViewData["StatusCode"] = "Unknown";
                ViewData["ErrorMessage"] = "An unknown error occurred.";
            }

            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

    }
}
