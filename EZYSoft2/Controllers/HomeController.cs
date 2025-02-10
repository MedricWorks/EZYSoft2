using EZYSoft2.Helpers;
using EZYSoft2.Models;
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
                if (string.IsNullOrEmpty(user.SessionToken) || user.SessionToken != storedSessionToken)
                {
                    _logger.LogWarning($"Session token issue detected for {user.Email}. User must log in again.");
                    await _signInManager.SignOutAsync();
                    Response.Cookies.Delete("SessionToken");
                    return RedirectToAction("Login", "Account");
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
    
        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                _logger.LogInformation($"User {user.Email} logged out.");
                user.SessionToken = null;
                await _userManager.UpdateAsync(user);
            }

            await _signInManager.SignOutAsync();
            Response.Cookies.Delete("SessionToken");

            return RedirectToAction("Login", "Account");
        }

        [Route("Home/Error")]
        public IActionResult Error(int? statusCode = null)
        {
            if (statusCode.HasValue)
            {
                _logger.LogWarning($"⚠️ Error {statusCode}: {Request.Path}");
                ViewData["StatusCode"] = statusCode;
                ViewData["Path"] = Request.Path;
            }
            else
            {
                _logger.LogError("🚨 An unexpected error occurred.");
            }

            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

    }
}
