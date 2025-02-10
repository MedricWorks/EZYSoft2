using EZYSoft2.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace EZYSoft2.Helpers
{
    public class SessionHelper
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly ILogger<SessionHelper> _logger;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public SessionHelper(UserManager<User> userManager, SignInManager<User> signInManager, ILogger<SessionHelper> logger, IHttpContextAccessor httpContextAccessor)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<User> GetValidatedUser(Controller controller)
        {
            var user = await _userManager.GetUserAsync(controller.User);

            if (user == null)
            {
                _logger.LogWarning("Unauthorized access attempt detected.");
                return null; // Caller should handle redirection
            }

            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext.Request.Cookies.TryGetValue("SessionToken", out string storedSessionToken))
            {
                if (string.IsNullOrEmpty(user.SessionToken) || user.SessionToken != storedSessionToken)
                {
                    _logger.LogWarning($"Session token mismatch for {user.Email}. Logging out.");
                    await _signInManager.SignOutAsync();
                    httpContext.Response.Cookies.Delete("SessionToken");
                    return null;
                }
            }
            else
            {
                _logger.LogWarning($"Session token missing for {user.Email}. Logging out.");
                await _signInManager.SignOutAsync();
                httpContext.Response.Cookies.Delete("SessionToken");
                return null;
            }

            return user;
        }
    }
}
