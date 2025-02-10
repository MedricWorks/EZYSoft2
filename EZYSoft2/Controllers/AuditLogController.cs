using EZYSoft2.Data;
using EZYSoft2.Helpers;
using EZYSoft2.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using System.Threading.Tasks;

namespace EZYSoft2.Controllers
{
    [Authorize] // 🔹 Only logged-in users can view logs
    public class AuditLogController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly SessionHelper _sessionHelper;

        public AuditLogController(ApplicationDbContext context, SessionHelper sessionHelper)
        {
            _context = context;
            _sessionHelper = sessionHelper;
        }

        public async Task<IActionResult> Index()
        {
            var user = await _sessionHelper.GetValidatedUser(this);
            if (user == null)
            {
                return RedirectToAction("Login", "Account");
            }

            var logs = await _context.AuditLogs.OrderByDescending(l => l.Timestamp).ToListAsync();
            return View(logs);
        }
    }
}
