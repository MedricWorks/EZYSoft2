using EZYSoft2.Data;
using EZYSoft2.Models;
using Microsoft.AspNetCore.Authorization;
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

        public AuditLogController(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<IActionResult> Index()
        {
            var logs = await _context.AuditLogs.OrderByDescending(l => l.Timestamp).ToListAsync();
            return View(logs);
        }
    }
}
