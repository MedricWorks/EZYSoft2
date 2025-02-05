using System;

namespace EZYSoft2.Models
{
    public class AuditLog
    {
        public int Id { get; set; } // Primary Key
        public string UserId { get; set; } // Foreign Key from IdentityUser
        public string Action { get; set; } // E.g., "Login Success", "Logout", "Failed Login"
        public DateTime Timestamp { get; set; } = DateTime.UtcNow; // Time of action
        public string IPAddress { get; set; } // IP address of the user
    }
}
