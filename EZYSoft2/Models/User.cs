using Microsoft.AspNetCore.Identity;

namespace EZYSoft2.Models
{
    public class User : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Gender { get; set; }
        public DateTime DateOfBirth { get; set; }
        public string NRIC { get; set; } 
        public string ResumePath { get; set; }
        public string WhoAmI { get; set; }
        public string? SessionToken { get; set; }
        public string PreviousPasswords { get; set; } = "[]"; // Stores JSON array of last 2 password hashes
        public DateTime LastPasswordChange { get; set; } = DateTime.UtcNow;
    }
}
