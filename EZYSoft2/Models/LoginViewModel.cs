using System.ComponentModel.DataAnnotations;

namespace EZYSoft2.Models
{
    public class LoginViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        public bool RememberMe { get; set; }
        public bool ForceLogoutOtherSession { get; set; }

    }
}
