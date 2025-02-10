using System.ComponentModel.DataAnnotations;

namespace EZYSoft2.Models
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
