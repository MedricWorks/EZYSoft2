using System.ComponentModel.DataAnnotations;

namespace EZYSoft2.Models
{
    public class TwoFactorAuthViewModel
    {
        [Required]
        public string Code { get; set; }

        public bool RememberMe { get; set; }
        public string SharedKey { get; set; }  // Secret key for the user
        public string AuthenticatorUri { get; set; }  // QR Code URI
    }
}
