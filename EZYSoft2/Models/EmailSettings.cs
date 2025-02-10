namespace EZYSoft2.Models
{
    public class EmailSettings
    {
        public string SenderEmail { get; set; }  // ✅ Ensure this exists
        public string SenderName { get; set; }
        public string SmtpServer { get; set; }
        public int Port { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
