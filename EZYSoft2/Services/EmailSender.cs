using System.Net;
using System.Net.Mail;
using EZYSoft2.Models;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

public class EmailSender : IEmailSender
{
    private readonly EmailSettings _emailSettings;
    private readonly ILogger<EmailSender> _logger;

    public EmailSender(IOptions<EmailSettings> emailSettings, ILogger<EmailSender> logger)
    {
        _emailSettings = emailSettings.Value;
        _logger = logger;
    }

    public async Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        _logger.LogInformation("📧 Attempting to send email...");
        _logger.LogInformation($"🔹 SMTP Server: {_emailSettings.SmtpServer}");
        _logger.LogInformation($"🔹 Port: {_emailSettings.Port}");
        _logger.LogInformation($"🔹 Sender Email: {_emailSettings.SenderEmail}");
        _logger.LogInformation($"🔹 Receiver Email: {email}");

        try
        {
            using var client = new SmtpClient(_emailSettings.SmtpServer, _emailSettings.Port)
            {
                Credentials = new NetworkCredential(_emailSettings.SenderEmail, _emailSettings.Password),
                EnableSsl = true
            };

            var mailMessage = new MailMessage
            {
                From = new MailAddress(_emailSettings.SenderEmail, _emailSettings.SenderName),
                Subject = subject,
                Body = htmlMessage,
                IsBodyHtml = true
            };

            mailMessage.To.Add(email);

            _logger.LogInformation("🔹 Sending email...");
            await client.SendMailAsync(mailMessage);
            _logger.LogInformation("✅ Email sent successfully!");
        }
        catch (Exception ex)
        {
            _logger.LogError($"🚨 Email sending failed: {ex.Message}");
            _logger.LogError($"📌 StackTrace: {ex.StackTrace}");
            throw; // Re-throw exception to see detailed logs
        }
    }
}
