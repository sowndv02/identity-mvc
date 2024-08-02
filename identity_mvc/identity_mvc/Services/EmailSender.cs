using Microsoft.AspNetCore.Identity.UI.Services;
using SendGrid.Helpers.Mail;
using SendGrid;

namespace identity_mvc.Services
{
    public class EmailSender : IEmailSender
    {
        public string SendGridKey {  get; set; }

        public EmailSender(IConfiguration _configuration)
        {
            SendGridKey = _configuration.GetValue<string>("SendGrid:SecretKey");
        }

        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            var client = new SendGridClient(SendGridKey);
            var from_email = new EmailAddress("daoson03112002@gmail.com", "SonDV - Identity Manager");

            var to_email = new EmailAddress(email);

            var msg = MailHelper.CreateSingleEmail(from_email, to_email, subject, "", htmlMessage);
            return client.SendEmailAsync(msg);
        }
    }
}
