using System.ComponentModel.DataAnnotations;

namespace identity_mvc.Models.ViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
