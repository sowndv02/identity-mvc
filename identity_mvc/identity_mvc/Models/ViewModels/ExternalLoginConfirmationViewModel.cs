using System.ComponentModel.DataAnnotations;

namespace identity_mvc.Models.ViewModels
{
    public class ExternalLoginConfirmationViewModel
    {
        [Required]
        public string FullName { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
