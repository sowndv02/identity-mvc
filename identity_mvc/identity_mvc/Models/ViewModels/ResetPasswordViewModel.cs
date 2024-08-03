using System.ComponentModel.DataAnnotations;

namespace identity_mvc.Models.ViewModels
{
    public class ResetPasswordViewModel
    {
        public string Code { get; set; }
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        [Display(Name = "Password")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [DataType(DataType.Password)]
        [Display(Name = "Confirm Password")]
        [Compare("Password", ErrorMessage = "The password and confirm password do not match.")]
        public string ConfirmPassword { get; set; }
    }
}
