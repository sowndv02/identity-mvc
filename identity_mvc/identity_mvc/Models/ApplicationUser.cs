using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace identity_mvc.Models
{
    public class ApplicationUser :IdentityUser
    {
        [Required]
        public string FullName { get; set; }
    }
}
