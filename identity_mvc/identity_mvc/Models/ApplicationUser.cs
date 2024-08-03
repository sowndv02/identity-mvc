using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace identity_mvc.Models
{
    public class ApplicationUser :IdentityUser
    {
        [Required]
        public string FullName { get; set; }

        [NotMapped]
        public string RoleId {  get; set; }
        [NotMapped]
        public string Role { get; set; }
        [NotMapped]
        public string UserClaim { get; set; }
    }
}
