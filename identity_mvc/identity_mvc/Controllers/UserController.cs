using identity_mvc.Models;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;
using identity_mvc.Data;

namespace identity_mvc.Controllers
{
    public class UserController : Controller
    {

        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _db;
        public UserController(UserManager<ApplicationUser> userManager, ApplicationDbContext db,
            RoleManager<IdentityRole> roleManager)
        {
            _db = db;   
            _userManager = userManager;
            _roleManager = roleManager;

        }

        public IActionResult Index()
        {
            var userList = _db.ApplicationUsers.ToList();
            var userRole = _db.UserRoles.ToList();  
            var roles = _db.Roles.ToList(); 


            foreach(var user in userList)
            {
                var user_role = userRole.FirstOrDefault(u => u.UserId == user.Id);
                if (user_role == null)
                {
                    user.Role = "None";
                }
                else 
                {
                    user.Role = roles.FirstOrDefault(x => x.Id == user_role.RoleId).Name;
                }
            }

            return View(userList);
        }
    }
}
