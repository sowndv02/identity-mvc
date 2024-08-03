using identity_mvc.Models;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;
using identity_mvc.Data;
using identity_mvc.Models.ViewModels;

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



        public async Task<IActionResult> ManageRole(string userId)
        {
            ApplicationUser user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }

            List<string> exsitingUserRoles = await _userManager.GetRolesAsync(user) as List<string>;
            var model = new RolesViewModel()
            {
                User = user
            };

            foreach (var role in _roleManager.Roles)
            {
                RoleSelection roleSelection = new()
                {
                    RoleName = role.Name
                };
                if (exsitingUserRoles.Any(c => c == role.Name))
                {
                    roleSelection.IsSelected = true;
                }
                model.RolesList.Add(roleSelection);
            }
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageRole(RolesViewModel rolesViewModel)
        {
            ApplicationUser user = await _userManager.FindByIdAsync(rolesViewModel.User.Id);
            if (user == null)
            {
                return NotFound();
            }

            var oldUserRoles = await _userManager.GetRolesAsync(user);
            var result = await _userManager.RemoveFromRolesAsync(user, oldUserRoles);

            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error while removing roles";
                return View(rolesViewModel);
            }

            result = await _userManager.AddToRolesAsync(user,
                rolesViewModel.RolesList.Where(x => x.IsSelected).Select(y => y.RoleName));

            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error while adding roles";
                return View(rolesViewModel);
            }

            TempData[SD.Success] = "Roles assigned successfully";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LockUnlock(string userId)
        {
            ApplicationUser user = _db.ApplicationUsers.FirstOrDefault(u => u.Id == userId);
            if (user == null)
            {
                return NotFound();
            }
            if (user.LockoutEnd != null && user.LockoutEnd > DateTime.Now)
            {
                //user is locked and will remain locked untill lockoutend time
                //clicking on this action will unlock them
                user.LockoutEnd = DateTime.Now;
                TempData[SD.Success] = "User unlocked successfully";
            }
            else
            {
                //user is not locked, and we want to lock the user
                user.LockoutEnd = DateTime.Now.AddYears(1000);
                TempData[SD.Success] = "User locked successfully";
            }
            _db.SaveChanges();

            return RedirectToAction(nameof(Index));
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteUser(string userId)
        {
            var user = _db.ApplicationUsers.FirstOrDefault(u => u.Id == userId);
            if (user == null)
            {
                return NotFound();
            }

            _db.ApplicationUsers.Remove(user);
            _db.SaveChanges();
            TempData[SD.Success] = "User deleted successfully";
            return RedirectToAction(nameof(Index));

        }

    }
}
