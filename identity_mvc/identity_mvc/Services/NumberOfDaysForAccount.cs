using identity_mvc.Data;
using identity_mvc.Services.IServices;

namespace identity_mvc.Services
{
    public class NumberOfDaysForAccount : INumberOfDaysForAccount
    {
        private readonly ApplicationDbContext _db;
        public NumberOfDaysForAccount(ApplicationDbContext db)
        {
            _db = db;
        }
        public int Get(string userId)
        {
            var user = _db.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if (user != null && user.DateCreated != DateTime.MinValue)
            {
                return (DateTime.Today - user.DateCreated).Days;
            }
            return 0;
        }
    }
}
