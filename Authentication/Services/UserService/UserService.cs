using System.Security.Claims;

namespace Authentication.Services.UserService
{
    public class UserService : IUserService
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        public UserService(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }
        public string GetUserName()
        {
            var res = string.Empty;

            if(_httpContextAccessor.HttpContext !=null)
            {
                res = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
            }

            return res;
        }
    }
}
