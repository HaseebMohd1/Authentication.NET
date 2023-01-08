using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Authentication.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        public static User user = new User();

        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }


        [HttpGet, Authorize]
        public ActionResult<string> GetMe()
        {
            var userName = User?.Identity?.Name;

            var userName2 = User.FindFirst(ClaimTypes.Name);
            var userRole = User.FindFirst(ClaimTypes.Role);

            return Ok(new {userName, userName2, userRole});
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto userDetails)
        {
            CreatePasswordHash(userDetails.Password, out byte[] passwordSalt, out byte[] passwordHash);

            user.UserName = userDetails.UserName;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto userDetails)
        {
            if(user.UserName != userDetails.UserName)
            {
                return BadRequest("User Not Found");
            }

            if(!VerifyPassword(userDetails.Password, user.PasswordSalt, user.PasswordHash))
            {
                return BadRequest("Incorrect Credentials!!!");
            }

            string token = CreateToken(user);

            return Ok(token);
        }

        private string CreateToken(User user)
        {

            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));

            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            // definig PAYLOAD of our JSON Web Token    
            var token = new JwtSecurityToken(
                    claims: claims,
                    expires : DateTime.Now.AddDays(1),
                    signingCredentials : credentials
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        private void CreatePasswordHash(string password, out byte[] passwordSalt, out byte[] passwordHash)
        {
            using(var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPassword(string password, byte[] passwordSalt, byte[] passwordHash)
        {
            using(var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));

                return computedHash.SequenceEqual(passwordHash);
            }
        }
    }
}
