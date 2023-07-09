using JWT_UsingDotNet5.Helpers;
using JWT_UsingDotNet5.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JWT_UsingDotNet5.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWT _jwt;
        public AuthService(UserManager<ApplicationUser> userManager, IOptions<JWT> jwt, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwt = jwt.Value;
        }

        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if(user is null || ! await _roleManager.RoleExistsAsync(model.Role))
            {
                return "Invalid User ID or Role";
            }
            if(await _userManager.IsInRoleAsync(user,model.Role))
            {
                return "User already assigned to this Role";
            }

            var result = await _userManager.AddToRoleAsync(user, model.Role);

            return result.Succeeded ? string.Empty : "Something Went Wrong";

        }

        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {
            var authModel = new AuthModel();
            var user = await _userManager.FindByEmailAsync(model.Email);

            if(user is null || !await _userManager.CheckPasswordAsync(user,model.Password))
            {
                authModel.message = "Email or Password is incorrect";
                return authModel;
            }

            var jwtSecuirtyToken = await CreateJwtToken(user);
            var RolesList = await _userManager.GetRolesAsync(user);

            authModel.IsAuthenticated = true;
            authModel.ExpireOn = jwtSecuirtyToken.ValidTo;
            authModel.Username = user.UserName;
            authModel.Email = user.Email;
            authModel.Roles = RolesList.ToList();
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecuirtyToken);
            return authModel;
        }

        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
            if (await _userManager.FindByEmailAsync(model.Email) is not null)
                return new AuthModel { message = "Email is already Registered!" };
            if (await _userManager.FindByNameAsync(model.Username) is not null)
                return new AuthModel { message = "Username is already Registered!" };

            var user = new ApplicationUser
            {
                UserName = model.Username,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName
            };

            var result = await _userManager.CreateAsync(user,model.Password);
            if(!result.Succeeded)
            {
                var errors = string.Empty;
                foreach(var error in result.Errors)
                {
                    errors += $"{error.Description},";
                }
                return new AuthModel { message = errors };
            }

            await _userManager.AddToRoleAsync(user, "User");

            var jwtSecuirtyToken = await CreateJwtToken(user);

            return new AuthModel 
            { 
                Email = user.Email,
                IsAuthenticated = true,
                ExpireOn = jwtSecuirtyToken.ValidTo,
                Roles = new List<string> { "User"},
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecuirtyToken),
                Username = user.UserName
            };

        }

        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles)
            {
                roleClaims.Add(new Claim("roles", role));
            }

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub,user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email,user.Email),
                new Claim("uid",user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmertricSecuirtyKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));

            var signinCredentials = new SigningCredentials(symmertricSecuirtyKey,SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.DurationInDays),
                signingCredentials: signinCredentials
                );

            return jwtSecurityToken;

        }
    }
}
