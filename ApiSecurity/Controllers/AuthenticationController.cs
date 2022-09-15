using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ApiSecurity.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly IConfiguration _config;

    public record AuthenticationData(string? UserName, string? Password);

    public record UserData(int UserId, string UserName, string Title, string EmployeeId);

    public AuthenticationController(IConfiguration config)
    {
        _config = config;
    }

    [HttpPost("token")]
    [AllowAnonymous]
    public ActionResult<string> Authenticate([FromBody] AuthenticationData data)
    {
        var user = ValidateCredentials(data);

        if (user is null)
        {
            return Unauthorized();
        }
         
        var token = GenerateToken(user);
        return Ok(token);   

    }

    private string GenerateToken(UserData user)
    {
        var securityKey = new SymmetricSecurityKey(
            Encoding.ASCII.GetBytes(
                _config.GetValue<string>("Authentication:SecretKey")));

        var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        List<Claim> claims = new();
        claims.Add(new(JwtRegisteredClaimNames.Sub, user.UserId.ToString()));
        claims.Add(new(JwtRegisteredClaimNames.UniqueName , user.UserName));
        claims.Add(new("title", user.Title));   // Custom Claim
        claims.Add(new("employeeId", user.EmployeeId));   // Custom Claim

        var token = new JwtSecurityToken(
            _config.GetValue<string>("Authentication:Issuer"),
            _config.GetValue<string>("Authentication:Audience"),
            claims,
            DateTime.UtcNow, // when token becomes valid
            DateTime.UtcNow.AddMinutes(1), // when tokens will expire
            signingCredentials
            );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private UserData? ValidateCredentials(AuthenticationData data)
    {
        // THIS IS ONLY FOR DEMO, NOT A PRODUCTION CODE
        if (CompareValues(data.UserName, "mani") &&
            CompareValues(data.Password, "123"))
        {
            return new UserData(1, data.UserName!, "Business Owner", "E001");
        }

        if (CompareValues(data.UserName, "krishu") &&
            CompareValues(data.Password, "123"))
        {
            return new UserData(2, data.UserName!, "Head of Security", "E005");
        }

        return null;

    }

    private bool CompareValues(string? actual, string expected)
    {
        return actual == expected;
    }
}
