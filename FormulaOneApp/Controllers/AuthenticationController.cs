using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using FormulaOneApp.Configurations;
using FormulaOneApp.Data;
using FormulaOneApp.Models;
using FormulaOneApp.Models.DTOs;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.IdentityModel.Tokens;

namespace FormulaOneApp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthenticationController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IConfiguration _configuration;
    private readonly AppDbContext _context;
    private readonly TokenValidationParameters _tokenValidationParameters;

    public AuthenticationController(
        UserManager<IdentityUser> userManager,
        IConfiguration configuration,
        AppDbContext context,
        TokenValidationParameters tokenValidationParameters)
    {
        _userManager = userManager;
        _configuration = configuration;
        _context = context;
        _tokenValidationParameters = tokenValidationParameters;
    }

    [HttpPost]
    [Route("Register")]
    public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDto requestDto)
    {
        // Validate the incoming request
        if (ModelState.IsValid)
        {
            // We need to check if the email already exist.
            var user_exist = await _userManager.FindByEmailAsync(requestDto.Email);

            if (user_exist != null)
            {
                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Email already exist."
                    }
                });
            }

            // create a user.
            var new_user = new IdentityUser()
            {
                Email = requestDto.Email,
                UserName = requestDto.Email
            };

            var is_created = await _userManager.CreateAsync(new_user, requestDto.Password);

            if (is_created.Succeeded)
            {
                // Generate the token.
                var jwtToken = await GenerateJwtToken(new_user);

                return Ok(jwtToken);
            }

            return BadRequest(new AuthResult()
            {
                Errors = new List<string>
                {
                    "Server error"
                },
                Result = false
            });
        }

        return BadRequest();
    }

    [HttpPost]
    [Route("Login")]
    public async Task<IActionResult> Login([FromBody] UserLoginRequestDto loginRequest)
    {
        if (ModelState.IsValid)
        {
            // Check iff the user exist.
            var existing_user = await _userManager.FindByEmailAsync(loginRequest.Email);

            if (existing_user == null)
            {
                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>()
                    {
                        "Invalid payload"
                    },
                    Result = false
                });
            }

            var isCorrect = await _userManager.CheckPasswordAsync(existing_user, loginRequest.Password);

            if (!isCorrect)
            {
                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>()
                    {
                        "Invalid credentials"
                    },
                    Result = false
                });
            }

            var jwtToken = await GenerateJwtToken(existing_user);

            return Ok(jwtToken);
        }

        return BadRequest(new AuthResult()
        {
            Errors = new List<string>()
            {
                "Invalid payload"
            },
            Result = false
        });
    }

    private async Task<AuthResult> GenerateJwtToken(IdentityUser user)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();

        var key = Encoding.UTF8.GetBytes(_configuration.GetSection("JwtConfig:Secret").Value!);

        // Token descriptor
        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(new []
            {
                new Claim("Id", user.Id),
                new Claim(JwtRegisteredClaimNames.Sub, user.Email!),
                new Claim(JwtRegisteredClaimNames.Email, user.Email!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString())
            }),

            Expires = DateTime.UtcNow.Add(TimeSpan.Parse(_configuration.GetSection("JwtConfig:ExpiryTimeFrame").Value!)),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
        };

        var token = jwtTokenHandler.CreateToken(tokenDescriptor);

        var jwtToken = jwtTokenHandler.WriteToken(token);

        var refreshToken = new RefreshToken()
        {
            JwtId = token.Id,
            Token = RandomStringGeneration(23), // Generate a refresh token
            AddedDate = DateTime.UtcNow,
            ExpiryDate = DateTime.UtcNow.AddMonths(6),
            IsRevoked = false,
            IsUsed = false,
            UserId = user.Id
        };

        await _context.RefreshTokens.AddAsync(refreshToken);
        await _context.SaveChangesAsync();

        return new AuthResult()
        {
            Token = jwtToken,
            RefreshToken = refreshToken.Token,
            Result = true
        };
    }

    private string RandomStringGeneration(int length)
    {
        var random = new Random();
        var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789abcdefghijklmnopqrstuvwxyz_";
        return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
    }

}