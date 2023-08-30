// Importation des espaces de noms nécessaires
using Microsoft.AspNetCore.Mvc;
using Bloc2API.Data;
using Bloc2API.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Bloc2API.Configurations;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using System.ComponentModel.DataAnnotations;

namespace Bloc2API.Controllers
{
    // Déclaration du contrôleur pour la gestion des utilisateurs
    [ApiController]
    [Route("/api/[controller]")]
    public class UsersController : Controller
    {
        private readonly ILogger<UsersController> _logger;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtConfiguration _jwtConfig;

        // Constructeur de la classe UsersController
        public UsersController(ILogger<UsersController> logger, UserManager<IdentityUser> userManager,IOptions<JwtConfiguration> jwtConfigOptions)
        {
            // Injection des dépendances nécessaires
            this._logger = logger;
            this._userManager = userManager;
            this._jwtConfig = jwtConfigOptions.Value;
        }

        // Action pour obtenir la liste des utilisateurs
        [HttpGet]
        public async Task<IActionResult> GetUsers()
        {
            // Récupération de la liste des utilisateurs à partir du UserManager
            List<IdentityUser> users = _userManager.Users.ToList();
            return Ok(users);
        }

        // Action pour ajouter un nouvel utilisateur
        [HttpPost]
        public async Task<IActionResult> AddUser([FromBody] User user)
        {
            if (ModelState.IsValid)
            {
                // Verify if the provided input is a valid email
                if (!IsValidEmail(user.Email))
                {
                    return BadRequest("Email address is not valid.");
                }

                // Check if a user with the same email already exists
                IdentityUser? mailExist = await _userManager.FindByEmailAsync(user.Email);
                if (mailExist != null)
                {
                    return BadRequest("An account with this email address already exists.");
                }

                // Create a new Identity user
                var newUser = new IdentityUser()
                {
                    Email = user.Email,
                    UserName = user.Email
                };
                // Create the user using the UserManager
                var isCreated = await _userManager.CreateAsync(newUser, user.Password);

                if (isCreated.Succeeded)
                {
                    // Generate a JWT token for the newly created user
                    string token = GenerateJwtToken(newUser);
                    return Ok(new Login()
                    {
                        Result = true,
                        Token = token
                    });
                }
                // Return errors in case of creation failure
                return BadRequest(error: isCreated.Errors.Select(x => x.Description).ToList());
            }
            // Return an error in case of an invalid model
            return BadRequest(error: "Invalid registration data.");
        }

        // Function to validate if a string is a valid email address
        private bool IsValidEmail(string email)
        {
            return new EmailAddressAttribute().IsValid(email);
        }

        // Action pour l'authentification de l'utilisateur
        [HttpPost]
        [Route(template: "login")]
        public async Task<IActionResult> UserLogin([FromBody] User login)
        {
            if (ModelState.IsValid)
            {
                // Recherche de l'utilisateur existant par email
                var existingUser = await _userManager.FindByEmailAsync(login.Email);

                if (existingUser == null)
                {
                    return BadRequest(error: "Email ou mot de passe incorrect");
                }
                // Vérification du mot de passe pour l'utilisateur existant
                var verifPassword = await _userManager.CheckPasswordAsync(existingUser, login.Password);
                if (verifPassword)
                {
                    // Génération d'un jeton JWT en cas de succès
                    var token = GenerateJwtToken(existingUser);
                    return Ok(new Login()
                    {
                        Token = token,
                        Result = true
                    });
                }
                return BadRequest(error: "Email ou mot de passe incorrect");
            }
            return BadRequest();
        }

        // Fonction privée pour générer un jeton JWT
        private string GenerateJwtToken(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            byte[] key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new[]
                {
            new Claim("Id", value: user.Id),
            new Claim(JwtRegisteredClaimNames.Sub, value: user.Email),
            new Claim(JwtRegisteredClaimNames.Email, value: user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        }),
                Expires = DateTime.UtcNow.AddHours(8),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);
            return jwtToken;
        }

        // Action pour supprimer un utilisateur
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteUser(string id)
        {
            // Recherche de l'utilisateur par son ID
            var user = await _userManager.FindByIdAsync(id);

            if (user == null)
            {
                return NotFound();
            }

            // Suppression de l'utilisateur avec le UserManager
            var result = await _userManager.DeleteAsync(user);

            if (result.Succeeded)
            {
                return NoContent(); // 204 No Content
            }
            else
            {
                return BadRequest(result.Errors);
            }
        }

        [HttpPut]
        [Route("{id:Guid}")]
        public async Task<IActionResult> UpdateUser([FromRoute] Guid id, [FromQuery] string? updatedEmail, [FromQuery] string? updatedPassword)
        {
            if (ModelState.IsValid)
            {
                // Recherche de l'utilisateur par son ID
                var user = await _userManager.FindByIdAsync(id.ToString());

                if (user == null)
                {
                    return BadRequest();
                }
                if (!IsValidEmail(updatedEmail))
                {
                    return BadRequest("Email address is not valid.");
                }
                // Sauvegarde de l'email d'origine pour la génération du nouveau jeton
                string originalEmail = user.Email;

                // Mise à jour des informations de l'utilisateur
                if (!string.IsNullOrEmpty(updatedEmail))
                {
                    user.Email = updatedEmail;
                    user.UserName = updatedEmail;
                }

                if (!string.IsNullOrEmpty(updatedPassword))
                {
                    var newPasswordHash = _userManager.PasswordHasher.HashPassword(user, updatedPassword);
                    user.PasswordHash = newPasswordHash;
                }

                var result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    // Générer un nouveau jeton JWT avec les nouvelles informations de l'utilisateur
                    string newToken = GenerateJwtToken(user);
                    return Ok(new { message = "User updated successfully", newToken = newToken });
                }
                else
                {
                    return BadRequest(result.Errors);
                }
            }

            return BadRequest("Invalid data");
        }





    }
}
