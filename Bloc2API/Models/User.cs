using System.ComponentModel.DataAnnotations;
namespace Bloc2API.Models
{
    // Définition de la classe User pour représenter les données d'un utilisateur
    public class User
    {
        public Guid Id { get; set; }

        [Required] // Attribut de validation : Le champ Email est requis
        public string Email { get; set; }

        [Required] // Attribut de validation : Le champ Password est requis
        public string Password { get; set; }
    }
}
