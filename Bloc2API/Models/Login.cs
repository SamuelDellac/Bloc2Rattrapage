namespace Bloc2API.Models
{
    // Définition de la classe Login
    public class Login
    {
        // Propriété pour stocker le jeton JWT, initialisée à une chaîne vide par défaut
        public string Token { get; set; } = string.Empty;

        // Propriété pour indiquer le résultat de l'opération d'authentification
        public bool Result { get; set; }

        // Liste pour stocker les éventuelles erreurs liées à l'opération
        public List<string> Errors { get; set; }
    }
}
