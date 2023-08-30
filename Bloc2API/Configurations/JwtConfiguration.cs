namespace Bloc2API.Configurations
{
    // Définition de la classe JwtConfiguration pour la configuration du JWT
    public class JwtConfiguration
    {
        public string Secret { get; set; } = string.Empty; // Propriété pour stocker la clé secrète du JWT (initialisée à une chaîne vide par défaut)
    }
}
