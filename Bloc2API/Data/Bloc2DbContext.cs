using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Bloc2API.Models;
namespace Bloc2API.Data
{
    // Définition de la classe Bloc2DbContext qui hérite de IdentityDbContext
    public class Bloc2DbContext : IdentityDbContext
    {
        // Constructeur de la classe Bloc2DbContext
        public Bloc2DbContext(DbContextOptions<Bloc2DbContext> options) : base(options) { }

        // DbSet pour accéder à la table des utilisateurs dans la base de données
        public DbSet<User> Users { get; set; }
    }
}
