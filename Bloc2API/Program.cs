using Bloc2API.Data;
using Microsoft.EntityFrameworkCore;
using Bloc2API.Configurations;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Configuration de la classe JwtConfiguration à partir des valeurs dans le fichier de configuration
builder.Services.Configure<JwtConfiguration>(builder.Configuration.GetSection(key: "JwtConfig"));

// Ajout des services pour les contrôleurs
builder.Services.AddControllers();

// Ajout des services pour la génération de la documentation API via Swagger/OpenAPI
builder.Services.AddEndpointsApiExplorer();

// Ajout des services pour la gestion d'identité par défaut (Identity) avec Entity Framework Stores
builder.Services.AddDefaultIdentity<IdentityUser>(configureOptions: options => options.SignIn.RequireConfirmedAccount = false)
    .AddEntityFrameworkStores<Bloc2DbContext>();

// Ajout des services pour  Swagger
builder.Services.AddSwaggerGen();

// Ajout des services pour la gestion de la base de données avec Entity Framework Core (utilisation de SQL Server)
builder.Services.AddDbContext<Bloc2DbContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("RattrapageDbConnectionString")));

// Configuration de l'authentification
builder.Services.AddAuthentication(configureOptions: options =>
{
    // Configuration des schémas d'authentification par défaut
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(jwt =>
{
    // Récupération de la clé secrète depuis la configuration
    byte[] key = Encoding.ASCII.GetBytes(builder.Configuration.GetSection(key: "JwtConfig:Secret").Value);
    jwt.SaveToken = true;

    // Configuration des paramètres de validation du jeton JWT
    jwt.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = true,
        ValidateAudience = true,
        RequireExpirationTime = false,
        ValidateLifetime = false
    };
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseCors(policy => policy.AllowAnyHeader().AllowAnyMethod().AllowAnyOrigin());
app.UseAuthorization();

app.MapControllers();

app.Run();
