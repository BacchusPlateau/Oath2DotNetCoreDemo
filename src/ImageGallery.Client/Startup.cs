using IdentityModel;
using ImageGallery.Client.HttpHandlers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using System;
using System.IdentityModel.Tokens.Jwt;

namespace ImageGallery.Client
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();  //clears any mapped claims
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews()
                 .AddJsonOptions(opts => opts.JsonSerializerOptions.PropertyNamingPolicy = null);

            services.AddAuthorization(options =>
            {
                options.AddPolicy(
                    "CanOrderFrame",
                    policyBuilder =>
                    {
                        policyBuilder.RequireAuthenticatedUser();
                        policyBuilder.RequireClaim("country", "be");
                        policyBuilder.RequireClaim("subscriptionlevel", "PayingUser");

                        //we could also require a role with our policy
                        //policyBuilder.RequireRole(...);
                    });
            });

            //this allows dependency injection
            services.AddHttpContextAccessor();

            services.AddTransient<BearerTokenHandler>();

            // create an HttpClient used for accessing the API project, NOT the IDP server
            services.AddHttpClient("APIClient", client =>
            {
                client.BaseAddress = new Uri("https://localhost:44366/");
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
            }).AddHttpMessageHandler<BearerTokenHandler>();

            //create an HttpClient used for accessing the IDP server
            services.AddHttpClient("IDPClient", client =>
            {
                client.BaseAddress = new Uri("https://localhost:5001/");
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
            });

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
                {
                    options.AccessDeniedPath = "/Authorization/AccessDenied";
                })
                .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
                {
                    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

                    //this points to the Identity Server, NOT the client server url
                    options.Authority = "https://localhost:5001/";
                    options.ClientId = "imagegalleryclient";
                    options.ResponseType = "code";

                    //comment this out to disable PKCE, it is enabled by default
                    //options.UsePkce = false;

                    //?
                    //options.CallbackPath = new PathString("...");

                    //example of preserving a non-default claim - this is non-intuitive
                    //options.ClaimActions.Remove("nbf");  

                    //examples of removing a default claim
                    options.ClaimActions.DeleteClaim("sid");
                    options.ClaimActions.DeleteClaim("idp");
                    options.ClaimActions.DeleteClaim("s_hash");
                    options.ClaimActions.DeleteClaim("auth_time");

                    //the below Scope items correspond to the claims list defined in the IDP config.  
                    //you only need to add items that are not defaults
                    options.Scope.Add("address");
                    options.Scope.Add("roles");
                    options.Scope.Add("imagegalleryapi");
                    options.Scope.Add("country");
                    options.Scope.Add("subscriptionlevel");
                    options.Scope.Add("offline_access");  //allows token refreshing

                    //for custom claims we have to manually configure
                    options.ClaimActions.MapUniqueJsonKey("role", "role");
                    options.ClaimActions.MapUniqueJsonKey("subscriptionlevel", "subscriptionlevel");
                    options.ClaimActions.MapUniqueJsonKey("country", "country");

                    options.SaveTokens = true;
                    options.ClientSecret = "secret";
                    options.GetClaimsFromUserInfoEndpoint = true;

                    //this is required to populate the User.IsInRole list
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        NameClaimType = JwtClaimTypes.GivenName,
                        RoleClaimType = JwtClaimTypes.Role
                    };

                });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseStaticFiles();
 
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Shared/Error");
                // The default HSTS value is 30 days. You may want to change this for
                // production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Gallery}/{action=Index}/{id?}");
            });
        }
    }
}
