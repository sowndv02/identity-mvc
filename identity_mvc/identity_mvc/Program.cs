using identity_mvc;
using identity_mvc.Authorize;
using identity_mvc.Data;
using identity_mvc.Models;
using identity_mvc.Services;
using identity_mvc.Services.IServices;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);




// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultSQLConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();


builder.Services.AddTransient<IEmailSender, EmailSender>();
builder.Services.AddScoped<INumberOfDaysForAccount, NumberOfDaysForAccount>();

//Add DI requirement authorization handler
builder.Services.AddScoped<IAuthorizationHandler, AdminWithOver1000DaysHandler>();
builder.Services.AddScoped<IAuthorizationHandler, FirstNameAuthHandler>();

// Config access denied path
builder.Services.ConfigureApplicationCookie(options =>
{
    options.AccessDeniedPath = new PathString("/Account/AccessDenied");
});

// Config password, Lockout, AccessAttempts
builder.Services.Configure<IdentityOptions>(opt =>
{
    opt.Password.RequireDigit = false;
    opt.Password.RequireLowercase = false;
    opt.Password.RequireNonAlphanumeric = false;
    opt.Lockout.MaxFailedAccessAttempts = 5;    
    opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
    opt.SignIn.RequireConfirmedEmail = false;   
});

// Config Authorization with policy

builder.Services.AddAuthorization(option =>
{

    // Authorization with policy using role requirement
    option.AddPolicy("Admin", policy => policy.RequireRole(SD.Admin));
    // Authorization with policy using role requirement using condition and
    option.AddPolicy("AdminAndUser", policy => policy.RequireRole(SD.Admin).RequireRole(SD.User));
    // Authorization with policy using single claim requirement
    option.AddPolicy("AdminRole_CreateClaim", policy => policy.RequireRole(SD.Admin).RequireClaim("Create", "True"));
    // Authorization with policy using multiple claim requirement
    option.AddPolicy("AdminRole_CreateEditDeleteClaim", policy => policy.RequireRole(SD.Admin)
                                            .RequireClaim("Create", "True")
                                            .RequireClaim("Delete", "True")
                                            .RequireClaim("Edit", "True")
                                            );


    option.AddPolicy("AdminRole_CreateEditDeleteClaim_ORSuperAdminRole", policy => policy.RequireAssertion(context => AdminRole_CreateEditDeleteClaim_ORSuperAdminRole(context)));

    option.AddPolicy("OnlySuperAdminChecker", p => p.Requirements.Add(new OnlySuperAdminChecker()));
    // requirement is calculate date
    option.AddPolicy("AdminWithMoreThan1000Days", p => p.Requirements.Add(new AdminWithMoreThan1000DaysRequirement(1000)));

    // requirement is claim 
    option.AddPolicy("FirstNameAuth", p => p.Requirements.Add(new FirstNameAuthRequirement("test")));


});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();


bool AdminRole_CreateEditDeleteClaim_ORSuperAdminRole(AuthorizationHandlerContext context)
{
    return (context.User.IsInRole(SD.Admin) && context.User.HasClaim(c => c.Type == "Create" && c.Value == "True")
        && context.User.HasClaim(c => c.Type == "Edit" && c.Value == "True")
        && context.User.HasClaim(c => c.Type == "Delete" && c.Value == "True")
    ) || context.User.IsInRole(SD.SuperAdmin);
}