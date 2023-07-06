using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWT_UsingDotNet5.Models
{
    public class ApplicationDbConteext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbConteext(DbContextOptions<ApplicationDbConteext> options) : base(options)
        {

        }
    }
}
