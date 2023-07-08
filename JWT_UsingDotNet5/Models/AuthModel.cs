using System;
using System.Collections.Generic;

namespace JWT_UsingDotNet5.Models
{
    public class AuthModel
    {
        public string message { get; set; }
        public bool IsAuthenticated { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public List<string> Roles { get; set; }
        public string Token { get; set; }
        public DateTime ExpireOn { get; set; }
    }
}
