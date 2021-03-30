using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class UserController : BaseApiController
    {
        private readonly DataContext _context;
        public UserController(DataContext context)
        {
            _context = context;
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult<IEnumerable<AppUser>>> GetUser(){
            return await _context.Users.ToListAsync();
        }

        //api/user/id
        [Authorize]
        [HttpGet("{id}")]   
        public async Task<ActionResult<AppUser>> GetUser(int id){
            return await _context.Users.FindAsync(id); 
        }
    }
}