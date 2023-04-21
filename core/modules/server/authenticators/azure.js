/*\
title: $:/core/modules/server/authenticators/azure.js
type: application/javascript
module-type: authenticator

Authenticator for checking oauth tokens from azure canned oauth provider and checking against authorized users from environment.

It is the second part that this is really for, otherwise you could just use the authorized header authenticator and set it to x-ms-client-principal-name.

\*/

(function(){

  /*jslint node: true, browser: true */
  /*global $tw: false */
  "use strict";
  
  function AzureAuthenticator(server) {
    this.server = server;
    this.header = 'x-ms-client-principal-name';
    this.authorizedUsers = []
    this.authorizedDomains = []
  }
  
  /*
  Returns true if the authenticator is active, false if it is inactive, or a string if there is an error
  */
  AzureAuthenticator.prototype.init = function() {
    let authUsers = process.env.AuthorizedUsers;
    let authDomains = process.env.AuthorizedDomains;
    if (!authUsers && !authDomains) {
      return "The administrator must configure at least one of AuthorizedUsers or AuthorizedDomains in the application settings."
    }
    this.authorizedUsers = authUsers.split(";").map(x => x.trim());
    this.authorizedDomains = authDomains.split(";").map(x => x.trim());
    return !!process.env.AzureOAuth;
  };
  
  /*
  Returns true if the request is authenticated and assigns the "authenticatedUsername" state variable.
  Returns false if the request couldn't be authenticated having sent an appropriate response to the browser
  */
  AzureAuthenticator.prototype.authenticateRequest = function(request,response,state) {
    // Otherwise, authenticate as the username in the specified header
    var username = request.headers[this.header];
    if(!username) {
      response.writeHead(401,"Authorization required to access '" + state.server.servername + "'");
      response.end();
      return false;
    } else if (!this.authorizedDomains.includes(username.split("@")[1]) && !this.authorizedUsers.includes(username)){
      response.writeHead(401,"Your username is not authorized to access this resource.");
      response.end();
      return false;
    } else {
      // authenticatedUsername will be undefined for anonymous users
      state.authenticatedUsername = username;
      return true;
    }
  };
  
  exports.AuthenticatorClass = AzureAuthenticator;
  
  })();
  