#to run project 
 -> run program normally in VSC

  #install things using pip
  ``pip install``
  `
  
  #install flask
  ``pip install flask``

  Requirements
1. You may use either a SQL or NoSQL datastore, to store login credentials (username and password). Be smart about your data store choice.
2. You must create an application that connects to your data store.
3. You must allow any anonymous user to register for an account by providing a username and password.
4. You must use, create, and store a salted SHA-256 hash to avoid storing the user's password in plain text in the database.
5. Your salt value must be randomly generated for each user's password and also stored in your database alongside the hash for later retrieval/comparison/login activities
6. You must allow registered users to attempt to login, and then you should compare the credentials they provided on login with the credentials stored in the database.  If they match, the user is authenticated. If they do not match, 7. then refuse access to the application.
8. You must provide your user with the ability to change their password - their username should remain
9. You must enforce some type of basic password complexity rules for your user's chosen passwords. For instance, your passwords might need to require a certain number of letters, numbers, characters, special symbols, non-repeating characters, etc... (While you can certainly write your own algo for this, feel free to leverage a library from your platform of choice.

Be sure to show:
1. > a user registering 
2. > credentials stored in the table
3. > a user authenticating incorrectly
4. > a user authenticating correctly
5. > a user changing their password
6. > password protection rules

