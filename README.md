#to run project 
 -> run program normally in VSC

  #install things using pip
  ``pip install``
  `
  
  #install flask
  ``pip install flask``

  Requirements
1. Your application will allow a User to register with a username and a password. Their password will become their "Master Password" for use throughout this application
2. The username and encrypted master password for eah user should be persisted in your datastore. Be sure store the user's master password in an AES-encrypted, Base64 encoded format for later retrieval for each user.
3. Users must be able to log back in to the application using their specific username & master password. Your program should check these credentials against those which you have already stored and encrypted for the User in your system. You should reject those users whose credentials fail.
4. Once a User has successfully logged into the application they should have access to some very basic functionality:
> 1. A user can create multiple user records/details. These records should include an account id, username, password, and a textual simple comment. Please persist all Account data to your datastore, and be sure to encrypt and Base64-encode each unique Account password while the data is at rest. (As a suggestion, you'll probably want to use the User's unique master password as the input for a SHA1-derived hash, which then serves as the key for the AES algorithm.) I hope that explanation wasn't too confusing - just remember back to the code we did in class, or come ask me.
> 2. There is natural relationship between Users and Accounts -> One-to-Many. Regardless of the type of datastore you choose, it would be nice if your code or schema somehow elegantly and inteligently leveraged this relationship. Just something to think about and explore as create your specific application design
> 3. A user should have a menu option allowing them to view all of the details of the all of the sub-account records/users they have created. A quick list display for all of the fields in each individual Account will be sufficient. While displaying this info, please display the password as actual unencrypted clear-text.

Be sure to show:
1. > a user accessing the application using the master password 
2. > a user adding one or more accounts, first by logging in via the master password, and then utilizing the unique credentials for each specific account they have created
3. > a user accessing and listing one or more previously stored account credentials (two separate runs of the application)

Learning Objectives
> Understand symmetric and asymmetric encryption.  Utilize encryption in an application context.
> To help get you acclimated to the end-result of this assignment, you may want to do some research on already-exisiting Password Vaults, such as BitWarden, and LastPass.