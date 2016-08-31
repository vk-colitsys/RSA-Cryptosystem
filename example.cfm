
<!--- The RSACrypt component expects to find the bouncyCastle Crypto API in 
the server.javaLoader instance (http://javaloader.riaforge.org/) . You need to create an instance of the javaLoader and provide it
with the path to the bouncyCastle JAR (bcprov-jdk16-145.jar). Below is an example of  this:

<cflock scope="server" type="exclusive" timeout="1">
 <cfset loadPaths = ['bcprov-jdk16-145.jar']>
 <cfset server.javaLoader = createObject('component', 'JavaLoader').init(loadPaths)>
</cflock>
--->

<!--- load the CFC into the application scope --->
<cfset application.util = {}>
<cfset application.util.RSACrypt = createObject("component", "RSACrypt").init()>

<!--- create key pair. Change 'string' to 'java' to 
return the java instance of the public/private key pair. The results of this
call can be written to a database/file since they are strings --->
<cfset keys = application.util.RSACrypt.generateKeys(512,'string')>
<cfdump var="#keys#" label="Keys">

<!--- encrypt a string using the public key --->
<cfset theString 		= 'This is my password dude!'>
<cfset encryptedString 	= application.util.RSACrypt.encrypt(theString,keys.publicKey)>
<cfdump var="#encryptedString#" label="Encrypted String">

<!--- decrypt the string using the private key --->
<cfset decryptedString 	= application.util.RSACrypt.decrypt(encryptedString,keys.privateKey)>
<cfdump var="#decryptedString#" label="Decrypted String">


