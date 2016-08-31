<cfcomponent name="RSACrypt" output="false"  hint="Encryption, decryption and key generation using RSA chiper library. Note, this library uses the bouncyCastle (www.bouncycastle.org) Crypto API to generate the public and private key pair">
	
	
	<!--- Constructor Method --->
	<cffunction name="init" access="public" output="false" returntype="RSACrypt"  hint="Constructor function for RSACrypt Component">	
		<cfreturn this>
	</cffunction>
	
	<cffunction name="generateKeys" access="public" returntype="struct" output="false" hint="Returns a structure with the public and private key pair.">
		<cfargument name="keylength" 	type="numeric" default="512" hint="The key size" />
		<cfargument name="returnAs" 	type="string" default="string"	hint="String or Java. Return the base64 encoded strings, or the java instances of the public and private key pair"/>
		
			<cfset var result 			= {}>
			<cfset var kpgo				= ''>
			<cfset var kpg				= ''>
			<cfset var sr				= ''>
			<cfset var kp				= ''>
			
			<!--- create the return object --->
			<cfset result['privateKey'] = ''>
			<cfset result['publicKey'] 	= ''>
			
			<cfif not structKeyExists(server,'javaLoader')>
				<cfthrow message="The RSACrypt Component requires the JavaLoader Class and BouncyCastle Crypto API. No JavaLoader detected in the server scope.">
			</cfif>
			
			<!--- Get the Bouncy Castle Asymmetric Key Generator. Note, we're using the server.javaLoader class to create the new instance.
			See http://www.compoundtheory.com/?action=displayPost&ID=212) for more information on the javaloader --->
			<cftry>
				<cfset kpgo = server.javaLoader.create("org.bouncycastle.jce.provider.asymmetric.ec.KeyPairGenerator")/>
				
				<cfcatch>
					<cfthrow message="BouncyCastle Crypto API not found in server.javaloader. See http://www.compoundtheory.com/?action=displayPost&ID=212 and www.bouncycastle.org.">
				</cfcatch>
			
			</cftry>
			<!--- Get an instance of the provider for the RSA algorithm. --->
			<cfset kpg = kpgo.getInstance("RSA") />
			<!--- Get an instance of secureRandom, we'll need this to initialize the key generator --->
			<cfset sr = createObject('java', 'java.security.SecureRandom').init() />
			<!--- Initialize the generator by passing in the size of key we want, and a strong pseudo-random number generator (PRNG) --->
			<cfset kpg.initialize(arguments.keylength, createObject('java', 'java.security.SecureRandom')) />
			<!--- This will create two keys, one public, and one private --->
			<cfset kp = kpg.generateKeyPair() />
			
			<!--- Get the two keys. --->
			<cfset result['privateKey'] = kp.getPrivate()>
			<cfset result['publicKey'] 	= kp.getPublic()>
			
			<!--- convert to strings if requested --->
			<cfif arguments.returnAs is 'string'>
				<cfset result['privateKey'] = toBase64(result['privateKey'].getEncoded())>
				<cfset result['publicKey'] 	= toBase64(result['publicKey'].getEncoded())>
			</cfif>
			
		<cfreturn result>
	</cffunction>
	
	<cffunction name="encrypt" access="public" returntype="Any" output="false">
	    <!--- Take in the string to encrypt and the key to encrypt with --->
	    <cfargument name="inputString" 	type="string" />
	    <cfargument name="key" 			type="any" hint="Java instance, a binary object or base64 encoded string"/>
		<cfargument name="returnAs" 	type="string" default="string"	hint="string or binary"/>
		 
			<cfset var keyBinary 		= ''>
			<cfset var pubKeySpec 		= ''>
			<cfset var factory 			= ''>
			<cfset var cipher			= ''>
			<cfset var encMode			= ''>
			<cfset var encryptedValue	= ''>
			<cfset var stringBytes		= ''>
			
			<!--- Create a Java Cipher object and get a mode --->
		    <cfset cipher = createObject('java', 'javax.crypto.Cipher').getInstance("RSA") />
		    <!--- The mode tells the Cipher whether is will be encrypting or decrypting --->
		    <cfset encMode = cipher.ENCRYPT_MODE />
		    

			<!--- if the key is not a public key instance, create the key from the base64 encoded string --->
			<cfif not isObject(arguments.key)>
				<cfif not isBinary(arguments.key)>
					<cfset keyBinary = toBinary(arguments.key)>
						<cfelse>
					<cfset keyBinary = arguments.key>
				</cfif>
				
				<!--- create public key instance --->
				<cfset pubKeySpec   	= createObject("java", "java.security.spec.X509EncodedKeySpec").init(keyBinary) /> 
				<cfset factory     		= createObject("java", "java.security.KeyFactory").getInstance("RSA") /> 
				<cfset arguments.key    = factory.generatePublic(pubKeySpec) /> 
				
			</cfif>
			
		    <!--- Initialize the Cipher with the mode and the key and encrypt the string --->
		    <cfset cipher.init(encMode, arguments.key) />
		    <cfset stringBytes = arguments.inputString.getBytes("UTF8") />
		    <cfset encryptedValue = cipher.doFinal(stringBytes, 0, len(arguments.inputString)) />
		    
			<!--- convert to base 64 if a string is requested --->
			<cfif arguments.returnAs is 'string'>
				<cfset encryptedValue = toBase64(encryptedValue)>
			</cfif>
			
		   <cfreturn encryptedValue>
	</cffunction>
	
	
	<cffunction name="decrypt" access="public" returntype="Any" output="false">
	    <!--- takes in the encrypted bytes and the decryption key --->
	    <cfargument name="input" 	type="any" hint="The string or binary object to decrypt">
	    <cfargument name="key" 		type="any" hint="Java instance, a binary object or base64 encoded string">
	    
			<cfset var cipher 			= ''>
		    <cfset var decMode 			= ''>
		    <cfset var returnString 	= ''>
			<cfset var keyBinary 		= ''>
			<cfset var privateKeySpec 	= ''>
			<cfset var factory 			= ''>
				
				<!--- convert value to decode from string to binary if
				its not provided in binary format --->
				<cfif not isBinary(arguments.input)>
					<cfset arguments.input = toBinary(arguments.input)>
				</cfif>
				
				<!--- if the key is not a private key instance, create the key from the base64 encoded string --->
				<cfif not isObject(arguments.key)>
					<cfif not isBinary(arguments.key)>
						<cfset keyBinary = toBinary(arguments.key)>
							<cfelse>
						<cfset keyBinary = arguments.key>
					</cfif>
				
					<!--- create public key instance --->
					<cfset privateKeySpec   = createObject("java", "java.security.spec.PKCS8EncodedKeySpec").init(keyBinary) /> 
					<cfset factory      	= createObject("java", "java.security.KeyFactory").getInstance("RSA") /> 
					<cfset arguments.key    = factory.generatePrivate(privateKeySpec) /> 
				
				</cfif>
					
	
			    <!--- Create a Java Cipher object and get a mode and do decyption --->
			    <cfset cipher = createObject('java', 'javax.crypto.Cipher').getInstance("RSA") />
			    <cfset decMode = cipher.DECRYPT_MODE />  
			    <cfset cipher.init(decMode, arguments.key) />
			    <cfset returnString = cipher.doFinal(arguments.input, 0, len(arguments.input)) />
		
		<!--- Convert the bytes back to a string and return it --->
	    <cfreturn toString(returnString, "UTF8") />

	</cffunction>

</cfcomponent>