package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"
	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"

	// optional
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg
	// see someUsefulThings() below
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
/*func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
        var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
} */

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username string
	PrivKey userlib.PKEDecKey
	PrivSignKey userlib.DSSignKey
	MagicLinkEncryptor []byte
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}


type FilePointer struct {
	FileID uuid.UUID
}

type EncFileChain struct {
	EncFiles []FilePointer
	EncHMAC []byte
	OriginLoc map[uuid.UUID] uuid.UUID
}

func (efc *EncFileChain) verifyMAC(HMACKey []byte) bool {
	//Compute the checksum of the file
	arrStream,e := json.Marshal(efc.EncFiles)
	if (e != nil) {return false}
	fileChainHMAC,e := userlib.HMACEval(HMACKey, arrStream)
	if (e != nil) {return false}
	return userlib.HMACEqual(fileChainHMAC,efc.EncHMAC)
}

func (efc *EncFileChain) retrieveFile(index int) (EncFile, bool) {
	var retFile EncFile
	size := len(efc.EncFiles)
	if index >= size {return retFile, false}
	fileStream, e := userlib.DatastoreGet(efc.EncFiles[index].FileID)
	if (!e) {return retFile, false}
	err := json.Unmarshal(fileStream,&retFile)
	if (err != nil) {return retFile, false}
	return retFile,true
}

type EncFile struct {
	Encdata []byte
	EncHMAC []byte
}

func (ef *EncFile) store() FilePointer {
	fP := FilePointer{uuid.New()}
	EncFileStream,_ := json.Marshal(ef)
	userlib.DatastoreSet(fP.FileID,EncFileStream)
	return fP
}

func (ef *EncFile) verifyMAC(HMACkey []byte) bool {
	dataMAC,e := userlib.HMACEval(HMACkey,ef.Encdata)
	if (e != nil) {return false}
	return userlib.HMACEqual(dataMAC,ef.EncHMAC)
}

func (u *User) toByteStream() []byte {
	b,_ := json.Marshal(*u)
	return b
}


type MagicLink struct {
	LinkPointer uuid.UUID
	DBKey []byte
	FileChainKey []byte
	HMACKey []byte
	DataKey []byte
}

type sharedVector struct {
	EncMsg []byte
	EncKey []byte
	Signature []byte
}




// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

func getUserKeys(password string, username string) ([]byte, []byte, []byte,[]byte ) {
	hash := passwordKey(password, username)
	return hash[:16],hash[16:32],hash[32:48],hash[48:64]
}

func usernameToMapKey(username string) uuid.UUID {
	salt := "I am quite salty"
	hash:=userlib.Argon2Key([]byte(username),[]byte(salt),16)
	mapKey,_:= uuid.FromBytes(hash)
	return mapKey
}

func fileNameToLinkLoc(username string, filename string, fileKey []byte) uuid.UUID {
	hash:=userlib.Argon2Key([]byte(username), []byte(filename), 16)
	hash=userlib.Argon2Key(hash,fileKey ,16)
	hash=userlib.Argon2Key(fileKey,hash ,16)
	mapKey,_:= uuid.FromBytes(hash)
	return mapKey
}

func getFileHMACKey(username string, filename string, fileKey []byte) []byte {
	hash := passwordKey(username, filename)
	hash = userlib.Argon2Key(hash, fileKey, 16)
	hash,_ = userlib.HMACEval(hash, fileKey)
	return hash[:16]
}

func generate4RandomKeys() ([]byte, []byte, []byte,[]byte ) {
	hash:= userlib.Argon2Key(userlib.RandomBytes(64),userlib.RandomBytes(64),64)
	return hash[:16],hash[16:32],hash[32:48],hash[48:64]
}


/*func get8FileKeys(username string, filename string, fileKey []byte) ([]byte, []byte, []byte,[]byte,[]byte, []byte, []byte,[]byte) {
	hash := passwordKey(username, filename)
	hash = userlib.Argon2Key(hash, fileKey, 128)
	return hash[:16],hash[16:32],hash[32:48],hash[48:64],hash[64:80],hash[80:96], hash[96:112],hash[112:128]
} */


func passwordKey(password string, salt string) []byte {
	return userlib.Argon2Key([]byte(password), []byte(salt), 64)
}


func symmetricEnc(key []byte, plaintext []byte) []byte {
	IV := userlib.RandomBytes(16)
	return userlib.SymEnc(key,IV,plaintext)
}



// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {


	var userdata User
	userdataptr = &userdata
	//Generate secure keys from the User's Identification
	dbKey, dataKey,fileKey,HMACUser := getUserKeys(password, username)
	userUUID := bytesToUUID(dbKey)


	//Within the user, create a new public/private key pair and store it in the keystore
	pk, sk, _ := userlib.PKEKeyGen()
	e := userlib.KeystoreSet(username + "RSAKey", pk)
	if (e != nil) {return nil,e}

	PrivSK, PubSK, _ := userlib.DSKeyGen()
	e = userlib.KeystoreSet(username + "SIGNKey", PubSK)
	if (e != nil) {return nil,e}


	//Create the user
	userdata.Username = username
	userdata.MagicLinkEncryptor = userlib.Argon2Key(userlib.RandomBytes(64),fileKey,16)
	userdata.PrivKey = sk
	userdata.PrivSignKey = PrivSK

	//Encrypt user data using our generated Key
	userStream := userdata.toByteStream()
	encryptedStream := symmetricEnc(dataKey,userStream)

	userHMAC, e := userlib.HMACEval(HMACUser,encryptedStream)
	if (e != nil) {return nil, e}

	encryptedStream = append(userHMAC, encryptedStream...)

	//Create an entry in the data store, where the key is a UUID based on username/password
	userlib.DatastoreSet(userUUID, encryptedStream)

	//Return the user dataPointer
	return userdataptr, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//Compute the user's primary key
	dbKey, dataKey,_,HMACKey := getUserKeys(password, username)

	//Compute the UUID from the hash
	userUUID := bytesToUUID(dbKey)


	encryptedUserData, exists := userlib.DatastoreGet(userUUID)

	//If the user does not exist, or if the user/password combo is invalid,
	//we will return an error.
	if !exists { return nil, getUserError(0)}

	if len(encryptedUserData) < 64 {return nil, getUserError(1)}



	//Test if the HMAC hasn't changed
	HMAC := encryptedUserData[:64]
	encryptedUserData = encryptedUserData[64:]
	evaldHMAC,e  := userlib.HMACEval(HMACKey,encryptedUserData)
	if e!=nil { return nil, getUserError(0)}

	if !userlib.HMACEqual(HMAC,evaldHMAC) {return nil,getUserError(1)}


	//Decrypt user data using second key
	userStream := userlib.SymDec(dataKey,encryptedUserData)

	//Convert the data into a User struct
	e = json.Unmarshal(userStream,userdataptr)

	// If json cannot unmarshal this data, we assume it has been corrupted
	if (e != nil) {
		return nil, getUserError(1)
	}

	return userdataptr, nil
}


// This stores a file in the datastore.
//
// The name and length of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	//First we generate some keys to store the filename.
	// We assume the filename has too low of an entropy, so we must add some more entropy
	//If we use the username and part of the users passwordHash we should be okay
	HMACMLKey := getFileHMACKey(userdata.Username, filename, userdata.MagicLinkEncryptor)


	dbKey,dataKey,HMACKey,fileChainKey:= generate4RandomKeys()
	fileUUID := bytesToUUID(dbKey)

	//Now we must create some sort of checksum that ensures that
	//the file is not tampered with unless we want it to be
	EncFileData := symmetricEnc(dataKey,data)
	EncFileHash,_ := userlib.HMACEval(HMACKey,EncFileData)

	//Create an encrypted file dataType that includes the encrypted data
	//and an HMAC of the data for us to perform a checksum
	encryptedFile := EncFile{EncFileData,EncFileHash}
	EncFilePtr := encryptedFile.store()


	//Now we create a fileChain for subsequent appending
	var fPArr []FilePointer
	fPArr = append(fPArr, EncFilePtr)

	//Create an HMAC of the encrypted file Array
	arrStream,_ := json.Marshal(fPArr)
	fileChainHMAC,_ := userlib.HMACEval(HMACKey, arrStream)

	//Create the new File Chain struct with the array and its HMAC
	newfileChain := EncFileChain{fPArr,fileChainHMAC,make(map[uuid.UUID]uuid.UUID)}


	//Convert the fileChain struct into an array and then encrypt it
	newfileChainStream,_ := json.Marshal(newfileChain)

	EncFileChainStream := symmetricEnc(fileChainKey,newfileChainStream)


	userlib.DatastoreSet(fileUUID, EncFileChainStream)

	//Now we create a magic link for accessing the accounts.
	//This link must also be encrypted else people could redirect our access.
	linkLoc := fileNameToLinkLoc(userdata.Username, filename, userdata.MagicLinkEncryptor)

	//Finally we create a magicLink object with the necessary keys and we store it somewhere
	userMagicLink := MagicLink{fileUUID,dbKey,fileChainKey,HMACKey,dataKey}
	UMLStream,_ := json.Marshal(userMagicLink)
	EncUMLStream := symmetricEnc(userdata.MagicLinkEncryptor, UMLStream)
	HMACUML,_ := userlib.HMACEval(HMACMLKey,EncUMLStream)
	EncUMLStream = append(HMACUML,EncUMLStream...)
	userlib.DatastoreSet(linkLoc, EncUMLStream)
	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.


func (userdata *User) getFileMagicKey(filename string) (MagicLink, error) {

	var UML MagicLink
	linkLoc := fileNameToLinkLoc(userdata.Username, filename, userdata.MagicLinkEncryptor)

	HMACMLKey := getFileHMACKey(userdata.Username,filename,userdata.MagicLinkEncryptor)

	//Collect the encrypted user Magic Link to file
	encUML,exists := userlib.DatastoreGet(linkLoc)
	if (!exists) {return UML,LoadFileError(1)}

	if len(encUML) < 64 {return UML, getUserError(1)}


	//Test if the HMAC hasn't changed
	HMAC := encUML[:64]
	encUML = encUML[64:]
	evaldHMAC,e  := userlib.HMACEval(HMACMLKey,encUML)
	if e!=nil { return UML, getUserError(0)}

	if !userlib.HMACEqual(HMAC,evaldHMAC) {return UML,getUserError(1)}


	//Decrypt UML
	UMLStream := userlib.SymDec(userdata.MagicLinkEncryptor, encUML)
	//Collect into a magic link struct

	e = json.Unmarshal(UMLStream,&UML)
	if (e != nil) {return UML, LoadFileError(1)}

	return UML,nil

}

func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	UML,e := userdata.getFileMagicKey(filename)
	if (e != nil) {return e}

	//Obtain necessary keys
	dbKey := UML.DBKey
	dataKey := UML.DataKey
	HMACKey := UML.HMACKey
	fileChainKey := UML.FileChainKey
	fileUUID := bytesToUUID(dbKey)

	//load the current file chain, which doesn't actually contain any fileData, just pointers to chunks
	fileChain,e := loadFileChain(fileChainKey,HMACKey,fileUUID)
	if (e != nil) {return e}

	//Create a new encrypted file with a new HMAC by:
	//encrypting the data
	encData := symmetricEnc(dataKey,data)
	//Computing an HMAC for this encrypted data
	dataHMAC,e := userlib.HMACEval(HMACKey,encData)
	if (e != nil) {return e}
	//Placing both slices into a new encrypted file
	encryptedFile := EncFile{encData,dataHMAC}

	//Now we update the fileChain and recompute the HMAC of the fileChain
	fP := encryptedFile.store();
	fileChain.EncFiles = append(fileChain.EncFiles, fP)
	ptrArrayStream,e := json.Marshal(fileChain.EncFiles)
	if (e != nil) {return e}
	fileChain.EncHMAC,e = userlib.HMACEval(HMACKey,ptrArrayStream)
	if (e != nil) {return e}

	//now we have to store our fileChain again
	newfileChainStream,_ := json.Marshal(fileChain)
	EncFileChainStream := symmetricEnc(fileChainKey,newfileChainStream)
	userlib.DatastoreSet(fileUUID, EncFileChainStream)
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.


//Loads and decrypts a file chain given the necessary access keys
func loadFileChain(fileChainKey []byte, HMACKey []byte, fileUUID uuid.UUID) (EncFileChain,  error) {

	var fileChain EncFileChain
	EncFileChainStream, exists := userlib.DatastoreGet(fileUUID)

	if (!exists) {
		return fileChain,LoadFileError(0)
	}

	//Decrypt the file
	fileChainStream := userlib.SymDec(fileChainKey, EncFileChainStream)

	//Transfer our fileChainStream into a struct

	e := json.Unmarshal(fileChainStream,&fileChain)
	if (e != nil) {return fileChain,LoadFileError(1)}

	//Verify that the array of pointers hasn't been trifled with
	bool := fileChain.verifyMAC(HMACKey)
	if (!bool) {return fileChain, LoadFileError(1)}

	return fileChain,nil
}



func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	if (userdata == nil) {
		return nil,errors.New("user don't exist")
	}

	UML,e := userdata.getFileMagicKey(filename)
	if (e != nil) {return nil, e}

	dbKey := UML.DBKey
	dataKey := UML.DataKey
	HMACKey := UML.HMACKey
	fileChainKey := UML.FileChainKey

	fileUUID := bytesToUUID(dbKey)


	fileChain,e := loadFileChain(fileChainKey,HMACKey,fileUUID)
	if (e != nil) {return nil,e}

	//Create an array for us to return
	var fileData []byte

	for i := range fileChain.EncFiles {
		eF,exists := fileChain.retrieveFile(i)
		if (!exists) {return nil, LoadFileError(1)}
		unTampered := eF.verifyMAC(HMACKey)
		if (!unTampered) {return nil, LoadFileError(1)}
		fileChunkStream := userlib.SymDec(dataKey, eF.Encdata)
		fileData = append(fileData,fileChunkStream...)
	}

	//fmt.Println("The file data is")
	//fmt.Println(string(fileData[:len(fileData)]))

	return fileData, nil
}


// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	UML,e := userdata.getFileMagicKey(filename)
	if (e != nil) { return "",e}



	//Locate the recipient's public key for data encryption use
	recPubK,exists := userlib.KeystoreGet(recipient + "RSAKey")
	if (!exists) { return "", errors.New("Couldn't locate recipient")}


	//Now we create a full new Magic Key for the guest

	/*dbKeyRec := UML.DBKey
	dataKeyRec := UML.DataKey
	fileChainKey := UML.FileChainKey
	HMACKeyRec := UML.HMACKey
	LinkPtrRec := UML.HMACKey

	LinkPointer uuid.UUID
	DBKey []byte
	FileChainKey []byte
	HMACKey []byte
	DataKey []byte */



	//Create a location and a decryption key for the recipients magic key
	location := userlib.RandomBytes(16)
	locUUID,_ := uuid.FromBytes(location)
	accessKey := userlib.RandomBytes(16)
	HMACMLKey := userlib.RandomBytes(16)


	recMLStream,_ := json.Marshal(UML)
	encRML := symmetricEnc(accessKey,recMLStream)
	encMLHMAC,_ := userlib.HMACEval(HMACMLKey, encRML)

	encRML = append(encMLHMAC,encRML...)
	userlib.DatastoreSet(locUUID, encRML)


	//Now we have to send the key and the location to the recipient
	//We do this by first combining the arrays, then encrypting
	msg := append(location, accessKey...)
	msg = append(msg,HMACMLKey...)

	//We will send 3 packages:

	//The message encrypted with a session key
	sessionKey := userlib.RandomBytes(16)
	encMsg := symmetricEnc(sessionKey,msg)

	//The session key encrypted with the public key
	encSesKey,e := userlib.PKEEnc(recPubK, sessionKey)
	if (e != nil) {return "",errors.New("Unable to perform public key encryption")}


	//And an a hash verification
	signature,_:= userlib.DSSign(userdata.PrivSignKey, msg)

	vector := sharedVector{encMsg, encSesKey, signature}

	vectorStream,e := json.Marshal(vector)
	if (e != nil) {return "",errors.New("Unable to marshall the message")}

	return string(vectorStream),nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {


	//First we unpack the magic string that the sender gave us
	location,accessKey,HMACMLKey,e := userdata.unpackMagicString(sender, magic_string)
	if (e != nil) {return e}


	//Now we know we have received a correct magic link, so we can do some stuff with it


	//First we decrypt the magic Link
	encML,exists := userlib.DatastoreGet(location)
	if (!exists) {return LoadFileError(1)}

	if len(encML) < 64 {return getUserError(1)}

	//Test if the HMAC hasn't changed
	HMAC := encML[:64]
	encML = encML[64:]
	evaldHMAC,e  := userlib.HMACEval(HMACMLKey,encML)
	if e!=nil { return getUserError(0)}
	if !userlib.HMACEqual(HMAC,evaldHMAC) {return getUserError(1)}


	MLStream := userlib.SymDec(accessKey,encML)
	var senderML MagicLink
	e = json.Unmarshal(MLStream, &senderML)
	if (e != nil) {return e}

	//Then we collect the keys to make our own magic Link
	fileChainLoc := senderML.LinkPointer
	fileChainKey := senderML.FileChainKey
	HMACKey := senderML.HMACKey
	dBKey := senderML.DBKey
	dataKey := senderML.DataKey


	_, e = userdata.getFileMagicKey(filename)
	if (e == nil) {return errors.New("Filename already exists under this user")}

	//We compute the location of the receiver's Magic link
	linkLoc := fileNameToLinkLoc(userdata.Username, filename, userdata.MagicLinkEncryptor)


	//We load the file Chain, decrypt it, and add an entry to the origin locations that
	//points to the user's created magic link
	fileChain, e := loadFileChain(fileChainKey,HMACKey,fileChainLoc)
	if (e != nil) {return e}
	fileChain.OriginLoc[usernameToMapKey(userdata.Username)] = linkLoc


	//Now we must restore the fileChain
	newfileChainStream,_ := json.Marshal(fileChain)
	EncFileChainStream := symmetricEnc(fileChainKey,newfileChainStream)
	userlib.DatastoreSet(fileChainLoc, EncFileChainStream)

	//Finally we create a new magic link for this file for the user, and we store it
	newMagicLink := MagicLink{fileChainLoc, dBKey,fileChainKey, HMACKey, dataKey}
	UMLStream,e := json.Marshal(newMagicLink)
	if (e != nil) {return e}
	EncUMLStream := symmetricEnc(userdata.MagicLinkEncryptor, UMLStream)
	HMACMLKey = getFileHMACKey(userdata.Username,filename, userdata.MagicLinkEncryptor)

	HMACML,_ := userlib.HMACEval(HMACMLKey, EncUMLStream)

	EncUMLStream = append(HMACML,EncUMLStream...)
	userlib.DatastoreSet(linkLoc, EncUMLStream)
	return nil
}


func (userdata *User) unpackMagicString(sender string, magic_string string) (uuid.UUID, []byte ,[]byte, error) {

	errorID := uuid.New();

	recPrivK := userdata.PrivKey
	vectorStream:= []byte(magic_string)

	var vector sharedVector
	e := json.Unmarshal(vectorStream, &vector)
	if (e != nil) {return errorID,nil,nil,e}

	//We collect the necessary information from the magic string
	encMsg := vector.EncMsg
	encSesKey := vector.EncKey
	signature := vector.Signature

	//First let's decrypt the session key
	sesKey,e := userlib.PKEDec(recPrivK, encSesKey)
	if (e != nil) {return errorID, nil,nil,e}
	//Now we can decrypt the message
	msg := userlib.SymDec(sesKey, encMsg)

	//And finally we verify it is the correct message
	//For this we need to cop the sender's key:
	senderSPK,exists := userlib.KeystoreGet(sender + "SIGNKey")
	if (!exists) {return errorID,nil,nil, errors.New("Sender's public key couldn't be located")}
	e = userlib.DSVerify(senderSPK, msg, signature)
	if (e != nil) {return errorID,nil,nil, e}


	location := msg[:16]
	locUUID,_ := uuid.FromBytes(location)
	accessKey := msg[16:32]
	HMACMLKey := msg[32:48]

	return locUUID,accessKey,HMACMLKey,nil

}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {

	//My design has the advantage that it's very easy to revoke access to files
	//So lets do it
	//First we unpack the magic link
	ownerML, e:= userdata.getFileMagicKey(filename)
	if (e != nil) {return e}

	//So now we just load the file chain and delete that stuff
	fileChain, e := loadFileChain(ownerML.FileChainKey, ownerML.HMACKey, ownerML.LinkPointer)
	if (e != nil) {return e}

	//First assert that we are the user
	_,exists := fileChain.OriginLoc[usernameToMapKey(userdata.Username)]
	if (exists) {return errors.New("You aren't the owner of this file punk")}

	//Then we go and delete the target username

	//First we cop the magic link's location
	targetLink,exists := fileChain.OriginLoc[usernameToMapKey(target_username)]
	if (!exists) {return errors.New("The target_user doesn't have access")}
	//Then we delete him from the origins
	delete(fileChain.OriginLoc, usernameToMapKey(target_username))
	//Finally we delete his magic link in the database
	userlib.DatastoreDelete(targetLink)

	//Now he aint got access no more
	return
}


func getUserError(e int) error {
	if (e == 0) {
		return errors.New(strings.ToTitle("User could not be located in the system"))
	} else {
		return errors.New(strings.ToTitle("UserData was corrupted"))
	}

}

func LoadFileError(e int) error {
	if (e == 0) {
		return errors.New(strings.ToTitle("File could not be located in the system"))
	} else {
		return errors.New(strings.ToTitle("File was corrupted"))
	}

}



