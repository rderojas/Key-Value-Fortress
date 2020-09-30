package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"github.com/cs161-staff/userlib"
	_ "github.com/google/uuid"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"
)


func TestInit(t *testing.T) {

	t.Log("Initialization test")
	// You may want to turn it off someday
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	u2,err2 := InitUser("Ram","Bernabeu123")
	if err2 != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u3,err3 := InitUser("Pat","OSullivan")
	if err3 != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	t.Log("Got user", u2)
	t.Log("Got user", u3)
}


func TestInitUsersWithSamePassword(t *testing.T) {
	uInit,_ := InitUser("user1", "copycat")
	vInit,_ := InitUser("user2", "copycat")


	u,e := GetUser("user1", "copycat")
	if e!= nil { t.Error("Failed to get user", e); return }
	if (!reflect.DeepEqual(u,uInit)) { t.Error("Not the same", e); return }
	v,e := GetUser("user2", "copycat")
	if (!reflect.DeepEqual(v,vInit)) { t.Error("Not the same", e); return }
	if (reflect.DeepEqual(u,v)) { t.Error("Different users are equivalent", e); return }
}


func TestInitMultipleUsers(t *testing.T) {
	NUMUSERS := 20
	for i := 0; i < NUMUSERS; i++ {
		username := string(i)
		password := string(i + 16)
		_,e := InitUser(username, password)
		if e!= nil { t.Error("Failed to initialize user", e); return }
	}
	t.Log("All Users have been initialized")

	for i:= 0; i < NUMUSERS; i++ {
		username := string(i)
		password := string(i + 16)
		_,e := GetUser(username,password)
		if e!= nil { t.Error("Failed to initialize user", e); return }
	}

	t.Log("All users were loaded")
}


func getIthUser(i int) (*User, error) {
	username := string(i)
	password := string(i + 16)
	u,e :=GetUser(username,password)
	return  u,e
}

func getIthUserName(i int) (string) {
	return string(i)
}

func TestStoreMultipleFiles(t *testing.T) {
	NUMUSERS := 20

	//Get all the users, and get them to store the same fileNames
	//We will also make each
	for i := 0; i < NUMUSERS; i++ {
		username := string(i)
		password := string(i + 16)
		u,e := GetUser(username, password)
		if e!= nil { t.Error("Failed to get user", e); return }
		u.StoreFile("testFile", []byte(string(i+420)))
	}

	t.Log("Saved all the files")

	//Now we will see if each of them has their own file
	for i := 0; i < NUMUSERS; i++ {
		username := string(i)
		password := string(i + 16)
		u,e := GetUser(username, password)
		if e!= nil { t.Error("Failed to get user", e); return }
		f,e := u.LoadFile("testFile")
		if e!= nil { t.Error("Was unable to load the file", e); return }
		if (!reflect.DeepEqual(f,[]byte(string(i+420)))) {
			t.Error("Files don't match", e)
		}

		t.Log("All the files match")
	}


}

func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)


	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestLoadNilUser(t *testing.T) {

	var userdata User

	_,e := userdata.LoadFile("AnyFile")
	if (e == nil)  { t.Error("Loaded File from nil user", e); return }

}

func TestAppend(t *testing.T) {
	//u, err := InitUser("Ram", "Bernabeu123")
	u,err := GetUser("Ram", "Bernabeu123")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)


	filename := "fileAppend"

	//Creating and saving a file associated with Ram
	fa1 := []byte("This is part1 of the file.")
	u.StoreFile(filename, fa1)

	//Checking file can be retrieved and hasn't been saved
	retfile,e := u.LoadFile(filename)


	if (!reflect.DeepEqual(retfile,fa1)) {
		t.Error("Failed to load file", err)
		return
	}

	fa2 := []byte("This is part2 of the file")
	e = u.AppendFile(filename ,fa2)
	if e != nil {
		t.Error("Append operation failed", e)
		return
	}

	t.Log("Appended File Succesfully", fa2)

	faComplete := append(fa1, fa2...)
	retfile,_ = u.LoadFile(filename)
	if (!reflect.DeepEqual(retfile, faComplete)) {
		t.Error("Failed to append correctly/return appended file correctly", err)
		return
	}

	t.Log("Retrieved Correct File")









}


func TestShareChain(t *testing.T) {


	NUMUSERS := 20
	_,e := InitUser("src", "KennethIsStupidAndIhateHim")
	if e!= nil { t.Error("Failed to initialize user", e); return }
	src,e := GetUser("src", "KennethIsStupidAndIhateHim")
	if e!= nil { t.Error("Failed to initialize user", e); return }

	//Storing the file to be shared in a chain
	fileData := []byte("This is the file")
	src.StoreFile("chainFile" + string(0), fileData)


	//Testing if we can perform a sharing "chain", where a user shares
	//File with the next person
	sender := src
	senderUsername := "src"
	for i := 0; i < NUMUSERS; i++ {
		receiver,e := getIthUser(i)
		rcvrUserName := getIthUserName(i)
		if e!= nil { t.Error("Failed to get user", e); return}
		magicString,e := sender.ShareFile("chainFile" + string(i), rcvrUserName)
		if e!= nil { t.Error("Failed to share file", e); return}
		e = receiver.ReceiveFile("chainFile" + string(i+1),senderUsername,magicString)
		if e!= nil { t.Error("Failed to receive file", e); return}
		f,e := receiver.LoadFile("chainFile" + string(i+1))
		if e!= nil { t.Error("Failed to load shared file", e); return}
		if (!reflect.DeepEqual(f,fileData)) { t.Error("File Data has been corrupted and we never realized", e); return}
		sender = receiver
		senderUsername = rcvrUserName
	}

	t.Log("Shared the file effectively between ppl")
}


func TestRevocationErrors(t *testing.T) {


	//This tests revoking a file u aint got access to
	pretendRevoker,e := getIthUser(0)
	if e!= nil {t.Error("Failed to get user",e ); return}
	targetFileName := "FakeFile"
	e=pretendRevoker.RevokeFile(targetFileName,string(0))
	if (e == nil)  {t.Error("This mans revoked acces, wasn't owner", e); return}
	e=pretendRevoker.RevokeFile(targetFileName,string(1))
	if (e == nil)  {t.Error("This mans revoked acces, wasn't owner", e); return}

}


func TestRevocation(t *testing.T) {


	//First we will test that a user who isnt the owner
	//cannot revoke access to the file

	pretendRevoker,e := getIthUser(0)
	if e!= nil { t.Error("Failed to get user", e); return}
	targetFileName := "chainFile" + string(0+1) //Name of that user's file

	NUMUSERS := 20

	for i:=0; i < NUMUSERS;i++ {
		target_username := string(i)
		e:=pretendRevoker.RevokeFile(targetFileName,target_username)
		if (e == nil) {t.Error("This mans revoked acces, wasn't owner", e); return}
	}

	//Now we will test that the owner can revoke access for the file
	src,e := GetUser("src", "KennethIsStupidAndIhateHim")
	if e!= nil { t.Error("Failed to get user", e); return}

	origFileName := "chainFile" + string(0)

	//Now we will attempt to revoke access for all of these users
	for i := 0; i < NUMUSERS; i++ {
		target_username := string(i)
		e :=src.RevokeFile(origFileName,target_username)
		if e!= nil { t.Error("Failed to revoke access to the target user", e); return}
	}
	//Now we check if the children have access
	for i := 0; i < NUMUSERS; i++ {
		u,e := getIthUser(i)
		if e!= nil { t.Error("Failed to get user", e); return}
		_,e = u.LoadFile("chainFile" + string(i+1))
		if (e == nil) { t.Error("revoked user managed to access file.", e); return}
		e = u.AppendFile("chainFile" + string(i+1), []byte("I hate writing tests "))
		if (e == nil) { t.Error("revoked user managed to append file.", e); return}
	}


	//Revoke access to a file you don't have access to
	e = src.RevokeFile("nonExistent", getIthUserName(10))
	if (e == nil) { t.Error("revoked access to a non existent file .", e); return}


	//Revoke access to a file from a user that doesn't have access
	e = src.RevokeFile("chainFile"+ string(0), getIthUserName(10))

}

func TestSharingIncorrectly(t *testing.T) {

	u, e := InitUser("Felipe", "Cook")
	if e!= nil { t.Error("Failed to init user", e); return }

	//Now we init two users
	v1, e := InitUser("Evan", "Can Eat Gluten")
	v2, e:= InitUser("Shane", "Cannot Eat Gluten")

	u.StoreFile("Gluten", []byte("In mah beer"))

	//Trying to share with a user that doesn't exist
	_,e = u.ShareFile("Gluten", "Calvin")
	if e== nil { t.Error("Shared with non existent user", e); return }

	//Trying to share a file that doesn't exist with a real user
	_,e = u.ShareFile("U ever done DMT?","Evan")
	if e== nil { t.Error("Shared non existent file", e); return }


	//Sharing file correctly
	mS, e := u.ShareFile("Gluten","Evan")
	if e!= nil { t.Error("Failed to share file", e); return }

	//Receiving a file correctly
	e = v1.ReceiveFile("Brewski", "Felipe", mS)
	if e!= nil { t.Error("Couldn't receive file", e); return }

	//Assert Evan can load the file
	_,e = v1.LoadFile("Brewski")
	if e!= nil { t.Error("Couldn't open shared file", e); return }

	//Receiving a file that isn't for u
	e = v2.ReceiveFile("Brewski", "Felipe", mS)
	if e== nil { t.Error("Received File not meant for u", e); return }

	//Receiving a file that is for u but from a user that doesn't exist
	e = v1.ReceiveFile("Patfile", "MRWANG", mS)
	if e== nil { t.Error("Received File not meant for u", e); return }

	randomMS := "This program is rated ML for mature language, viewer discretion advised"
	e = v2.ReceiveFile("Brewski", "Felipe", randomMS)
	if e== nil { t.Error("We got serious issues", e); return }


	//Now we try to share a file that the receiver already has
	u.StoreFile("existent", []byte("argon2Key"))
	mS, e = u.ShareFile("existent", "Shane")
	v2.StoreFile("existent", []byte("Lawler"))
	e = v2.ReceiveFile("existent", "Felipe", mS)
	if (e == nil) { t.Error("Accepted file we already have", e); return }

	//Let's try to get the receiver to receive the same file twice
	e = v2.ReceiveFile("existent2", "Felipe", mS)
	if (e != nil) { t.Error("Receiving Errror", e); return }
	e = v2.ReceiveFile("existent2", "Felipe", mS)
	if (e == nil) { t.Error("Accepted file we already have", e); return }


}

func TestShareAndAppend(t *testing.T) {

	NUMUSERS := 20

	src,e := GetUser("src", "KennethIsStupidAndIhateHim")
	if e!= nil { t.Error("Failed to get user", e); return}

	fileData := "a"
	src.StoreFile("Appendable", []byte("a"))

	//Now we will share a file that will be appended by everyone
	for i := 0; i < NUMUSERS; i++ {
		receiver, e := getIthUser(i)
		rcvrUserName := getIthUserName(i)
		rcvrFileName := "Appendable" + string(i)

		if e != nil { t.Error("Failed to get user", e); return }
		magicString, e := src.ShareFile("Appendable", rcvrUserName)
		if e!= nil { t.Error("Failed to share file", e); return}
		e = receiver.ReceiveFile(rcvrFileName, "src", magicString)
		if e != nil { t.Error("Failed to receive file", e);return}
		e = receiver.AppendFile(rcvrFileName, []byte("a"))
		fileData = fileData + "a"

		//We will load the file from the childs prespective
		cf,e := receiver.LoadFile(rcvrFileName)
		cfS := string(cf)
		if (!reflect.DeepEqual(fileData,cfS)) { t.Error("Appending failed");return}

		//Now we load the file from the parent's prespective
		of, e := src.LoadFile("Appendable")
		ofS := string(of)
		if (!reflect.DeepEqual(fileData,ofS)) { t.Error("Appending failed", e);return}
	}
}

func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	var v, v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}


func TestErrors(t *testing.T) {

	//Init same user twice
	u,e := InitUser("Fortnite", "Dance")
	if e!=nil {t.Error("Couldn't init"); return}


	v,e := GetUser("Fortnite", "Dance")
	if e!=nil {t.Error("Couldn't get user"); return}

	if (!reflect.DeepEqual(u, v)) {t.Error("users is different"); return}


	//load non-existent user:
	_,e = GetUser("MrPat", "pooop")
	if (e == nil) {t.Error("Initialized a fake user"); return}


	_, e = GetUser("Pat", "OSUllieven")
	if e == nil { t.Error("Wrong password was entered", e); return }

}

//This goes at the end because I will probably be corrupting a lot of stufff
func TestDataCorruption(t *testing.T) {


	//Get a user
	src,e := GetUser("src", "KennethIsStupidAndIhateHim")
	_,e = GetUser(string(10), string(10 + 16))
	if e!=nil {t.Error("Couldn't get user"); return}
	_,e = src.LoadFile("chainFile" + string(0))
	if e!=nil {t.Error("Couldn't get file"); return}

	//Now corrupt the entire data store and check if we still can find files associated with him
	dataStore := userlib.DatastoreGetMap()
	for k,_ := range dataStore {
		dataStore[k] = userlib.RandomBytes(221)
	}

	//Now we try loading the file again
	_,e = src.LoadFile("chainFile" + string(0))
	if (e==nil) {t.Error("File should not be recoverable")}


	_,e = src.ShareFile("chainFile" + string(0), string(10))
	if e == nil {t.Error("File should not be sharable")}



	//Now we try loading a user again
	_,e = GetUser(string(10), string(10 + 16))
	if e == nil {t.Error("User should not be recoverable")}


	_,e = InitUser("Corruptible", "Pat")
	if e != nil {t.Error("User could not be loaded")}



	//Now we corrupt this specific user
	for k,_ := range dataStore {
		if len(dataStore[k]) > 300 {
			dataStore[k] = userlib.RandomBytes(5889)
			break;
		}
	}

	//And we check if we can access the user
	_,e = GetUser("Corruptible", "Pat")
	if e == nil {t.Error("Got corrupted user")}



	//Delete the whole dataStore
	userlib.DatastoreClear();



	//Now we are going to initialize a user, and store a file with the user, and see if it gets stuff wrong
	u,_ := InitUser("newUser", "SImon says")
	u.StoreFile("fileName", []byte("Pat Sucks"))


	//We now have a far smaller data store
	dataStore = userlib.DatastoreGetMap()
	for k,_ := range dataStore {
		if len(dataStore[k]) < 180 {
			dataStore[k] = userlib.RandomBytes(5889)
			break;
		}
	}

	_,e = u.LoadFile("fileName")
	if e == nil {t.Error("Got corrupted file")}

	//Userlength := 5889 characters


}


