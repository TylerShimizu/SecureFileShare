package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username        string
	Password        string
	Rsa_private_key userlib.PKEDecKey
	Signing_key     userlib.DSSignKey

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type Tree struct {
	Username     string
	File_pointer userlib.UUID
	HmacKey      []byte
	Invited      []Tree
	Accepted     bool
	Parent       string
}

type File_Struct struct {
	Head       userlib.UUID
	Share_tree Tree
	HmacKey    []byte
}

type File_content struct {
	Content     userlib.UUID
	Last_append userlib.UUID
	SymmKeyNext []byte
	HmacNext    []byte
	HmacKey     []byte
}

type Invitation struct {
	Pointer        uuid.UUID
	EncrytedSymKey []byte
}

type FilePointer struct {
	Pointer         uuid.UUID
	EncryptedSymKey []byte
	HMacKey         []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	len_username := len(username)
	if len_username == 0 {
		return &userdata, errors.New("password length must be greater than 0")
	} else {
		hashed_username := userlib.Hash([]byte(username))
		uuid, err := uuid.FromBytes(hashed_username[:16])
		if err == nil {
			_, exists := userlib.DatastoreGet(uuid)
			if exists {
				return &userdata, errors.New("a user with this username already exists")
			} else {
				//hashed_password := userlib.Hash([]byte(password))
				userdata.Username = username
				userdata.Password = password

				var pk userlib.PKEEncKey
				var sk userlib.PKEDecKey
				pk, sk, err = userlib.PKEKeyGen()
				if err != nil {
					fmt.Println("There was a problem in generating the rsa keys")
				}
				userdata.Rsa_private_key = sk

				pk_name := userlib.Hash([]byte(username + "-PEK")) //PEK = Public Encryption Key
				err = userlib.KeystoreSet(string(pk_name), pk)
				if err != nil {
					fmt.Println("There was a problem in storing the RSA Public Key")
				}

				var vk userlib.DSVerifyKey
				var signk userlib.DSSignKey
				signk, vk, err = userlib.DSKeyGen()
				if err != nil {
					fmt.Println("There was a problem in generating the Signing keys")
				}
				userdata.Signing_key = signk

				vk_name := userlib.Hash([]byte(username + "-SVK")) //SVK = Signature Verification Key
				err = userlib.KeystoreSet(string(vk_name), vk)
				if err != nil {
					fmt.Println("There was a problem in storing the Signature Verification Key")
				}

				sourceKey := userlib.Argon2Key([]byte(password), userlib.Hash([]byte(username)), 16)
				symmKey, err := userlib.HashKDF(sourceKey, []byte("User-protect"))
				if err != nil {
					fmt.Println("There was a problem in generating the symmKey using HashKDF")
				}
				// hmacKey, err := userlib.HashKDF(sourceKey[:16], []byte("hmac-user"))
				// if err != nil {
				// 	fmt.Println("There was a problem in generating the HMAC Key using HashKDF")
				// }
				IV := userlib.RandomBytes(16)

				userdatabytes, err := json.Marshal(userdata)
				if err != nil {
					fmt.Println("There was a problem in marshaling the User Struct")
				}
				cipher := userlib.SymEnc(symmKey[:16], IV, userdatabytes)

				signature, err := userlib.DSSign(signk, cipher)
				if err != nil {
					fmt.Println("There was a problem in generating the HMAC for the Ciphertext")
				}

				uuidData := append(signature, cipher...)
				userlib.DatastoreSet(uuid, uuidData)
			}
		}
	}
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	hashed_username := userlib.Hash([]byte(username))
	uuid, err := uuid.FromBytes(hashed_username[:16])
	if err != nil {
		fmt.Println("There was a problem in generating the UUID")
	}
	userCipher, exists := userlib.DatastoreGet(uuid)

	if !exists {
		return userdataptr, errors.New("no user with this username has been initialized")
	}

	sourceKey := userlib.Argon2Key([]byte(password), userlib.Hash([]byte(username)), 16)
	symmKey, err := userlib.HashKDF(sourceKey, []byte("User-protect"))
	if err != nil {
		fmt.Println("There was a problem in generating the symmKey using HashKDF")
		return userdataptr, err
	}

	SigVerKey, exists := userlib.KeystoreGet(string(userlib.Hash([]byte(username + "-SVK"))))
	if !exists {
		return userdataptr, errors.New("this key does not exist in the key store")
	}
	err = userlib.DSVerify(SigVerKey, userCipher[256:], userCipher[:256]) //SVK = Signature Verification Key

	if err != nil {
		return userdataptr, err
	}

	userMarshal := userlib.SymDec(symmKey[:16], userCipher[256:])
	err = json.Unmarshal(userMarshal, userdataptr)
	if err != nil {
		return nil, err
	}

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	var fileStruct File_Struct

	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + userdata.Password))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	_, exists := userlib.DatastoreGet(storageKey)
	// Storing the content of files into UUID of its own
	contentUUID := uuid.New()
	HMACKey := userlib.RandomBytes(16)
	ciphertext, symKey1, hmac := RandomSymEncAndMAC(contentBytes, HMACKey)
	contentData := append(ciphertext, hmac...)
	userlib.DatastoreSet(contentUUID, contentData)

	fileContent := File_content{
		Content:     contentUUID,
		Last_append: contentUUID,
		HmacNext:    nil,
		SymmKeyNext: nil,
		HmacKey:     HMACKey,
	}
	fileContentUUID := uuid.New()
	fileContentBytes, err := json.Marshal(fileContent)
	if err != nil {
		fmt.Println("There was a problem marshalling the File Content Struct")
	}
	fileContentBytes = append(fileContentBytes, symKey1...)

	if exists {
		pointerFile, fileStruct, ContKey := GetFileStruct(*userdata, filename)

		fileStruct.Head = fileContentUUID

		fileContentBytes = userlib.SymEnc(ContKey, userlib.RandomBytes(16), fileContentBytes)
		mac_fileContent, err := userlib.HMACEval(fileStruct.HmacKey, fileContentBytes)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(fileContentUUID, append(fileContentBytes, mac_fileContent...))
		fileStructBytes, err := json.Marshal(fileStruct)
		if err != nil {
			return err
		}
		fileStructBytes = append(fileStructBytes, ContKey...)
		fileStructBytes = userlib.SymEnc(pointerFile.EncryptedSymKey, userlib.RandomBytes(16), fileStructBytes)
		mac, err := userlib.HMACEval(pointerFile.HMacKey, fileStructBytes)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(pointerFile.Pointer, append(fileStructBytes, mac...))
		EncForAllUsers(fileStruct.Share_tree, pointerFile.Pointer, pointerFile.EncryptedSymKey, pointerFile.HMacKey, userdata.Rsa_private_key, "")

	} else {
		hmacKey2 := userlib.RandomBytes(16)
		ciphertext_fileContent, symKey2, hmac_fileContent := RandomSymEncAndMAC(fileContentBytes, hmacKey2)
		userlib.DatastoreSet(fileContentUUID, append(ciphertext_fileContent, hmac_fileContent...))
		sourceKey := userlib.Hash([]byte(userdata.Password + userdata.Username + "HMAC"))
		hmacKey, err := userlib.HashKDF(sourceKey[:16], []byte("HMAC-Files"))
		if err != nil {
			fmt.Println("There was a problem in generating an HMAC Key")
		}
		hmacKey = hmacKey[:16]
		shareTree := Tree{
			Username:     userdata.Username,
			File_pointer: storageKey,
			HmacKey:      hmacKey,
			Invited:      []Tree{},
			Accepted:     true,
			Parent:       "",
		}
		fileStruct = File_Struct{
			Head:       fileContentUUID,
			Share_tree: shareTree,
			HmacKey:    hmacKey2,
		}

		symKey3 := userlib.RandomBytes(16)
		fileStructBytes, err := json.Marshal(fileStruct)
		if err != nil {
			fmt.Println("There was a problem marshalling the File Struct")
		}
		fileStructBytes = append(fileStructBytes, symKey2...)
		cipher_fileStruct := userlib.SymEnc(symKey3, userlib.RandomBytes(16), fileStructBytes)
		hmacRandom := userlib.RandomBytes(16)
		mac, err := userlib.HMACEval(hmacRandom, cipher_fileStruct)
		if err != nil {
			return nil
		}
		PointerUUID := uuid.New()

		userlib.DatastoreSet(PointerUUID, append(cipher_fileStruct, mac...))

		EncForAllUsers(fileStruct.Share_tree, PointerUUID, symKey3, hmacRandom, userdata.Rsa_private_key, "")
	}
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	var file_struct File_Struct
	var content_struct File_content

	PointerFile, file_struct, ContSymKey := GetFileStruct(*userdata, filename)
	if ContSymKey == nil {
		return errors.New("no access to this file")
	}
	content_struct, headSymKey := GetHeadContentStruct(file_struct, ContSymKey)

	// Creating new home for the appended Content
	newContentUUID := uuid.New()
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return errors.New("could not marshal content")
	}
	hmacNew := userlib.RandomBytes(16)
	ciph, newSymKey, mac := RandomSymEncAndMAC(contentBytes, hmacNew) //newSymKey to enc content and append to marshal Cont_Struct

	userlib.DatastoreSet(newContentUUID, append(ciph, mac...))

	// New Content Struct
	var cont_struct2 File_content
	newContStructUUID := uuid.New()

	cont_struct2 = File_content{
		Content:     newContentUUID,
		Last_append: content_struct.Last_append,
		SymmKeyNext: content_struct.SymmKeyNext,
		HmacKey:     hmacNew,
		HmacNext:    content_struct.HmacNext,
	}

	content_struct.Last_append = newContStructUUID
	content_struct.HmacNext = userlib.RandomBytes(16) //Used to enc next Cont_stuct

	cont_struct2Bytes, err := json.Marshal(cont_struct2)
	if err != nil {
		return errors.New("could not marshal new content struct")
	}

	ciph_contStruct2, key, mac := RandomSymEncAndMAC(append(cont_struct2Bytes, newSymKey...), content_struct.HmacNext)
	content_struct.SymmKeyNext = key
	userlib.DatastoreSet(newContStructUUID, append(ciph_contStruct2, mac...))

	updatedHeadContStruct, err := json.Marshal(content_struct)
	if err != nil {
		return errors.New("could not produce marshal for updated content struct of head")
	}

	fileContentBytes := userlib.SymEnc(ContSymKey, userlib.RandomBytes(16), append(updatedHeadContStruct, headSymKey...))
	mac_fileContent, err := userlib.HMACEval(file_struct.HmacKey, fileContentBytes)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(file_struct.Head, append(fileContentBytes, mac_fileContent...))
	fileStructBytes, err := json.Marshal(file_struct)
	if err != nil {
		return err
	}
	fileStructBytes = append(fileStructBytes, ContSymKey...)
	fileStructBytes = userlib.SymEnc(PointerFile.EncryptedSymKey, userlib.RandomBytes(16), fileStructBytes)
	mac, err = userlib.HMACEval(PointerFile.HMacKey, fileStructBytes)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(PointerFile.Pointer, append(fileStructBytes, mac...))
	EncForAllUsers(file_struct.Share_tree, PointerFile.Pointer, PointerFile.EncryptedSymKey, PointerFile.HMacKey, userdata.Rsa_private_key, "")

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var fileStruct File_Struct
	_, fileStruct, ContSymKey := GetFileStruct(*userdata, filename)
	if ContSymKey == nil {
		return content, errors.New("no access to this file")
	}
	content_struct, headSymKey := GetHeadContentStruct(fileStruct, ContSymKey)

	var currContStruct File_content = content_struct
	var headCont File_content = content_struct

	var contentByte []byte
	var head uuid.UUID = currContStruct.Content
	var downloaded_content []byte

	for currContStruct.Last_append != head {
		currContJSON, exists := userlib.DatastoreGet(currContStruct.Last_append)
		if !exists {
			return nil, errors.New("file not in this UUID")
		}
		untampered := VerifyMAC(currContJSON, currContStruct.HmacNext, 64)
		if !untampered {
			return nil, errors.New("file may have been modified9")
		}
		currContJSON = userlib.SymDec(currContStruct.SymmKeyNext, currContJSON[:len(currContJSON)-64])
		currSymKey := currContJSON[len(currContJSON)-16:]
		err = json.Unmarshal(currContJSON[:len(currContJSON)-16], &currContStruct)
		if err != nil {
			return nil, errors.New("file may have been modified3")
		}
		contentByte, exists = userlib.DatastoreGet(currContStruct.Content)
		if !exists {
			return nil, errors.New("sorry you do not have access to this file")
		}
		untampered = VerifyMAC(contentByte, currContStruct.HmacKey, 64)
		if !untampered {
			return nil, errors.New("file may have been modified4")
		}
		contentJson := userlib.SymDec(currSymKey, contentByte[:len(contentByte)-64])
		err = json.Unmarshal(contentJson, &downloaded_content)
		if err != nil {
			return nil, errors.New("could not unmarshal the content")
		}
		content = append(downloaded_content, content...)
	}
	headJson, exists := userlib.DatastoreGet(headCont.Content)
	if !exists {
		return nil, errors.New("sorry you do not have access to this file2")
	}
	untampered := VerifyMAC(headJson, headCont.HmacKey, 64)
	if !untampered {
		return nil, errors.New("file may have been modified5")
	}
	contentJson := userlib.SymDec(headSymKey, headJson[:len(headJson)-64])
	err = json.Unmarshal(contentJson, &downloaded_content)
	if err != nil {
		return content, err
	}

	content = append(downloaded_content, content...)

	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	// var fileStruct File_Struct
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + userdata.Password))[:16])
	if err != nil {
		return invitationPtr, err
	}
	_, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return invitationPtr, errors.New("no such file name in your directory")
	}
	hashed_username := userlib.Hash([]byte(recipientUsername))
	user_uuid, err := uuid.FromBytes(hashed_username[:16])
	if err != nil {
		return invitationPtr, err
	}
	_, exists := userlib.DatastoreGet(user_uuid)
	if !exists {
		return invitationPtr, errors.New("no such recipient")
	}
	filepntr, fileStruct, contKey := GetFileStruct(*userdata, filename)

	recip_Node := SearchNode(&fileStruct.Share_tree, recipientUsername)
	if recip_Node != nil {
		fmt.Println("User already is in the tree or has been given an invite")
		return invitationPtr, errors.New("the user you are trying to invite is already in the share file space")
	}

	user_Node := SearchNode(&fileStruct.Share_tree, userdata.Username)
	if user_Node == nil {
		fmt.Println("Could not find user in tree")
		return invitationPtr, errors.New("this user does not exist in the tree")
	}
	inviteUUID := uuid.New()
	tempHmacKey := userlib.RandomBytes(16)
	newUser := Tree{
		Username:     recipientUsername,
		Invited:      []Tree{},
		File_pointer: inviteUUID,
		HmacKey:      tempHmacKey,
		Accepted:     false,
		Parent:       userdata.Username,
	}
	user_Node.Invited = append(user_Node.Invited, newUser)

	fileStructBytes, err := json.Marshal(fileStruct)
	if err != nil {
		fmt.Println("something went wrong")
		return invitationPtr, err
	}
	encFileStruct := userlib.SymEnc(filepntr.EncryptedSymKey, userlib.RandomBytes(16), append(fileStructBytes, contKey...))
	mac, err := userlib.HMACEval(filepntr.HMacKey, encFileStruct)
	if err != nil {
		return invitationPtr, err
	}
	userlib.DatastoreSet(filepntr.Pointer, append(encFileStruct, mac...))

	pk_name := userlib.Hash([]byte(recipientUsername + "-PEK")) //PEK = Public Encryption Key
	rsa_key, exists := userlib.KeystoreGet(string(pk_name))
	if !exists {
		fmt.Println("RSA Key for that user does not exist")
	}

	tmp := FilePointer{
		Pointer:         filepntr.Pointer,
		EncryptedSymKey: filepntr.EncryptedSymKey,
		HMacKey:         filepntr.HMacKey,
	}
	pointerKey := userlib.RandomBytes(16)

	marshaed_FilePointer, err := json.Marshal(tmp)
	if err != nil {
		fmt.Println("no marshal")
		return
	}
	ciphFilePntr := userlib.SymEnc(pointerKey, userlib.RandomBytes(16), marshaed_FilePointer)

	encryptKey, err := userlib.PKEEnc(rsa_key, pointerKey)
	if err != nil {
		fmt.Println("no PKEEnc")
		return
	}
	encFile := append(encryptKey, ciphFilePntr...)
	signedFile, err := userlib.DSSign(userdata.Signing_key, encFile)
	if err != nil {
		return invitationPtr, err
	}
	userlib.DatastoreSet(inviteUUID, append(encFile, signedFile...))

	EncForAllUsers(fileStruct.Share_tree, filepntr.Pointer, filepntr.EncryptedSymKey, filepntr.HMacKey, userdata.Rsa_private_key, "")

	// We get the file struct and the symmectic key used for it, then we create an invitation w/ pointer.hmackey, uuid of file struct, and
	// symmetric key. This will be stored in a random UUID. Change EncForAll to account for users with Accepted = false where we will
	// instead put signature and not hmac
	return inviteUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	//After accepting invitation pointer we will do something to get access
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + userdata.Password))[:16])
	if err != nil {
		return err
	}
	_, ok := userlib.DatastoreGet(storageKey)
	if ok {
		return errors.New("this file already exists in file space")
	}

	var pnterStruct FilePointer
	var fileStruct File_Struct

	invitation, exists := userlib.DatastoreGet(invitationPtr)
	if !exists {
		return errors.New("this invitation does not exist")
	}
	vk_name := userlib.Hash([]byte(senderUsername + "-SVK")) //SVK = Signature Verification Key
	VerifKey, exists := userlib.KeystoreGet(string(vk_name))
	if !exists {
		return errors.New("this verification key does not exist")
	}
	err = userlib.DSVerify(VerifKey, invitation[:len(invitation)-256], invitation[len(invitation)-256:])
	if err != nil {
		return err
	}
	pointerKey, err := userlib.PKEDec(userdata.Rsa_private_key, invitation[:256])
	if err != nil {
		fmt.Println("Checkpoint")
		return err
	}
	pointerStruct := userlib.SymDec(pointerKey, invitation[256:len(invitation)-256])
	err = json.Unmarshal(pointerStruct, &pnterStruct)
	if err != nil {
		return err
	}
	FileStructBytes, exists := userlib.DatastoreGet(pnterStruct.Pointer)
	if !exists {
		return errors.New("file location not found")
	}
	mac, err := userlib.HMACEval(pnterStruct.HMacKey, FileStructBytes[:len(FileStructBytes)-64])
	if err != nil {
		return err
	}
	untampered := userlib.HMACEqual(mac, FileStructBytes[len(FileStructBytes)-64:])
	if !untampered {
		return errors.New("the file may have been tampered with")
	}
	fileStructMarsh := userlib.SymDec(pnterStruct.EncryptedSymKey, FileStructBytes[:len(FileStructBytes)-64])
	contKey := fileStructMarsh[len(fileStructMarsh)-16:]
	err = json.Unmarshal(fileStructMarsh[:len(fileStructMarsh)-16], &fileStruct)
	if err != nil {
		fmt.Println("Could not marshal")
		return err
	}
	Node := SearchNode(&fileStruct.Share_tree, userdata.Username)
	if Node == nil {
		return errors.New("he broke in")
	}
	sourceKey := userlib.Hash([]byte(userdata.Password + userdata.Username + "HMAC"))
	DhmacKey, err := userlib.HashKDF(sourceKey[:16], []byte("HMAC-Files"))
	if err != nil {
		fmt.Println("There was a problem in generating an HMAC Key")
	}
	Node.Accepted = true
	Node.File_pointer = storageKey
	Node.HmacKey = DhmacKey[:16]

	FileStructBytes, err = json.Marshal(fileStruct)
	if err != nil {
		return err
	}
	ciphFileStruct := userlib.SymEnc(pnterStruct.EncryptedSymKey, userlib.RandomBytes(16), append(FileStructBytes, contKey...))
	mac, err = userlib.HMACEval(pnterStruct.HMacKey, ciphFileStruct)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(pnterStruct.Pointer, append(ciphFileStruct, mac...))
	EncForAllUsers(fileStruct.Share_tree, pnterStruct.Pointer, pnterStruct.EncryptedSymKey, pnterStruct.HMacKey, userdata.Rsa_private_key, "")

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	filepntr, fileStruct, contKey := GetFileStruct(*userdata, filename)
	if contKey == nil {
		return errors.New("file does not exist")
	}
	headContStruct, headContSymKey := GetHeadContentStruct(fileStruct, contKey)
	parent_node := SearchNode(&fileStruct.Share_tree, userdata.Username)

	// Error might be in here, I dont think the actual file struct is being updated
	inTree := RemoveNodeByUsername(parent_node, recipientUsername)
	if !inTree {
		return errors.New("recipient user is not in your invited list")
	}

	if headContStruct.Last_append == headContStruct.Content {
		newUUID := uuid.New()
		newHmacKey := userlib.RandomBytes(16)
		contData, exists := userlib.DatastoreGet(headContStruct.Content)
		if !exists {
			return errors.New("no file content exists")
		}
		untampered := VerifyMAC(contData, headContStruct.HmacKey, 64)
		if !untampered {
			return errors.New("this content has been tampered with")
		}
		contData = userlib.SymDec(headContSymKey, contData[:len(contData)-64])

		userlib.DatastoreDelete(headContStruct.Content)

		contData, newSymKey, mac := RandomSymEncAndMAC(contData, newHmacKey)
		userlib.DatastoreSet(newUUID, append(contData, mac...))
		headContStruct.Content = newUUID
		headContStruct.HmacKey = newHmacKey
		headContStruct.Last_append = newUUID

		userlib.DatastoreDelete(fileStruct.Head)

		//Cont Struct
		fileStruct.Head = uuid.New()
		fileStruct.HmacKey = userlib.RandomBytes(16)
		fileContJson, err := json.Marshal(headContStruct)
		if err != nil {
			return err
		}
		fileContCiph, newSymKey, mac := RandomSymEncAndMAC(append(fileContJson, newSymKey...), fileStruct.HmacKey)
		userlib.DatastoreSet(fileStruct.Head, append(fileContCiph, mac...))

		//File Struct
		newUUID = uuid.New()
		newHmacKey = userlib.RandomBytes(16)
		fileStructJson, err := json.Marshal(fileStruct)
		if err != nil {
			return err
		}
		fileStructCiph, newSymKey, mac := RandomSymEncAndMAC(append(fileStructJson, newSymKey...), newHmacKey)
		userlib.DatastoreSet(newUUID, append(fileStructCiph, mac...))

		EncForAllUsers(fileStruct.Share_tree, newUUID, newSymKey, newHmacKey, userdata.Signing_key, "revoke")

	} else {
		//go into each content and reEncrypt with a different key and change their UUID locations
		currContStruct := headContStruct
		last_app := headContStruct.Last_append

		newUUID := uuid.New()
		newHmacNext := userlib.RandomBytes(16)
		newSymNext := userlib.RandomBytes(16)

		headContStruct.Last_append = newUUID
		headContStruct.SymmKeyNext = newSymNext
		headContStruct.HmacNext = newHmacNext

		currHmacNextKey := currContStruct.HmacNext
		currSymKeyNext := currContStruct.SymmKeyNext

		for last_app != headContStruct.Content {

			currContJSON, exists := userlib.DatastoreGet(last_app)
			if !exists {
				return errors.New("file may have been modified1")
			}
			untampered := VerifyMAC(currContJSON, currHmacNextKey, 64)
			if !untampered {
				return errors.New("cannot verify mac")
			}
			currContJSON = userlib.SymDec(currSymKeyNext, currContJSON[:len(currContJSON)-64])
			currSymKey := currContJSON[len(currContJSON)-16:]
			err := json.Unmarshal(currContJSON[:len(currContJSON)-16], &currContStruct)
			if err != nil {
				return err
			}
			contentByte, exists := userlib.DatastoreGet(currContStruct.Content)
			if !exists {
				return errors.New("sorry you do not have access to this file")
			}
			untampered = VerifyMAC(contentByte, currContStruct.HmacKey, 64)
			if !untampered {
				return errors.New("file may have been modified4")
			}
			contentJson := userlib.SymDec(currSymKey, contentByte[:len(contentByte)-64])

			// Storing Content into new UUID with new hmac and sym keys
			newContHmac := userlib.RandomBytes(16)
			newContEnc, newContKey, newContmac := RandomSymEncAndMAC(contentJson, newContHmac)
			newContUUID := uuid.New()
			userlib.DatastoreSet(newContUUID, append(newContEnc, newContmac...))

			//Store Cont Struct w/ previouly set UUID, SymKeyNext, HmacNext

			userlib.DatastoreDelete(currContStruct.Content)
			currContStruct.Content = newContUUID
			currContStruct.HmacKey = newContHmac
			if currContStruct.SymmKeyNext != nil {
				currSymKeyNext = currContStruct.SymmKeyNext
				currHmacNextKey = currContStruct.HmacNext

				currContStruct.SymmKeyNext = userlib.RandomBytes(16)
				currContStruct.HmacNext = userlib.RandomBytes(16)

				userlib.DatastoreDelete(last_app)
			}
			last_app = currContStruct.Last_append
			currContStruct.Last_append = uuid.New()
			currContStructJson, err := json.Marshal(currContStruct)
			if err != nil {
				return err
			}
			currContStructCiph := userlib.SymEnc(newSymNext, userlib.RandomBytes(16), append(currContStructJson, newContKey...))
			mac, err := userlib.HMACEval(newHmacNext, currContStructCiph)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(newUUID, append(currContStructCiph, mac...))
			newSymNext = currContStruct.SymmKeyNext
			newUUID = currContStruct.Last_append
			newHmacNext = currContStruct.HmacNext
		}
		fileStruct.Head = uuid.New()
		fileStruct.HmacKey = userlib.RandomBytes(16)

		contData, exists := userlib.DatastoreGet(headContStruct.Content)
		if !exists {
			return errors.New("no file content exists")
		}
		untampered := VerifyMAC(contData, headContStruct.HmacKey, 64)
		if !untampered {
			return errors.New("this content has been tampered with")
		}
		contData = userlib.SymDec(headContSymKey, contData[:len(contData)-64])
		userlib.DatastoreDelete(headContStruct.Content)
		UUID := currContStruct.Last_append
		newHmacKey := userlib.RandomBytes(16)

		contData, newSymKey, mac := RandomSymEncAndMAC(contData, newHmacKey)
		userlib.DatastoreSet(UUID, append(contData, mac...))
		headContStruct.Content = UUID
		headContStruct.HmacKey = newHmacKey

		FileContJson, err := json.Marshal(headContStruct)
		if err != nil {
			return err
		}
		ciphFileCont, newSymKey, mac := RandomSymEncAndMAC(append(FileContJson, newSymKey...), fileStruct.HmacKey)
		userlib.DatastoreSet(fileStruct.Head, append(ciphFileCont, mac...))

		// Store File Struct
		newUUID = uuid.New()
		newHmacKey = userlib.RandomBytes(16)
		fileStructJson, err := json.Marshal(fileStruct)
		if err != nil {
			return err
		}
		fileStructCiph, newSymKey, mac := RandomSymEncAndMAC(append(fileStructJson, newSymKey...), newHmacKey)
		userlib.DatastoreSet(newUUID, append(fileStructCiph, mac...))

		EncForAllUsers(fileStruct.Share_tree, newUUID, newSymKey, newHmacKey, userdata.Signing_key, "revoke")
	}
	userlib.DatastoreDelete(filepntr.Pointer)

	return nil
}

func VerifyMAC(ciphertext []byte, key []byte, padding int) (untampered bool) {
	prev_hmac := ciphertext[len(ciphertext)-padding:]
	cipher := ciphertext[:len(ciphertext)-padding]
	curr_hmac, err := userlib.HMACEval(key, cipher)
	if err != nil {
		return false
	}
	untampered = userlib.HMACEqual(curr_hmac, prev_hmac)

	return untampered
}

func RandomSymEncAndMAC(plaintxt []byte, hmacKey []byte) (ciphertxt []byte, symmKey []byte, hmac []byte) {
	symmKey = userlib.RandomBytes(16)
	ciphertxt = userlib.SymEnc(symmKey, userlib.RandomBytes(16), plaintxt)
	hmac, err := userlib.HMACEval(hmacKey, ciphertxt)
	if err != nil {
		return nil, nil, nil
	}
	return ciphertxt, symmKey, hmac
}

func GetFileStruct(userdata User, filename string) (filePointer FilePointer, fileStruct File_Struct, headSymKey []byte) {
	var filePnter FilePointer
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + userdata.Password))[:16])
	if err != nil {
		fmt.Println("no file1")
		return filePnter, fileStruct, nil
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		fmt.Println("no file2")
		return filePnter, fileStruct, nil
	}
	sourceKey := userlib.Hash([]byte(userdata.Password + userdata.Username + "HMAC"))
	DhmacKey, err := userlib.HashKDF(sourceKey[:16], []byte("HMAC-Files"))
	if err != nil {
		fmt.Println("There was a problem in generating an HMAC Key")
		return filePnter, fileStruct, nil
	}
	untampered := VerifyMAC(dataJSON, DhmacKey[:16], 64)
	if !untampered {
		fmt.Println("Cant Verify")
		return filePnter, fileStruct, nil
	}
	key, err := userlib.PKEDec(userdata.Rsa_private_key, dataJSON[:256])
	if err != nil {
		fmt.Println("Cant PK Decrypt")
		return filePnter, fileStruct, nil
	}
	filePointerStructBytes := userlib.SymDec(key, dataJSON[256:len(dataJSON)-64])
	err = json.Unmarshal(filePointerStructBytes, &filePnter)
	if err != nil {
		fmt.Println("cant unmarshal filePointer Struct")
		return filePnter, fileStruct, nil
	}
	FileStructBytes, exists := userlib.DatastoreGet(filePnter.Pointer)
	if !exists {
		fmt.Println("pointer does not exist")
		return filePnter, fileStruct, nil
	}
	untampered = VerifyMAC(FileStructBytes, filePnter.HMacKey, 64)
	if !untampered {
		fmt.Println("cant verify2")
		return filePnter, fileStruct, nil
	}
	FileStructBytes = userlib.SymDec(filePnter.EncryptedSymKey, FileStructBytes[:len(FileStructBytes)-64])
	err = json.Unmarshal(FileStructBytes[:len(FileStructBytes)-16], &fileStruct)
	if err != nil {
		fmt.Println("cant unmarshal file struct")
		return filePnter, fileStruct, nil
	}
	return filePnter, fileStruct, FileStructBytes[len(FileStructBytes)-16:]
}

func GetHeadContentStruct(fileStruct File_Struct, ContentSymKey []byte) (headContentStruct File_content, headContentSymKey []byte) {
	headContStruct, exists := userlib.DatastoreGet(fileStruct.Head)
	if !exists {
		fmt.Println("cant find filestruct head")
		return
	}
	untampered := VerifyMAC(headContStruct, fileStruct.HmacKey, 64)
	if !untampered {
		fmt.Println("cant verify")
		return
	}
	headContStruct = userlib.SymDec(ContentSymKey, headContStruct[:len(headContStruct)-64])
	headContentSymKey = headContStruct[len(headContStruct)-16:]
	err := json.Unmarshal(headContStruct[:len(headContStruct)-16], &headContentStruct)
	if err != nil {
		fmt.Println("cant unmarshal head cont struct")
		return
	}
	return headContentStruct, headContentSymKey
}

func EncForAllUsers(tree Tree, uuid uuid.UUID, symmetricKey []byte, HmacKey []byte, signKey userlib.DSSignKey, purpose string) error {
	pk_name := userlib.Hash([]byte(tree.Username + "-PEK")) //PEK = Public Encryption Key
	rsa_key, exists := userlib.KeystoreGet(string(pk_name))
	if !exists {
		fmt.Println("RSA Key for that user does not exist")
	}

	var temp FilePointer
	temp.Pointer = uuid
	temp.EncryptedSymKey = symmetricKey
	temp.HMacKey = HmacKey

	pointerKey := userlib.RandomBytes(16)

	marshaed_FilePointer, err := json.Marshal(temp)
	if err != nil {
		fmt.Println("no marshal")
		return err
	}
	ciphFilePntr := userlib.SymEnc(pointerKey, userlib.RandomBytes(16), marshaed_FilePointer)

	encryptKey, err := userlib.PKEEnc(rsa_key, pointerKey)
	if err != nil {
		fmt.Println("no PKEEnc")
		return err
	}
	ciphFilePntr = append(encryptKey, ciphFilePntr...)
	if tree.Accepted {
		mac, err := userlib.HMACEval(tree.HmacKey, ciphFilePntr)
		if err != nil {
			fmt.Println("no HMAC")
			return err
		}
		userlib.DatastoreSet(tree.File_pointer, append(ciphFilePntr, mac...))
	} else {
		if purpose == "revoke" {
			signedFile, err := userlib.DSSign(signKey, ciphFilePntr)
			if err != nil {
				fmt.Println("error in signing")
				return err
			}

			userlib.DatastoreSet(tree.File_pointer, append(ciphFilePntr, signedFile...))
		}
	}
	for _, user := range tree.Invited {
		EncForAllUsers(user, uuid, symmetricKey, HmacKey, signKey, purpose)
	}

	return nil
}

func SearchNode(tree *Tree, target string) *Tree {
	if tree.Username == target {
		return tree
	}
	// Recursively search in the invited (children) nodes
	for i := range tree.Invited {
		if result := SearchNode(&tree.Invited[i], target); result != nil {
			return result
		}
	}
	return nil
}

func RemoveNodeByUsername(tree *Tree, target string) bool {
	for i := 0; i < len(tree.Invited); i++ {
		if tree.Invited[i].Username == target {
			userlib.DatastoreDelete(tree.Invited[i].File_pointer)
			RemoveFileSpaceSubTree(&tree.Invited[i])
			tree.Invited = append(tree.Invited[:i], tree.Invited[i+1:]...)
			return true
		}
		if RemoveNodeByUsername(&tree.Invited[i], target) {
			return true
		}
	}
	return false
}

func RemoveFileSpaceSubTree(tree *Tree) {
	for i := 0; i < len(tree.Invited); i++ {
		RemoveFileSpaceSubTree(&tree.Invited[i])
		userlib.DatastoreDelete(tree.Invited[i].File_pointer)
	}
}
