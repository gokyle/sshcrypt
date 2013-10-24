package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/cryptobox/cbecdsa"
	"github.com/cryptobox/gocryptobox/stoutbox"
	"github.com/gokyle/sshkey"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var Version = "0.1"
var pemType = "STOUTBOX SEALED MESSAGE"

func zero(in []byte) {
	if in == nil {
		return
	}
	inLen := len(in)
	for i := 0; i < inLen; i++ {
		in[i] ^= in[i]
	}
}

func boxIsShared(box []byte) bool {
	switch box[0] {
	case stoutbox.BoxShared:
		return true
	case stoutbox.BoxSharedSigned:
		return true
	default:
		return false
	}
}

func defaultDecryptKeyFile() string {
	home := os.Getenv("HOME")
	return filepath.Join(home, ".ssh", "id_ecdsa")
}

func Armour(box []byte) []byte {
	var block pem.Block
	block.Type = pemType
	block.Bytes = box
	block.Headers = make(map[string]string)
	block.Headers["VERSION"] = fmt.Sprintf("%s-%s", stoutbox.VersionString,
		Version)
	return pem.EncodeToMemory(&block)
}

func Unarmour(box []byte) ([]byte, bool) {
	blk, _ := pem.Decode(box)
	if blk == nil {
		return nil, false
	} else if blk.Type != pemType {
		return nil, false
	}
	return blk.Bytes, true
}

func Encrypt(sshPubs []string, signer string, inFile, outFile string, armour bool) bool {
	pubs := make([]stoutbox.PublicKey, 0)
	for _, fName := range sshPubs {
		pub, err := sshkey.LoadPublicKeyFile(fName, true)
		if err != nil {
			fmt.Printf("Failed to load SSH key %s.\n", fName)
			return false
		}
		if pub.Type != sshkey.KEY_ECDSA {
			fmt.Println("stoutssh requires P521 ECDSA keys.")
			return false
		} else if pub.Key.(*ecdsa.PublicKey).Curve != elliptic.P521() {
			fmt.Println("stoutssh requires P521 ECDSA keys.")
			return false
		}
		spub, err := cbecdsa.ECDSAToStoutboxPublic(pub.Key.(*ecdsa.PublicKey))
		if err != nil {
			fmt.Println("Invalid public key.")
			return false
		}
		pubs = append(pubs, spub)
	}
	fData, err := ioutil.ReadFile(inFile)
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	var (
		box []byte
		ok  bool
	)

	var sigKey struct {
		Priv stoutbox.PrivateKey
		Pub  stoutbox.PublicKey
	}

	if signer != "" {
		key, t, err := sshkey.LoadPrivateKeyFile(signer)
		if err != nil {
			fmt.Println("Failed to load signature key.")
			return false
		} else if t != sshkey.KEY_ECDSA {
			fmt.Println("Signature keys must be P521 ECDSA keys.")
			return false
		}
		priv := key.(*ecdsa.PrivateKey)
		sigKey.Priv, sigKey.Pub, err = cbecdsa.ECDSAToStoutbox(priv)
		if err != nil {
			fmt.Println("Invalid signature key.")
			return false
		}
		defer zero(sigKey.Priv)

		if len(pubs) == 1 {
			box, ok = stoutbox.SignAndSeal(fData, sigKey.Priv,
				sigKey.Pub, pubs[0])
		} else {
			box, ok = stoutbox.SignAndSealShared(fData, pubs,
				sigKey.Priv, sigKey.Pub)
		}
	} else {
		if len(pubs) == 1 {
			box, ok = stoutbox.Seal(fData, pubs[0])
		} else {
			box, ok = stoutbox.SealShared(fData, pubs)
		}
	}
	if !ok {
		fmt.Println("Failed to seal the file.")
		return false
	}

	if armour {
		box = Armour(box)
	}

	err = ioutil.WriteFile(outFile, box, 0644)
	if err != nil {
		fmt.Println(err.Error())
		return false
	}
	return true
}

func Decrypt(privFile string, signer string, inFile, outFile string) bool {
	sshPriv, t, err := sshkey.LoadPrivateKeyFile(privFile)
	if err != nil {
		fmt.Println("Failed to load decryption key.")
		return false
	} else if t != sshkey.KEY_ECDSA {
		fmt.Println("Signature keys must be P521 ECDSA keys.")
		return false
	}
	priv, pub, err := cbecdsa.ECDSAToStoutbox(sshPriv.(*ecdsa.PrivateKey))
	if err != nil {
		fmt.Println("Invalid private key.")
		return false
	}
	defer zero(priv)

	fData, err := ioutil.ReadFile(inFile)
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	box, ok := Unarmour(fData)
	if !ok {
		box = fData
	}

	var msg []byte
	if signer != "" {
		sshPub, err := sshkey.LoadPublicKeyFile(signer, true)
		if err != nil {
			fmt.Println("Invalid signature key.")
			return false
		}
		var peer stoutbox.PublicKey
		ecPub := sshPub.Key.(*ecdsa.PublicKey)
		peer, err = cbecdsa.ECDSAToStoutboxPublic(ecPub)
		if err != nil {
			fmt.Println("Invalid signature key.")
			return false
		}

		if boxIsShared(box) {
			msg, ok = stoutbox.OpenSharedAndVerify(box, priv, pub, peer)
		} else {
			msg, ok = stoutbox.OpenAndVerify(box, priv, peer)
		}

	} else {
		if boxIsShared(box) {
			msg, ok = stoutbox.OpenShared(box, priv, pub)
		} else {
			msg, ok = stoutbox.Open(box, priv)
		}
	}
	if !ok {
		fmt.Println("Failed to open message.")
		return false
	}

	err = ioutil.WriteFile(outFile, msg, 0644)
	if err != nil {
		fmt.Println(err.Error())
		return false
	}
	return true
}

func main() {
	fKey := flag.String("k", "", "key file(s)")
	fDecrypt := flag.Bool("o", false, "open input file")
	fArmour := flag.Bool("a", false, "ASCII-armour output file")
	fSigner := flag.String("s", "", "signature key")
	flag.Parse()

	if flag.NArg() != 2 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	inFile := flag.Args()[0]
	outFile := flag.Args()[1]
	if !*fDecrypt {
		keys := strings.Split(*fKey, ",")
		if len(keys) == 0 {
			fmt.Println("No keys specified.")
			os.Exit(1)
		}
		ok := Encrypt(keys, *fSigner, inFile, outFile, *fArmour)
		if !ok {
			fmt.Println("Failed to seal file.")
			os.Exit(1)
		} else {
			fmt.Println("OK.")
			os.Exit(1)
		}
	} else {
		ok := Decrypt(*fKey, *fSigner, inFile, outFile)
		if !ok {
			fmt.Println("Failed to open sealed message.")
			os.Exit(1)
		} else {
			fmt.Println("OK.")
			os.Exit(1)
		}
	}
}
