package main

import (
	"bufio"
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

var Version = "0.2"
var pemType = "STOUTBOX SEALED MESSAGE"

func ReadPrompt(prompt string) (in string, err error) {
	fmt.Printf("%s", prompt)
	rd := bufio.NewReader(os.Stdin)
	line, err := rd.ReadString('\n')
	if err != nil {
		return
	}
	in = strings.TrimSpace(line)
	return
}

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

func Encrypt(sshPubs []string, signer string, inFile, outFile *os.File, armour bool) bool {
	pubs := make([]stoutbox.PublicKey, 0)
	for _, fName := range sshPubs {
		fName = strings.TrimSpace(fName)
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
	fData, err := ioutil.ReadAll(inFile)
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

	_, err = outFile.Write(box)
	if err != nil {
		fmt.Println(err.Error())
		return false
	}
	return true
}

func Decrypt(privFile string, signer string, inFile, outFile *os.File) bool {
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

	fData, err := ioutil.ReadAll(inFile)
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	box, ok := Unarmour(fData)
	if !ok {
		box = fData[:len(box)-2]
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

	_, err = outFile.Write(msg)
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
	fOverwrite := flag.Bool("f", false, "force overwriting files")
	flag.Parse()

	if flag.NArg() != 2 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	inFile := flag.Args()[0]
	outFile := flag.Args()[1]
	var in, out *os.File
	var err error

	if inFile == "-" {
		in = os.Stdin
	} else {
		in, err = os.Open(inFile)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		defer in.Close()
	}

	if outFile == "-" {
		out = os.Stdout
	} else {
		if _, err = os.Stat(outFile); !os.IsNotExist(err) && !*fOverwrite {
			fmt.Printf("%s already exists.\n", outFile)
			yn, err := ReadPrompt("Overwrite (y/n)? ")
			if err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}
			if strings.ToUpper(string(yn[0])) != "Y" {
				os.Exit(1)
			}
		}
		out, err = os.Create(outFile)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		defer out.Close()
	}

	if !*fDecrypt {
		keys := strings.Split(*fKey, ",")
		if len(keys) == 0 {
			fmt.Println("No keys specified.")
			os.Exit(1)
		}
		ok := Encrypt(keys, *fSigner, in, out, *fArmour)
		if !ok {
			fmt.Println("Failed to seal file.")
			os.Exit(1)
		} else {
			fmt.Println("OK.")
			os.Exit(1)
		}
	} else {
		ok := Decrypt(*fKey, *fSigner, in, out)
		if !ok {
			fmt.Println("Failed to open sealed message.")
			os.Exit(1)
		} else {
			fmt.Println("OK.")
			os.Exit(1)
		}
	}
}
