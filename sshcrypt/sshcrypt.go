package main

import (
	"flag"
	"fmt"
	"github.com/cryptobox/gocryptobox/stoutbox"
	"github.com/cryptobox/sshcrypt/common"
	"io/ioutil"
	"os"
	"strings"
)

func Encrypt(sshPubs []string, signer string, inFile, outFile *os.File, armour bool) bool {
	pubs := make([]stoutbox.PublicKey, 0)
	for _, fName := range sshPubs {
		pub, ok := common.LoadPub(fName)
		if !ok {
			fmt.Println("Failed to load public key", fName)
			return false
		}
		pubs = append(pubs, pub)
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
		sigKey.Priv, sigKey.Pub, ok = common.LoadPriv(signer)
		defer common.Zero(sigKey.Priv)
		if !ok {
			fmt.Println("Couldn't load key for signature.")
			return false
		}

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
		box = common.ArmourCrypt(box)
	}

	_, err = outFile.Write(box)
	if err != nil {
		fmt.Println(err.Error())
		return false
	}
	return true
}

func Decrypt(privFile string, signer string, inFile, outFile *os.File) bool {
	priv, pub, ok := common.LoadPriv(privFile)
	if !ok {
		fmt.Println("Couldn't load private key.")
		return false
	}

	fData, err := ioutil.ReadAll(inFile)
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	if len(fData) < stoutbox.Overhead {
		fmt.Println("Invalid sealed message.")
		return false
	}

	box, ok := common.UnarmourCrypt(fData)
	if !ok {
		box = fData
	}

	var msg []byte
	if signer != "" {
		var peer stoutbox.PublicKey
		peer, ok = common.LoadPub(signer)
		if !ok {
			fmt.Println("Invalid signature key.")
			return false
		}

		if common.BoxIsShared(box) {
			msg, ok = stoutbox.OpenSharedAndVerify(box, priv, pub, peer)
		} else {
			msg, ok = stoutbox.OpenAndVerify(box, priv, peer)
		}

	} else {
		if common.BoxIsShared(box) {
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
	fOutputFile := flag.String("file", "-", "output file name")
	flag.Parse()

	if flag.NArg() != 1 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	inFile := flag.Args()[0]
	outFile := *fOutputFile
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
		out = common.CheckAndOpen(outFile, *fOverwrite)
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
