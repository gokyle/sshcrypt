package main

import (
	"flag"
	"fmt"
	"github.com/cryptobox/gocryptobox/stoutbox"
	"github.com/cryptobox/sshcrypt/common"
	"io/ioutil"
	"os"
)

func Sign(keyFile string, in, out *os.File) (ok bool) {
	priv, pub, ok := common.LoadPriv(keyFile)
	if !ok {
		return
	}
	defer common.Zero(priv)

	msg, err := ioutil.ReadAll(in)
	if err != nil {
		fmt.Println("Couldn't read input.")
		return false
	}

	sig, ok := stoutbox.Sign(msg, priv, pub)
	if !ok {
		fmt.Println("Signing failed.")
		return
	}

	_, err = out.Write(sig)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	ok = true
	return
}

func Verify(keyFile string, in, sig *os.File) (ok bool) {
	pub, ok := common.LoadPub(keyFile)
	if !ok {
		fmt.Fprintf(os.Stderr, "Couldn't load public key.")
		return
	}

	sigData, err := ioutil.ReadAll(sig)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	inData, err := ioutil.ReadAll(in)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	return stoutbox.Verify(inData, sigData, pub)
}

func main() {
	fOverwrite := flag.Bool("f", false, "force overwrite")
	fKeyFile := flag.String("k", "", "signature key")
	fVerify := flag.Bool("v", false, "verify signature")
	fOutputFile := flag.String("file", "-", "output file")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Println("No input file specified.")
		os.Exit(1)
	}
	inFile := flag.Args()[0]

	var in, out *os.File
	if inFile == "-" {
		in = os.Stdin
	} else {
		var err error
		in, err = os.Open(inFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error())
			os.Exit(1)
		}
		defer in.Close()
	}

	if *fVerify {
		if *fOutputFile == "-" {
			out = os.Stdin
		} else {
			var err error
			out, err = os.Open(*fOutputFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, err.Error())
				os.Exit(1)
			}
			defer out.Close()
		}
	} else {
		if *fOutputFile == "-" {
			out = os.Stdout
		} else {
			out = common.CheckAndOpen(*fOutputFile, *fOverwrite)
			defer out.Close()
		}
	}

	var ok bool
	if *fVerify {
		fmt.Println("verify", inFile, "signature", *fOutputFile)
		ok = Verify(*fKeyFile, in, out)
	} else {
		if *fKeyFile == "" {
			*fKeyFile = common.DefaultKeyFile()
		}
		ok = Sign(*fKeyFile, in, out)
	}

	if !ok {
		fmt.Println("Failed.")
		os.Exit(1)
	} else {
		fmt.Println("OK")
		os.Exit(0)
	}
}
