package common

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/pem"
	"fmt"
	"github.com/cryptobox/cbecdsa"
	"github.com/cryptobox/gocryptobox/stoutbox"
	"github.com/gokyle/sshkey"
	"os"
	"path/filepath"
	"strings"
)

var Version = "0.2"
var pemSealed = "STOUTBOX SEALED MESSAGE"
var pemSigned = "STOUTBOX SIGNATURE"

// ReadPrompt prints the prompt (with no modification), and reads
// a line of input from the user. This line is returned as a
// string with the newline and any leading and trailing spaces
// trimmed.
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

// Zero wipes the byte slice, resetting every byte to zero.
func Zero(in []byte) {
	if in == nil {
		return
	}
	inLen := len(in)
	for i := 0; i < inLen; i++ {
		in[i] ^= in[i]
	}
}

// BoxIsShared returns true if the box is a shared box.
func BoxIsShared(box []byte) bool {
	switch box[0] {
	case stoutbox.BoxShared:
		return true
	case stoutbox.BoxSharedSigned:
		return true
	default:
		return false
	}
}

// DefaultKeyFile returns a sane default key to use as the user's
// default private key. Add ".pub" to the result to get the
// appropriate public key.
func DefaultKeyFile() string {
	home := os.Getenv("HOME")
	return filepath.Join(home, ".ssh", "id_ecdsa")
}

func armour(box []byte, pemType string) []byte {
	var block pem.Block
	block.Type = pemType
	block.Bytes = box
	block.Headers = make(map[string]string)
	block.Headers["VERSION"] = fmt.Sprintf("%s-%s", stoutbox.VersionString,
		Version)
	return pem.EncodeToMemory(&block)
}

// ArmourCrypt PEM-encodes a sealed box with the appropriate PEM
// type.
func ArmourCrypt(box []byte) []byte {
	return armour(box, pemSealed)
}

// ArmourSigned PEM-encodes a signature with the appropriate PEM
// type.
func ArmourSigned(sig []byte) []byte {
	return armour(sig, pemSigned)
}

func unarmour(box []byte, pemType string) ([]byte, bool) {
	blk, _ := pem.Decode(box)
	if blk == nil {
		return nil, false
	} else if blk.Type != pemType {
		return nil, false
	}
	return blk.Bytes, true
}

// UnarmourCrypt checks a PEM-encoded (armoured) box has the correct
// PEM type, and decodes it. Typically, if this function fails, the
// input slice should be used directly under the assumption that it
// is not armoured.
func UnarmourCrypt(box []byte) ([]byte, bool) {
	return unarmour(box, pemSealed)
}

// UnarmourSigned is the signature analogue to UnarmourCrypt.
func UnarmourSigned(box []byte) ([]byte, bool) {
	return unarmour(box, pemSigned)
}

// LoadPub loads an SSH public key from the filename.
func LoadPub(filename string) (pub stoutbox.PublicKey, ok bool) {
	filename = strings.TrimSpace(filename)
	spub, err := sshkey.LoadPublicKeyFile(filename, true)
	if err != nil {
		return
	}
	if spub.Type != sshkey.KEY_ECDSA {
		return
	} else if spub.Key.(*ecdsa.PublicKey).Curve != elliptic.P521() {
		return
	}

	pub, err = cbecdsa.ECDSAToStoutboxPublic(spub.Key.(*ecdsa.PublicKey))
	if err != nil {
		return
	}
	ok = true
	return
}

// LoadPriv loads an SSH private key from the filename.
func LoadPriv(filename string) (priv stoutbox.PrivateKey, pub stoutbox.PublicKey, ok bool) {
	key, t, err := sshkey.LoadPrivateKeyFile(filename)
	if err != nil {
		return
	} else if t != sshkey.KEY_ECDSA {
		return
	}
	ecpriv := key.(*ecdsa.PrivateKey)
	priv, pub, err = cbecdsa.ECDSAToStoutbox(ecpriv)
	if err != nil {
		Zero(priv)
		return
	}
	ok = true
	return
}

// Check whether the filename exists; if it does, display a prompt asking
// whether to overwrite. If the user doesn't want to overwrite, or if an
// error occurs, it will die.
func CheckAndOpen(filename string, force bool) (f *os.File) {
	var err error
	if _, err = os.Stat(filename); !os.IsNotExist(err) && !force {
		fmt.Printf("%s already exists.\n", filename)
		yn, err := ReadPrompt("Overwrite (y/n)? ")
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		if strings.ToUpper(string(yn[0])) != "Y" {
			os.Exit(1)
		}
	}
	f, err = os.Create(filename)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	return
}
