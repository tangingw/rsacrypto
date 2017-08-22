package RSAcrypto

import (
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

var testMsg = []string{
	"I am goood!",
	"dsfddfdsfsdfgdafdfdafdsafsdvfkjvdfvfdvmfdvdrfvdsasdaf",
	"How are you?",
	"1232343254363553568687589775342354565676",
	"We will head to YHSFVC!",
	"e3qdfewifmdsfwfads3824q3wu54e9ger84r@!#@$#%$%^^TGDFDv,dslf ewqkfreo9giv",
	"efiewfadsnfjewq nqew fq23ITY9T668TFSDNDFKR EWKJRQ UVREAV EQWNVRU3W MAMEVR ENVIEWRVEWUVB4QTWERVH ER3W ESAAR RWET 8R T'R EOR 8Q4WVRESNF TRH,4",
}

func TestReadWriteGob(t *testing.T) {

	bitLength := 3072

	keyPair := generateRSAKey(bitLength)

	saveGobKey("rsa_key.key", keyPair)
	saveGobKey("public.key", keyPair.PublicKey)

	key := retrieveGobKey("public.key", &rsa.PublicKey{})

	if key.(*rsa.PublicKey).E != keyPair.PublicKey.E {

		t.Error("Expected %d, Got %d\n", keyPair.PublicKey.E, key.(*rsa.PublicKey).E)

	}
}

func TestCrypto(t *testing.T) {

	bitLength := 3072

	keypair := generateRSAKey(bitLength)

	for _, msg := range testMsg {

		byteMessage := []byte(msg)
		encryptedMessage := keypair.encryptOAEP(sha256.New(), byteMessage, nil)
		decryptedMessage := keypair.decryptOAEP(sha256.New(), encryptedMessage, nil)

		if string(decryptedMessage) != msg {
			t.Error("Expected %s, got %\n", msg, string(decryptedMessage))
		}
	}
}

func TestPublicPEM(t *testing.T) {

	bitLength := 3072

	keyPair := generateRSAKey(bitLength)
	savePublicPEMKey("public.pem", keyPair.PublicKey)

	key := retrievePEMPubKey("public.pem")

	if key.E != keyPair.PublicKey.E {

		t.Error("Expect %d, got %d\n",
			key.E,
			keyPair.PublicKey.E,
		)
	}
}

func TestPrivatePEM(t *testing.T) {

	bitLength := 3072

	keypair := generateRSAKey(bitLength)
	savePEMKey("private.pem", keypair.PrivateKey)

	privateKey := retrievePEMKey("private.pem")

	if privateKey.PublicKey.E != keypair.PrivateKey.PublicKey.E {

		t.Error("expect %d, got %d\n",
			privateKey.PublicKey.E,
			keypair.PrivateKey.PublicKey.E,
		)
	}
}
