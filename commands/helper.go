package commands

import (
	"github.com/chris-wood/dns"
	"github.com/chris-wood/odoh"
	"log"
	"time"
	"fmt"
)

// Function for Converting CLI DNS Query Type to the uint16 Datatype
func dnsQueryStringToType(stringType string) uint16 {
	switch stringType {
	case "A":
		return dns.TypeA
	case "AAAA":
		return dns.TypeAAAA
	case "CAA":
		return dns.TypeCAA
	case "CNAME":
		return dns.TypeCNAME
	default:
		return 0
	}
}

func parseDnsResponse(data []byte) (*dns.Msg, error) {
	msg := &dns.Msg{}
	err := msg.Unpack(data)
	return msg, err
}

func prepareDnsQuestion(domain string, questionType uint16) (res []byte) {
	dnsMessage := new(dns.Msg)
	dnsMessage.SetQuestion(domain, questionType)
	dnsSerializedString, err := dnsMessage.Pack()
	if err != nil {
		log.Fatalf("Unable to Pack the dnsMessage correctly %v", err)
	}
	return dnsSerializedString
}

func prepareOdohQuestion(domain string, questionType uint16, key []byte, publicKey odoh.ObliviousDNSPublicKey) (res odoh.ObliviousDNSQuery, msg []byte, err error) {
	start := time.Now()
	dnsMessage := prepareDnsQuestion(domain, questionType)
	prepareQuestionTime := time.Since(start)

	var seed [odoh.ResponseSeedLength]byte
	copy(seed[:], key)

	fmt.Printf("dnsMessage: TESTING: %x\n\n", dnsMessage)
	fmt.Printf("responseSeed: TESTING: %v\n\n", seed)
	odohQuery := odoh.ObliviousDNSQuery{
		DnsMessage:  dnsMessage,
		ResponseSeed: seed,
		Padding: []byte{},
	}
	fmt.Printf("Padding: TESTING: %x\n\n", odohQuery.Padding)

	odnsMessage, err := publicKey.EncryptQuery(odohQuery)
	encryptionTime := time.Since(start)
	if err != nil {
		log.Fatalf("Unable to Encrypt oDoH Question with provided Public Key of Resolver")
		return odoh.ObliviousDNSQuery{}, nil, err
	}

	log.Printf("Time to Prepare DNS Question : [%v]\n", prepareQuestionTime.Milliseconds())
	log.Printf("Time to Encrypt DNS Question : [%v]\n", encryptionTime.Milliseconds())

	return odohQuery, odnsMessage.Marshal(), nil
}