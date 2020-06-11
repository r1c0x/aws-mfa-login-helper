package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"gopkg.in/ini.v1"
)

// OTP code from https://gist.github.com/tilaklodha
// Append extra 0s if the length of otp is less than 6
// If otp is "1234", it will return it as "001234"
func prefix0(otp string) string {
	if len(otp) == 6 {
		return otp
	}
	for i := (6 - len(otp)); i > 0; i-- {
		otp = "0" + otp
	}
	return otp
}

func getHOTPToken(secret string, interval int64) string {

	// Converts secret to base32 Encoding. Base32 encoding desires a 32-character
	// subset of the twenty-six letters A–Z and ten digits 0–9
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		panic(err)
	}
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, uint64(interval))

	// Signing the value using HMAC-SHA1 Algorithm
	hash := hmac.New(sha1.New, key)
	hash.Write(bs)
	h := hash.Sum(nil)

	// We're going to use a subset of the generated hash.
	// Using the last nibble (half-byte) to choose the index to start from.
	// This number is always appropriate as it's maximum decimal 15, the hash will
	// have the maximum index 19 (20 bytes of SHA1) and we need 4 bytes.
	o := (h[19] & 15)

	var header uint32
	// Get 32 bit chunk from hash starting at the o
	r := bytes.NewReader(h[o : o+4])
	err = binary.Read(r, binary.BigEndian, &header)
	if err != nil {
		panic(err)
	}

	// Ignore most significant bits as per RFC 4226.
	// Takes division from one million to generate a remainder less than < 7 digits
	h12 := (int(header) & 0x7fffffff) % 1000000

	// Converts number as a string
	otp := strconv.Itoa(int(h12))

	return prefix0(otp)
}

func getTOTPToken(secret string) string {
	// The TOTP token is just a HOTP token seeded with every 30 seconds.
	interval := time.Now().Unix() / 30
	return getHOTPToken(secret, interval)
}

func getMfaSerialUser() string {
	svc := iam.New(session.New())
	input := &iam.GetUserInput{}

	result, err := svc.GetUser(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
	}
	return (aws.StringValue(result.User.UserName))
}

func getAccountID(accessKey string) string {

	svc := sts.New(session.New())
	input := &sts.GetAccessKeyInfoInput{
		AccessKeyId: &accessKey,
	}
	result, err := svc.GetAccessKeyInfo(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case sts.ErrCodeRegionDisabledException:
				fmt.Println(sts.ErrCodeRegionDisabledException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}

	}
	return aws.StringValue(result.Account)

}

func getSessionToken(serialNumberUser string, accountID string, otp string) (string, string, string) {

	svc := sts.New(session.New())
	input := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(3600),
		SerialNumber:    aws.String("arn:aws:iam::" + accountID + ":mfa/" + serialNumberUser),
		TokenCode:       aws.String(otp),
	}

	result, err := svc.GetSessionToken(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case sts.ErrCodeRegionDisabledException:
				fmt.Println(sts.ErrCodeRegionDisabledException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}

	}
	return aws.StringValue(result.Credentials.AccessKeyId), aws.StringValue(result.Credentials.SecretAccessKey), aws.StringValue(result.Credentials.SessionToken)

}

func createMfaProfile(awsCredentialPath string) {
	homeDir := os.Getenv("HOME")
	if awsCredentialPath == "default" {
		awsCredentialPath = homeDir + "/.aws/credentials"
	}
	profile := os.Args[1]
	region := os.Args[2]
	totpSecret := os.Args[3]
	mfaProfile := profile + "_mfa"

	os.Setenv("AWS_PROFILE", profile)
	cfg, err := ini.Load(awsCredentialPath)
	if err != nil {
		fmt.Printf("Fail to read file: %v", err)
		os.Exit(1)
	}
	accountID := getAccountID(cfg.Section(profile).Key("aws_access_key_id").String())
	mfaSerialUser := getMfaSerialUser()
	totpToken := getTOTPToken(totpSecret)

	accessKey, secretKey, sessionToken := getSessionToken(mfaSerialUser, accountID, totpToken)

	fmt.Println("totptoken: " + totpToken)
	fmt.Println("account ID: " + accountID)
	fmt.Println("mfa serial user: " + mfaSerialUser)
	fmt.Println("session token: " + sessionToken)

	cfg.Section(mfaProfile).Key("aws_access_key_id").SetValue(accessKey)
	cfg.Section(mfaProfile).Key("aws_secret_access_key").SetValue(secretKey)
	cfg.Section(mfaProfile).Key("aws_session_token").SetValue(sessionToken)
	cfg.Section(mfaProfile).Key("region").SetValue(region)
	cfg.SaveTo(awsCredentialPath)
}

func main() {
	if len(os.Args) != 5 {
		fmt.Println("Usage: aws-mfa-login-helper <profile> <region> <google_authenticator_secret> [aws_credential_path:default]")
		os.Exit(1)
	}

	createMfaProfile(os.Args[4])
}
