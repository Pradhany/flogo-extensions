package jwt

import (
	"encoding/json"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/project-flogo/core/activity"
)

// JWT is an Activity that works with JWT Tokens
// It can create, verify and decrypt JWT tokens
// inputs : {input1, input2, datatype, comparemode}
// outputs: result (bool)
type Activity struct {
	//metadata *activity.Metadata
}

func init() {
	_ = activity.Register(&Activity{}, New)
}

var activityMd = activity.ToMetadata(&Input{}, &Output{})

// Metadata returns the activity's metadata
func (a *Activity) Metadata() *activity.Metadata {
	return activityMd
}

// New create a new  activity
func New(ctx activity.InitContext) (activity.Activity, error) {

	ctx.Logger().Info("In New activity")

	act := &Activity{}
	return act, nil
}

// Eval implements api.Activity.Eval - Logs the Message
func (a *Activity) Eval(context activity.Context) (done bool, err error) {

	context.Logger().Debug("In Eval")

	in := &Input{}
	output := &Output{}
	err = context.GetInputObject(in)
	if err != nil {
		return false, err
	}
	// Get the runtime values
	sharedEncryptionKey := []byte(in.Secret)

	// context.Logger().Debug(in.Header, in.Payload, in.Token, in.Secret, in.Algorithm)
	context.Logger().Debug(in.Payload, in.Token, in.Secret, in.Algorithm)

	// Take the inputed header, payload and secret to create a new JWT
	context.Logger().Debug("In Sign")

	// var hdr map[string]interface{}
	claims := jwt.MapClaims{}

	// take the payload (claims) string and unmarshall it into a byte slice
	if err := json.Unmarshal([]byte(in.Payload), &claims); err != nil {
		context.Logger().Info("Invalid Payload: ", err)
		return false, err
	}
	context.Logger().Debug("Unmarshalled JSON payload", claims)
	alg := in.Algorithm

	// use the alg name to get the signing method
	signwith := jwt.GetSigningMethod(alg)
	context.Logger().Debug("signing: ", signwith)

	// get the tokens object (this creates the first two parts of the token, based on the determined values, rather that using the passed strings)
	token := jwt.NewWithClaims(signwith, claims)
	context.Logger().Debug("Token Object created", token)

	var key interface{}

	//  Depending on the algorithm type we need to convert  the format of the private string
	if isEs(alg) {
		key, err = jwt.ParseECPrivateKeyFromPEM(sharedEncryptionKey)
		if err != nil {
			context.Logger().Info("Bad ECDSA key", err)
			return false, err
		}
	} else if isRs(alg) {
		key, err = jwt.ParseRSAPrivateKeyFromPEM(sharedEncryptionKey)
		if err != nil {
			context.Logger().Info("Bad RSA key", err)
			return false, err
		}
	} else {
		key = sharedEncryptionKey
	}

	// Sign and get the complete encoded token as a string using the secret/key
	tokenString, err := token.SignedString(key)
	if err != nil {
		context.Logger().Info("Signing error: ", err)
		return false, err
	}

	context.Logger().Debug("Token String created", tokenString)
	output.Token = tokenString
	context.SetOutputObject(output)
	return true, nil

}
func isEs(alg string) bool {
	return strings.HasPrefix(alg, "ES")
}

func isRs(alg string) bool {
	return strings.HasPrefix(alg, "RS")
}
