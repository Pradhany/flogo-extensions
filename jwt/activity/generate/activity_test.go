package jwt

import (
	"fmt"
	"testing"

	"github.com/project-flogo/core/activity"
	"github.com/project-flogo/core/support/test"
	"github.com/stretchr/testify/assert"
)

func TestRegister(t *testing.T) {

	ref := activity.GetRef(&Activity{})
	act := activity.Get(ref)

	assert.NotNil(t, act)
}

func TestSign(t *testing.T) {
	act := &Activity{}
	tc := test.NewActivityContext(act.Metadata())

	fmt.Println("#######   Testing JWT Sign")

	//test3
	fmt.Println("===> Test3")
	tc.SetInput("payload", `{"foo":"bar","nbf":1444478400}`)
	tc.SetInput("secret", "secret")
	tc.SetInput("algorithm", "HS256")
	act.Eval(tc)

	if tc.GetOutput("token") == nil {
		fmt.Println("******** Test Failed  ********")
		t.Fail()
	} else {
		fmt.Println("******** Result: ", tc.GetOutput("token"))
	}

	//test6
	fmt.Println("===> Test6")
	tc.SetInput("algorithm", "RS256")
	tc.SetInput("payload", `{"Email":"jrocket@example.com","GivenName":"Johnny","Role":["Manager","Project Administrator"],"Surname":"Rocket","aud":"www.example.com","exp":1753512665,"iat":1721976665,"iss":"Online JWT Builder","sub":"jrocket@example.com"}`)
	tc.SetInput("secret", `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCXwJ3Hp21kj7/gTbX9hYzkfqDdqPdadz6YE1uu+Y1HWOBmMZyi
1M39d4+wGMRIbA4xhRvihR6d1eZnV5vD3lbAQaP/D03uo03aClkcP+TV3c4Z7xaw
9dL2aUHcuX5s053fEhwgod1XiqQJY1iqXgZQQdcmwFYlWSumME/9woi72QIDAQAB
AoGAT26DJ/57RCf6R25l1E4TcYbWrS/ESZYhLXj0hKIbUT00OEm/s3uwVvw+Oe68
zyvAQitqbSdA310XPQCeh+fZf/qEqDO94rBvSMBsW5z0OxwV+2fZvnrPgBUTPlff
bR734/MGj1KQinDrBFvJPoLd36sNZiv/Rkm/yhqT8a8COAECQQDFuhishc3xgN+I
uHTkzzgTgrPz40jVgdKqdxVsPRHyZJUgoCN1n2mb19cktpKERRRnBNFiwAzxIP5k
OMWVIMZPAkEAxHnhMFkng1aU5Yeb0tjHssOUzat6mYarl3vT4CM6agWvWrgmiZ22
hNixt14TdjMgFi/RHcjTFdjV7cbjnjZ5VwJBAKxiR7q52UfxNHGtZ3RI2TnhXOSH
xmsmiTVHJy07vRbX7FAKbX/R4LAXKKIAbpLU6ym5wJdYmq/rNP7JpDEU5u8CQGJv
+g4iLPTVtUYGmmCaMftzmCMvbf5rhZ8g8DeVDtg9vuyB5PT/6olGlEudu7x1wva6
wFfe3TtN52j5Q+NpwYMCQQCDr4LnzlJrw7RjIe0Yih5JLnsIR31ENT/8Dk5EdN3k
Lj5MtNY7vikHA5glFtnpnGpDN289AAm2zy3J7c75RiOW
-----END RSA PRIVATE KEY-----`)
	tc.SetInput("mode", "Sign")
	act.Eval(tc)

	if tc.GetOutput("token") == nil {
		fmt.Println("******** Test Failed  ********")
		t.Fail()
	} else {
		fmt.Println("******** Result: ", tc.GetOutput("token"))
	}
}
