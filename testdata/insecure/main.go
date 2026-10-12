package fixture

import "crypto/tls"

var apiKey = "fixture-secret-value"
var config = &tls.Config{InsecureSkipVerify: true}
