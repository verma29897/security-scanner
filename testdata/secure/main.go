package fixture

import "crypto/tls"

var config = &tls.Config{MinVersion: tls.VersionTLS13}
