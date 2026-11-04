package commands

import "time"

// nowFunc is overridable in tests.
var nowFunc = time.Now
