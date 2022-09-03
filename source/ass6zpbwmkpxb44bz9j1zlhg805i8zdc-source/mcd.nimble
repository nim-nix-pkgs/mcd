# Package

version       = "0.3.2"
author        = "Arnaud Moura"
description   = "Application to detect which commit generates malicious code detection by antivirus software."
license       = "MIT"
srcDir        = "src"
bin           = @["mcd"]
binDir        = "bin"

backend       = "c"


# Dependencies

requires "nim >= 1.4.0"
requires "parsetoml >= 0.5.0"
requires "cligen >= 1.2.2"
requires "colorizeEcho"

task test, "Run build and test":
  echo "Build"
  exec "nimble build -y"
  echo "Run tests"
  exec "testament cat /"