import osproc, os, strformat

let CurrentDirectory = getCurrentDir()

when defined(windows):
    let ext = ".exe"
elif defined(linux):
    let ext = ""

proc build(): bool =
    echo "Run MCD"
    result = true

    let apikey = getEnv("API_KEY")
    doAssert apikey != ""

    if not dirExists("./tests/MaliciousTest"):
        discard execCmdEx(&"git clone https://gitlab.com/malicious-commit-detector/malicioustest.git ./tests/MaliciousTest")

    var (output, errC) = execCmdEx(&"{CurrentDirectory}/bin/mcd{ext} detectCommit --apikey {apikey} --config ./tests/mcd-config.toml -w 60")
    echo output
    
    removeDir("./tests/MaliciousTest")
    
    if errC != QuitSuccess:
        return false


doAssert build()