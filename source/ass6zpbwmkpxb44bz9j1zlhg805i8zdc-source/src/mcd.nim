import httpclient, mimetypes, json, os, osproc, strformat
import cligen, colorizeEcho, parsetoml

# Contantes
const OKStatus = "200 OK"
const NbTryAnalyzeCompleted = 4
const WaitTime = 25

# HTTP
let mimes = newMimetypes()
var client = newHttpClient()
client.headers = newHttpHeaders({ "Content-Type": "application/json" })

# Types
type 
    Config = object # Configuration
        build_command: seq[string] # List of commands to build project
        build_dir: string # Folder name to build the project in relative format
        file_path: seq[string] # Files to analyse
        project_dir: string # Folder path where is the project

    AVResult = enum # AV result
        OK,
        KO,
        ERROR

    ProjectVirusState = enum # Current project virus status
        NOVIRUS,
        VIRUS,
        NONE


template cd*(dir: string, body: untyped) =
    ## Sets the current dir to ``dir``, executes ``body`` and restores the
    ## previous working dir.
    let lastDir = getCurrentDir()
    setCurrentDir(dir)
    body
    setCurrentDir(lastDir)


proc parseConfig(configFilePath: string): ref Config =
    ## Parse config file to extract and create configuration
    ## ``configFilePath`` config file path
    colorizeEcho "[cyan]Configuration file: " & configFilePath
    if fileExists(configFilePath):
        var absoluteConfigFilePath = configFilePath
        if not isAbsolute(configFilePath):
            absoluteConfigFilePath = absolutePath(configFilePath)

        var config = new Config
        config.build_dir = "."

        let configTOML = parsetoml.parseFile(absoluteConfigFilePath)
        if configTOML.hasKey("build_command"):
            for command in configTOML["build_command"].getElems():
                config.build_command.add(command.getStr())
        else:
            colorizeEcho "[red]Error: build command not found"
            return nil

        if configTOML.hasKey("project_dir"):
            config.project_dir = configTOML["project_dir"].getStr()

            if not isAbsolute(config.project_dir):
                config.project_dir = absolutePath(config.project_dir, parentDir(absoluteConfigFilePath))

                if not dirExists(config.project_dir):
                    colorizeEcho "[red]Error: project dir not found in " & config.project_dir
                    return nil

        if configTOML.hasKey("build_dir"):
            config.buildDir = config.project_dir / configTOML["build_dir"].getStr()
        else:
            colorizeEcho "[red]Error: build dir not found"
            return nil

        if configTOML.hasKey("file_path"):
            for file in configTOML["file_path"].getElems():
                config.file_path.add(config.project_dir / file.getStr())
        else:
            colorizeEcho "[red]Error: file path not found"
            return nil

        return config


proc checkFile(file: string, wait = WaitTime, threshold: int): AVResult =
    ## Request to VirusTotal on a file
    ## ``file`` the file to check
    ## ``wait`` time to wait response
    ## ``threshold`` detection threshold
    let data = newMultipartData()
    data.addFiles({"file": file}, mimeDb = mimes)

    var response = client.request("https://www.virustotal.com/api/v3/files", httpMethod = HttpPost, multipart=data)
    if response.status != OKStatus:
        colorizeEcho "[red]Error: post file"
        return ERROR

    # Wait 2sec
    colorizeEcho &"[cyan]⏳ Wait analyze {$wait} sec ..."
    sleep(wait * 1000)
    var 
        analyzeCompleted = false
        nbTry = 0

    while not analyzeCompleted and nbTry < NbTryAnalyzeCompleted:
        var jsonBody = parseJson(response.body)
        let id = jsonBody["data"]["id"].getStr()
        response = client.request("https://www.virustotal.com/api/v3/analyses/" & id, httpMethod = HttpGet)

        if response.status != OKStatus:
            colorizeEcho "[red]Error: get analyze"
            return ERROR

        jsonBody = parseJson(response.body)
        let sha256 = jsonBody["meta"]["file_info"]["sha256"].getStr()
        if jsonBody["data"]["attributes"]["status"].getStr() == "completed":
            analyzeCompleted = true

            # Extract result
            let 
                suspicious = jsonBody["data"]["attributes"]["stats"]["suspicious"].getInt()
                malicious = jsonBody["data"]["attributes"]["stats"]["malicious"].getInt()
                undetected = jsonBody["data"]["attributes"]["stats"]["undetected"].getInt()

            if (suspicious + malicious) <= threshold and undetected > 0:
                colorizeEcho &"[green]✔️  {extractFilename(file)}"
                return OK
            else:
                colorizeEcho &"[red]❌  {extractFilename(file)}"
                colorizeEcho &"[red]  See https://www.virustotal.com/gui/file/{sha256}/detection"
                return KO
        else:
            # Wait 2sec
            colorizeEcho &"[cyan]    analyze not completed, wait {$wait} sec ..."
            sleep(wait * 1000)
            inc nbTry

    colorizeEcho "[yellow]💤 Timeout to get analyze"
    return ERROR


proc analyze(apikey: string, paths: seq[string], wait = WaitTime, threshold = 2): int =
    ## Analyse if liste of file are malwares
    ## ``apikey`` API key from VirusTotal
    ## ``paths`` list of files to check
    ## ``wait`` time to wait response
    ## ``threshold`` detection threshold
    if apikey == "":
        colorizeEcho "[red]Error: apikey is empty"
        return 1
    else:
        client.headers.add("x-apikey", apikey)

        for file in paths:
            if not fileExists(file):
                colorizeEcho &"[red]Error: file {file} not found"
            else:
                let res = checkFile(file, wait, threshold)
                if res == ERROR:
                    return 2
    return 0


proc detectCommit(apikey: string, config: string, startCommit = "", lastCommit = "", branch = "", wait = WaitTime, threshold = 2): int =
    ## Detect when a built malware is detected in a project
    ## ``apikey`` API key from VirusTotal
    ## ``config`` MCD configure file path
    ## ``startCommit`` start commit in the branch
    ## ``lastCommit`` last commit in the branch
    ## ``branch`` the project git branch
    ## ``wait`` time to wait response
    ## ``threshold`` detection threshold
    if apikey == "":
        colorizeEcho "[red]Error: apikey is empty"
        return 1
    else:
        client.headers.add("x-apikey", apikey)

    # Read config file
    let configuration = parseConfig(config)
    if configuration == nil:
        colorizeEcho "[red]Error: parsing config file or build directory not found"
        return 2

    # Check if project folder exists
    if not os.dirExists(configuration.project_dir):
        colorizeEcho &"[red]Error: project folder not found {configuration.project_dir}"
        return 2

    # Get project directory from config directory
    cd configuration.project_dir:

        # Get has list
        var hashList: seq[string]

        let gitPath = findExe("git")
        if gitPath.len != 0:
            var 
                gitProcess = if branch == "":
                                startProcess(gitPath, "", args=["log", "--pretty=format:\"%h\""])
                            else:
                                startProcess(gitPath, "", args=["log", "--pretty=format:\"%h\"", branch])
                exitCode: int
            let (lines, exCode) = gitProcess.readLines()

            if exCode == 0:
                for line in lines:
                    hashList.add(line)
            gitProcess.close()

            if exitCode != 0:
                colorizeEcho &"[red]Error: {$exitCode}"
                return 3

        # Check if start and last commit found
        if startCommit != "" and not hashList.contains(startCommit):
            colorizeEcho "[red]Error: " & startCommit & " not found"
            return 4

        if lastCommit != "" and not hashList.contains(lastCommit):
            colorizeEcho "[red]Error: " & lastCommit & " not found"
            return 5

        # Run detection loop
        var initProjectState = NONE
        for hashKey in hashList:
            # Checkout
            colorizeEcho &"[cyan]🔍 Commit {hashKey}"
            var output = execCmdEx(&"{gitPath} checkout {hashKey}")
            if output.exitCode != 0:
                colorizeEcho &"[red]Error: checkout hash key {hashKey}"
                return 6
            else:
                # Change build_dir to build and check file
                if not dirExists(configuration.buildDir):
                    createDir(configuration.buildDir)
                cd configuration.buildDir:
                    # Run build commands
                    colorizeEcho &"[cyan]🔨 Build"
                    for cmd in configuration.build_command:
                        output = execCmdEx(cmd)
                        if output.exitCode != 0:
                            colorizeEcho &"[red]Error: build command -> {cmd}"
                            return 7

                    # Check all files
                    var 
                        res = OK
                    for file in configuration.file_path:
                        if not fileExists(file):
                            colorizeEcho &"[red]Error: file {file} not found, maybe not build in this commit"
                        else:
                            res = checkFile(file, wait, threshold)
                            if res == ERROR:
                                return 8
                            elif res == OK:
                                if initProjectState == NONE:
                                    initProjectState = NOVIRUS
                            else:
                                if initProjectState == NONE:
                                    initProjectState = VIRUS

                        if initProjectState != NONE:
                            if res == OK and initProjectState == VIRUS:
                                colorizeEcho &"[green]Commit " & hashKey & " is the last commit without generated malicous files"
                                return 0
                            elif res == KO and initProjectState == NOVIRUS:
                                colorizeEcho &"[green]Commit " & hashKey & " is the first commit with generated malicous files"
                                return 0

    colorizeEcho &"[cyan]No more commit"
                
    return 0


when isMainModule:
    dispatchMulti([analyze, doc = "Check several files", help = { "apikey": "API key of your VirusTotal account", "wait": "waiting time of the analysis in seconds", "threshold": "detection threshold for false positive"}],
                [detectCommit, doc = "Detect first commit with malicious code", help = { "apikey": "API key of your VirusTotal account", "config": "config file to build binaries for each commit", "startCommit": "start commit", "lastCommit": "latest commit", "branch": "the branch where run detection", "wait": "waiting time of the analysis in seconds", "threshold": "detection threshold for false positive"}])
