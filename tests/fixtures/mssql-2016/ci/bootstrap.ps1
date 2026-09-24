$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ExpectedExpressHash = "123F35EB622E56A45A6A0AD951760AABA0DF8B908F30ED5D4AA0F93BC93FD448"
$ExpectedGdrHash = "E86109191B199A1347AD7FF62D2C785D1CAA5538FEDAFDF096C87ED0E78E0201"
$ExpectedVersion = "13.0.6500.1"
$MediaRoot = $PSScriptRoot
$Stage = "bootstrap_start"

function Write-CiStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $port = New-Object System.IO.Ports.SerialPort "COM1", 115200, "None", 8, "One"
    try {
        $port.NewLine = "`n"
        $port.Open()
        $port.WriteLine($Message)
    }
    finally {
        if ($port.IsOpen) {
            $port.Close()
        }
        $port.Dispose()
    }
}

function Set-CiStage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $script:Stage = $Name
    Write-CiStatus -Message "DFE_SQL2016_STAGE $Name"
}

function Invoke-Installer {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList,
        [Parameter(Mandatory = $true)]
        [string]$Operation
    )

    $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -WindowStyle Hidden -Wait -PassThru
    if ($process.ExitCode -eq 3010) {
        throw "$Operation requires a reboot, but this provisioning run has no resumable post-reboot state"
    }
    if ($process.ExitCode -ne 0) {
        throw "$Operation failed with exit code $($process.ExitCode)"
    }
}

function Wait-SqlListener {
    param(
        [Parameter(Mandatory = $true)]
        [int]$MaximumAttempts
    )

    for ($attempt = 1; $attempt -le $MaximumAttempts; $attempt++) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $client.Connect("127.0.0.1", 1433)
            return
        }
        catch [System.Net.Sockets.SocketException] {
            if ($attempt -eq $MaximumAttempts) {
                throw "SQL Server did not listen on TCP port 1433 after $MaximumAttempts attempts"
            }
        }
        finally {
            $client.Dispose()
        }
        Start-Sleep -Seconds 2
    }
}

try {
    Set-CiStage -Name "bootstrap_started"
    $secretPath = Join-Path $MediaRoot "fixture-secret.txt"
    if (-not (Test-Path -LiteralPath $secretPath -PathType Leaf)) {
        throw "Generated fixture password file is missing"
    }
    $fixturePassword = (Get-Content -LiteralPath $secretPath -Raw).TrimEnd([char[]]"`r`n")
    if (
        $fixturePassword.Length -lt 16 -or
        $fixturePassword.Length -gt 64 -or
        $fixturePassword -cnotmatch "^[A-Za-z0-9_.!@#%+=,-]+$" -or
        $fixturePassword -cnotmatch "[A-Z]" -or
        $fixturePassword -cnotmatch "[a-z]" -or
        $fixturePassword -notmatch "[0-9]" -or
        $fixturePassword -notmatch "[_.!@#%+=,-]"
    ) {
        throw "Generated fixture password does not satisfy the provisioning contract"
    }

    $expressInstaller = Join-Path $MediaRoot "SQLEXPR_x64_ENU.exe"
    $gdrInstaller = Join-Path $MediaRoot "SQLServer2016-KB5102340-x64.exe"
    foreach ($requiredPath in @($expressInstaller, $gdrInstaller)) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "Required provisioning file is missing: $requiredPath"
        }
    }

    $localRoot = "C:\dfe-sql2016-ci"
    if (Test-Path -LiteralPath $localRoot) {
        throw "Fresh guest provisioning directory already exists: $localRoot"
    }
    New-Item -ItemType Directory -Path $localRoot | Out-Null
    $localExpressInstaller = Join-Path $localRoot "SQLEXPR_x64_ENU.exe"
    $localGdrInstaller = Join-Path $localRoot "SQLServer2016-KB5102340-x64.exe"
    Copy-Item -LiteralPath $expressInstaller -Destination $localExpressInstaller
    Copy-Item -LiteralPath $gdrInstaller -Destination $localGdrInstaller
    if ((Get-FileHash -LiteralPath $localExpressInstaller -Algorithm SHA256).Hash -ne $ExpectedExpressHash) {
        throw "SQL Server 2016 SP3 Express media hash mismatch"
    }
    if ((Get-FileHash -LiteralPath $localGdrInstaller -Algorithm SHA256).Hash -ne $ExpectedGdrHash) {
        throw "SQL Server 2016 GDR media hash mismatch"
    }
    Set-CiStage -Name "media_verified"

    $extractionRoot = Join-Path $localRoot "SQLEXPR_x64_ENU"
    Invoke-Installer -FilePath $localExpressInstaller -Operation "SQL Server 2016 SP3 Express extraction" -ArgumentList @(
        "/Q",
        "/X:$extractionRoot"
    )
    $setupInstaller = Join-Path $extractionRoot "SETUP.EXE"
    if (-not (Test-Path -LiteralPath $setupInstaller -PathType Leaf)) {
        throw "SQL Server setup executable is missing after extraction"
    }
    Set-CiStage -Name "base_extracted"

    Invoke-Installer -FilePath $setupInstaller -Operation "SQL Server 2016 SP3 Express installation" -ArgumentList @(
        "/Q",
        "/ACTION=Install",
        "/FEATURES=SQLEngine",
        "/INSTANCENAME=SQLEXPRESS",
        "/SQLSVCACCOUNT=`"NT AUTHORITY\NETWORK SERVICE`"",
        "/SQLSVCSTARTUPTYPE=Automatic",
        "/SQLSYSADMINACCOUNTS=`"BUILTIN\Administrators`"",
        "/SECURITYMODE=SQL",
        "/SAPWD=$fixturePassword",
        "/TCPENABLED=1",
        "/NPENABLED=0",
        "/UpdateEnabled=False",
        "/IACCEPTSQLSERVERLICENSETERMS"
    )
    Set-CiStage -Name "engine_installed"

    Invoke-Installer -FilePath $localGdrInstaller -Operation "SQL Server 2016 GDR KB5102340 installation" -ArgumentList @(
        "/quiet",
        "/IAcceptSQLServerLicenseTerms",
        "/Action=Patch",
        "/AllInstances"
    )
    Set-CiStage -Name "gdr_installed"

    $instanceNamesPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
    $instanceId = (Get-ItemProperty -LiteralPath $instanceNamesPath -Name "SQLEXPRESS").SQLEXPRESS
    if ([string]::IsNullOrWhiteSpace($instanceId)) {
        throw "SQL Server setup did not register the SQLEXPRESS instance"
    }
    $tcpPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceId\MSSQLServer\SuperSocketNetLib\Tcp"
    Set-ItemProperty -LiteralPath $tcpPath -Name "Enabled" -Type DWord -Value 1
    Set-ItemProperty -LiteralPath $tcpPath -Name "ListenOnAllIPs" -Type DWord -Value 1
    $ipAllPath = Join-Path $tcpPath "IPAll"
    Set-ItemProperty -LiteralPath $ipAllPath -Name "TcpDynamicPorts" -Value ""
    Set-ItemProperty -LiteralPath $ipAllPath -Name "TcpPort" -Value "1433"

    $serviceName = 'MSSQL$SQLEXPRESS'
    Set-Service -Name $serviceName -StartupType Automatic
    Restart-Service -Name $serviceName -Force
    Wait-SqlListener -MaximumAttempts 90
    if (-not (Get-NetFirewallRule -DisplayName "DFE SQL Server 2016 CI fixture" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "DFE SQL Server 2016 CI fixture" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 1433 | Out-Null
    }
    Set-CiStage -Name "tcp_configured"

    $connectionString = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
    $connectionString.DataSource = "127.0.0.1,1433"
    $connectionString.InitialCatalog = "master"
    $connectionString.UserID = "sa"
    $connectionString.Password = $fixturePassword
    $connectionString.Encrypt = $false
    $connectionString.ConnectTimeout = 30
    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString.ConnectionString
    try {
        $connection.Open()
        $command = $connection.CreateCommand()
        $command.CommandText = "SELECT CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductVersion'))"
        $version = [string]$command.ExecuteScalar()
    }
    finally {
        $connection.Dispose()
    }
    if ($version -ne $ExpectedVersion) {
        throw "SQL Server patch level is unexpected: actual=$version required=$ExpectedVersion"
    }

    $status = [ordered]@{
        state = "ready"
        product_version = $version
        instance = "SQLEXPRESS"
        tcp_port = 1433
        completed_at_utc = [DateTime]::UtcNow.ToString("o")
    }
    $status | ConvertTo-Json | Set-Content -LiteralPath "C:\dfe-sql2016-ci-ready.json" -Encoding UTF8
    Write-CiStatus -Message "DFE_SQL2016_READY product_version=$version instance=SQLEXPRESS tcp_port=1433"
}
catch {
    $exceptionType = $_.Exception.GetType().FullName -replace "[^A-Za-z0-9_.]", "_"
    $hresult = "0x{0:X8}" -f ($_.Exception.HResult -band 0xFFFFFFFFL)
    try {
        Write-CiStatus -Message "DFE_SQL2016_ERROR stage=$Stage type=$exceptionType hresult=$hresult"
    }
    catch {
        Write-Error "Guest provisioning failed and COM1 status publication also failed"
    }
    throw
}
