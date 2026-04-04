$ErrorActionPreference = 'Stop'

function Cleanup {
    try {
        docker compose down -v --remove-orphans | Out-Null
    }
    catch {
        Write-Host "[smoke] cleanup skipped: $($_.Exception.Message)"
    }
}

function Wait-Health {
    param(
        [string[]]$Urls,
        [int]$Retries = 60,
        [int]$SleepSeconds = 2
    )

    for ($i = 1; $i -le $Retries; $i++) {
        $allOk = $true
        foreach ($url in $Urls) {
            try {
                $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5
                if ($resp.StatusCode -ne 200) {
                    $allOk = $false
                    break
                }
            }
            catch {
                $allOk = $false
                break
            }
        }

        if ($allOk) {
            Write-Host "[smoke] health checks passed"
            return
        }

        if ($i -eq $Retries) {
            throw "health checks failed after $Retries attempts"
        }

        Start-Sleep -Seconds $SleepSeconds
    }
}

function Assert-Json {
    param(
        [string]$Url,
        [string]$Name,
        [int[]]$AllowedStatus = @(200),
        [hashtable]$Headers = @{}
    )

    $status = $null
    $body = $null
    try {
        $resp = Invoke-WebRequest -Uri $Url -Headers $Headers -UseBasicParsing -TimeoutSec 10
        $status = [int]$resp.StatusCode
        $body = $resp.Content
    }
    catch {
        if ($_.Exception.Response) {
            $status = [int]$_.Exception.Response.StatusCode
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $body = $reader.ReadToEnd()
            $reader.Close()
        }
        else {
            throw "${Name} request failed: $($_.Exception.Message)"
        }
    }

    if ($AllowedStatus -notcontains $status) {
        Write-Host "[smoke] ${Name} body:"
        Write-Host $body
        throw "${Name} returned unexpected status: $status"
    }

    if ([string]::IsNullOrWhiteSpace($body)) {
        throw "${Name} returned empty body"
    }

    try {
        $null = $body | ConvertFrom-Json
    }
    catch {
        throw "${Name} is not valid JSON"
    }

    Write-Host "[smoke] ${Name} check passed (status=$status)"
}

try {
    docker compose up -d --build

    Wait-Health -Urls @('http://127.0.0.1:8000/healthz') -Retries 60 -SleepSeconds 2
    Assert-Json -Url 'http://127.0.0.1:8000/openapi.json' -Name 'openapi' -AllowedStatus @(200)
    Assert-Json -Url 'http://127.0.0.1:8000/banking/accounts' -Name 'banking' -AllowedStatus @(200, 401, 403, 503) -Headers @{ 'X-User-Id' = '000000001' }
}
finally {
    Cleanup
}
