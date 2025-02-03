# AUTHOR: Pusker Ghimire
#
# PURPOSE:
#
#  To export all user who are inactive for last 90 days
#
# REQUIREMENTS:
#Install-Module -Name AWSPowerShell
#Install-WindowsFeature RSAT-AD-PowerShell


#Changelog:
# Pusker - Added Max number of local .csv
# Pusker - Added Max number of log files
# Pusker - Added a function to test email

# Import necessary modules
Import-Module ActiveDirectory

# Script settings
$ScriptName = "AWS_AD_Enabled_Users"
$DateSuffix = (Get-Date -Format "yyyyMMddss")
$CsvFileName = "90-Days-inactive_user_accounts_$DateSuffix.csv"
$LogFileName = "log_$DateSuffix.txt"
$CsvFolderPath = "C:\reports\inactiveaccounts"
$LogFolderPath = "C:\\reports\inactiveaccounts\logs"
$MaxCsvFiles = 5
$MaxLogFiles = 6

# Create folders if not exist
If (!(Test-Path -Path $CsvFolderPath)) {
    New-Item -ItemType Directory -Path $CsvFolderPath
}
If (!(Test-Path -Path $LogFolderPath)) {
    New-Item -ItemType Directory -Path $LogFolderPath
}

# Full paths for CSV and Log files
$CsvFilePath = Join-Path $CsvFolderPath $CsvFileName
$LogFilePath = Join-Path $LogFolderPath $LogFileName

# Email configuration (Enable/Disable)
$EmailAlertsEnabled = $true # Set this to $false to disable email alerts

# Import XML configuration
$ConfigFile = "config.xml"
$Config = [xml](Get-Content $ConfigFile)

# Extract region, bucket, and credentials
$Region = $Config.Settings.RegionEndpoint
$BucketName = $Config.Settings.BucketName
$AccessKeyID = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Config.Settings.AccessKeyID))
$SecretAccessKey = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Config.Settings.SecretAccessKey))

# Email credentials for alerts
$SmtpUser = $Config.Settings.SmtpUser
$SmtpPassword = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Config.Settings.SmtpPassword))

# Logging function
function Log-Message {
    Param (
        [string]$Message
    )
    Add-Content -Path $LogFilePath -Value "$(Get-Date -Format G): $Message"
}

# Function to send email alerts
function Send-Alert {
    Param (
        [string]$Message
    )
    
    if ($EmailAlertsEnabled) {
        $password = ConvertTo-SecureString $SmtpPassword -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential ($SmtpUser, $password)
        $MailParams = @{
            SmtpServer                 = "smtp.office365.com"
            Port                       = "587"
            UseSSL                     = $true
            Credential                 = $credential
            From                       = $SmtpUser
            To                         = "test@abc.com" 
            Subject                    = "$ScriptName Alert - $(Get-Date -Format g)"
            Priority                   = "High"
            Body                       = $Message
            Attachments                = $LogFilePath
            DeliveryNotificationOption = "OnFailure"
        }
        
        try {
            Send-MailMessage @MailParams
        } catch {
            Log-Message "Error sending alert: $_"
        }
    } else {
        Log-Message "Email alerts are disabled."
    }
}

# Function to get all inactive users from AWS Managed AD
function Get-InactiveUsers {
    try {
        # Calculate the date 90 days ago from today
        $dateThreshold = (Get-Date).AddDays(-90)

        # Fetch all inactive users (no logon activity in last 90 days)
        $users = Get-ADUser -Filter { LastLogonDate -lt $dateThreshold -or LastLogonDate -notlike "*" } -Property SamAccountName, Name, LastLogonDate, Mail, Enabled

        $inactiveUserList = $users | Select-Object @{
            Name       = 'UserID';
            Expression = { $_.SamAccountName }
        }, @{
            Name       = 'UserName';
            Expression = { $_.Name }
        }, @{
            Name       = 'LastActiveDate';
            Expression = { $_.LastLogonDate }
        }, @{
            Name       = 'Email';
            Expression = { $_.Mail }
        }, @{
            Name       = 'AccountStatus';
            Expression = { if ($_.Enabled) { 'Active' } else { 'Inactive' } }
        }

        return $inactiveUserList
    } catch {
        Log-Message "Error fetching inactive users: $_"
        Send-Alert "Error fetching inactive users: $_"
        throw
    }
}



# Function to generate CSV
function Export-UserListToCSV {
    Param (
        [array]$UserList,
        [string]$FilePath
    )
    try {
        $UserList | Export-Csv -Path $FilePath -NoTypeInformation
        Log-Message "User list exported to CSV: $FilePath"
    } catch {
        Log-Message "Error exporting user list to CSV: $_"
        Send-Alert "Error exporting user list to CSV: $_"
        throw
    }
}

# Function to upload file to S3
function Upload-ToS3 {
    Param (
        [string]$FilePath,
        [string]$BucketName,
        [string]$Region
    )
    
    try {
        $env:AWS_ACCESS_KEY_ID = $AccessKeyID
        $env:AWS_SECRET_ACCESS_KEY = $SecretAccessKey

        $command = "aws s3 cp `"$FilePath`" s3://$BucketName/ADD/reports --region $Region"
        Invoke-Expression $command

        Remove-Item Env:AWS_ACCESS_KEY_ID
        Remove-Item Env:AWS_SECRET_ACCESS_KEY

        Log-Message "File uploaded to S3: $FilePath"
    } catch {
        Log-Message "Error uploading file to S3: $_"
        Send-Alert "Error uploading file to S3: $_"
        throw
    }
}

# Function to maintain last N files
function Maintain-FileLimit {
    Param (
        [string]$FolderPath,
        [string]$FilePattern,
        [int]$MaxFiles
    )
    $files = Get-ChildItem -Path $FolderPath -Filter $FilePattern | Sort-Object LastWriteTime -Descending
    if ($files.Count -gt $MaxFiles) {
        $filesToDelete = $files | Select-Object -Skip $MaxFiles
        $filesToDelete | ForEach-Object { Remove-Item $_.FullName }
    }
}

# Main workflow

    # Get enabled users from AWS Managed AD
try {
    Log-Message "Script execution started"

    # Test email functionality
    #Test-Email
    $enabledUsers = Get-EnabledUsers
    
    # Export the enabled users to CSV
    Export-UserListToCSV -UserList $enabledUsers -FilePath (Join-Path $CsvFolderPath $CsvFileName)
    
    # Maintain CSV file limit
    Maintain-FileLimit -FolderPath $CsvFolderPath -FilePattern "inactive_user_accounts_*.csv" -MaxFiles $MaxCsvFiles
    
    # Get inactive users
    $inactiveUsers = Get-InactiveUsers
    
    # Export the inactive users to a separate CSV
    $InactiveCsvFileName = "inactive_user_accounts_$DateSuffix.csv"
    Export-UserListToCSV -UserList $inactiveUsers -FilePath (Join-Path $CsvFolderPath $InactiveCsvFileName)
    
    # Maintain CSV file limit again
    Maintain-FileLimit -FolderPath $CsvFolderPath -FilePattern "inactive_user_accounts_*.csv" -MaxFiles $MaxCsvFiles
    
    # Upload the CSVs to S3
    Upload-ToS3 -FilePath (Join-Path $CsvFolderPath $CsvFileName) -BucketName $BucketName -Region $Region
    Upload-ToS3 -FilePath (Join-Path $CsvFolderPath $InactiveCsvFileName) -BucketName $BucketName -Region $Region
    
    # Maintain log file limit
    Maintain-FileLimit -FolderPath $LogFolderPath -FilePattern "log_*.txt" -MaxFiles $MaxLogFiles

    Log-Message "Script execution completed successfully"
} catch {
    Log-Message "Script execution failed: $_"
    Send-Alert "Script execution failed: $_"
}


