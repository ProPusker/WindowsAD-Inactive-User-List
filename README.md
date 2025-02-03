
# **AWS AD Inactive Users Report Script**



## **Overview**
This PowerShell script identifies users in AWS Managed Active Directory (AD) who have been inactive for the last 90 days. It exports the results to a CSV file, uploads it to an Amazon S3 bucket, and optionally sends email alerts. The script includes logging, error handling, and automated file management to maintain a clean workspace.



## **Features**
- **Inactive User Detection**: Identifies users with no logon activity in the last 90 days.
- **CSV Export**: Generates a CSV report with user details (UserID, UserName, LastActiveDate, Email, AccountStatus).
- **S3 Upload**: Securely uploads the CSV report to a specified S3 bucket.
- **Email Alerts**: Sends email notifications on success/failure (configurable).
- **Logging**: Detailed logs with timestamps and error context.
- **File Management**: Automatically retains only the most recent CSV/log files.



## **Prerequisites**
1. **PowerShell Modules**:
   - `ActiveDirectory`: Install via PowerShell:
     ```powershell
     Install-WindowsFeature RSAT-AD-PowerShell
     ```
   - `AWSPowerShell`: Install via PowerShell:
     ```powershell
     Install-Module -Name AWSPowerShell -Force -Scope CurrentUser
     ```
2. **AWS Credentials**: Valid AWS access key ID and secret key with S3 write permissions.
3. **SMTP Credentials**: Email credentials (if email alerts are enabled).
4. **Configuration File**: A `config.xml` file (see [Configuration](#configuration)).

---

## **Configuration**
### **`config.xml` Setup**
Create a `config.xml` file in the script directory with the following structure:
```xml
<Settings>
    <RegionEndpoint>us-west-2</RegionEndpoint>
    <BucketName>your-s3-bucket-name</BucketName>
    <AccessKeyID>Base64EncodedAccessKeyID</AccessKeyID>
    <SecretAccessKey>Base64EncodedSecretAccessKey</SecretAccessKey>
    <SmtpUser>smtp-user@example.com</SmtpUser>
    <SmtpPassword>Base64EncodedSmtpPassword</SmtpPassword>
</Settings>
```
- **Encode Credentials**: Use Base64 encoding for security:
  ```powershell
  [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("plain-text-value"))
  ```



## **Installation**
1. **Clone or Download the Script**:
   - Place the script (`.ps1`) and `config.xml` in a directory (e.g., `C:\Scripts`).
2. **Configure Folders**:
   - The script creates `C:\Reports\InactiveAccounts` and `C:\Reports\InactiveAccounts\Logs` automatically.



## **Usage**
1. **Run the Script**:
   ```powershell
   .\AWS_AD_Inactive_Users.ps1
   ```
2. **Outputs**:
   - **CSV Report**: Saved to `C:\Reports\InactiveAccounts\90-Days-Inactive-User-Accounts_<timestamp>.csv`.
   - **Logs**: Saved to `C:\Reports\InactiveAccounts\Logs\Log_<timestamp>.txt`.
3. **S3 Upload**:
   - The CSV is uploaded to `s3://<BucketName>/ADD/reports`.



## **Email Alerts**
- **Enable/Disable**: Set `$EmailAlertsEnabled = $true` in the script.
- **SMTP Settings**: Uses Office 365 SMTP by default. Modify `Send-Alert` for other providers.
- **Recipient**: Update the `To` field in the `Send-Alert` function.



## **File Management**
- **CSV Files**: Retains the latest 5 files (configurable via `$MaxCsvFiles`).
- **Log Files**: Retains the latest 6 files (configurable via `$MaxLogFiles`).



## **Troubleshooting**
1. **Permissions Issues**:
   - Ensure the script runs with AD read access and S3 write permissions.
2. **XML Errors**:
   - Validate the `config.xml` structure and Base64 encoding.
3. **Email Failures**:
   - Check SMTP credentials and network/firewall settings.
4. **AWS Errors**:
   - Verify AWS credentials and bucket/region configuration.



## **Acknowledgments**
- AWS Tools for PowerShell: [AWS Documentation](https://docs.aws.amazon.com/powershell/)
- Microsoft ActiveDirectory Module: [PowerShell Docs](https://docs.microsoft.com/en-us/powershell/)

