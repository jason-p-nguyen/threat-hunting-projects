 # Set base path to where the files are located
$basePath = "C:\Users\jnguyen.admin\Documents\Confidential" 

# Define backdated timestamps
$creationDate = (Get-Date).AddDays(-30)
$lastModifiedDate = (Get-Date).AddDays(-14)
$lastAccessedDate = (Get-Date).AddDays(-7)

# List of files to update
$files = @(
    "Employee_Record_Dump.csv",
    "Quarterly_Financial_Projections_Q3.docx",
    "Client_Credentials_Access.xlsx"
)

foreach ($file in $files) {
    $fullPath = Join-Path $basePath $file
    if (Test-Path $fullPath) {
        (Get-Item $fullPath).CreationTime = $creationDate
        (Get-Item $fullPath).LastWriteTime = $lastModifiedDate
        (Get-Item $fullPath).LastAccessTime = $lastAccessedDate
        Write-Host "Updated metadata for $file"
    } else {
        Write-Warning "$file not found at $basePath"
    }
} 
