<#
    Deploy this directory to s3://milu.company and invalidate the CloudFront cache.
    Usage: .\deploy.ps1
#>

$ErrorActionPreference = 'Stop'

$Bucket          = 'milu.company'
$DistributionId  = 'E3KW4E82WRCX2G'
$SourceDir       = $PSScriptRoot

$excludes = @(
    '--exclude', 'deploy.ps1',
    '--exclude', 'deploy.sh',
    '--exclude', '.git/*',
    '--exclude', '.claude/*',
    '--exclude', '.gitignore',
    '--exclude', '.DS_Store',
    '--exclude', '*.swp'
)

Write-Host "Syncing $SourceDir -> s3://$Bucket ..." -ForegroundColor Cyan
& aws s3 sync $SourceDir "s3://$Bucket/" --delete @excludes
if ($LASTEXITCODE -ne 0) { throw "s3 sync failed (exit $LASTEXITCODE)" }

Write-Host "Creating CloudFront invalidation for $DistributionId ..." -ForegroundColor Cyan
$invalidation = & aws cloudfront create-invalidation --distribution-id $DistributionId --paths '/*' --output json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "cloudfront create-invalidation failed (exit $LASTEXITCODE)" }

Write-Host ("Invalidation {0} submitted ({1})." -f $invalidation.Invalidation.Id, $invalidation.Invalidation.Status) -ForegroundColor Green
Write-Host "Done. https://milu.company/" -ForegroundColor Green
