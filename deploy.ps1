<#
    Deploy this directory to s3://milu.company and invalidate the CloudFront cache.
    Usage: .\deploy.ps1

    Uses a whitelist: only files whose extension/name matches an --include below
    are uploaded. Everything else (this script, Lambda source, repo + tool
    metadata, scratch JSONs) is excluded from S3 regardless of where it sits in
    the tree.
#>

$ErrorActionPreference = 'Stop'

$Bucket          = 'milu.company'
$DistributionId  = 'E3KW4E82WRCX2G'
$SourceDir       = $PSScriptRoot

# Whitelist of file patterns that ship to the static site.
# --exclude "*" turns everything off, then each --include re-enables a pattern.
$includes = @(
    '--exclude', '*',
    '--include', '*.html',
    '--include', '*.css',
    '--include', '*.svg',
    '--include', '*.png',
    '--include', '*.jpg',
    '--include', '*.jpeg',
    '--include', '*.webp',
    '--include', '*.ico',
    '--include', '*.woff',
    '--include', '*.woff2',
    '--include', 'robots.txt',
    '--include', 'sitemap.xml',
    '--include', 'favicon.ico',
    '--include', 'manifest.json'
)

Write-Host "Syncing $SourceDir -> s3://$Bucket ..." -ForegroundColor Cyan
& aws s3 sync $SourceDir "s3://$Bucket/" --delete @includes
if ($LASTEXITCODE -ne 0) { throw "s3 sync failed (exit $LASTEXITCODE)" }

Write-Host "Creating CloudFront invalidation for $DistributionId ..." -ForegroundColor Cyan
$invalidation = & aws cloudfront create-invalidation --distribution-id $DistributionId --paths '/*' --output json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "cloudfront create-invalidation failed (exit $LASTEXITCODE)" }

Write-Host ("Invalidation {0} submitted ({1})." -f $invalidation.Invalidation.Id, $invalidation.Invalidation.Status) -ForegroundColor Green
Write-Host "Done. https://milu.company/" -ForegroundColor Green
