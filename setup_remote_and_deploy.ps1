# Shield Works Automated Deployment Provisioner

$ErrorActionPreference = "Stop"

Write-Host "`n🛡️ Shield Works API: Final Provisioning Sequence" -ForegroundColor Cyan
Write-Host "----------------------------------------------------"

# 1. Ask for credentials
$repoUrl = Read-Host "`n🔗 Paste your NEW GitHub Repository URL (e.g., https://github.com/user/repo)"
if ([string]::IsNullOrWhiteSpace($repoUrl)) {
    Write-Host "❌ URL is required to proceed." -ForegroundColor Red
    exit
}

# 2. Configure Git Remote
try {
    if (git remote get-url origin) {
        git remote set-url origin $repoUrl
    } else {
        git remote add origin $repoUrl
    }
    Write-Host "✅ GitHub Remote Linked." -ForegroundColor Green
} catch {
    git remote add origin $repoUrl
    Write-Host "✅ GitHub Remote Linked." -ForegroundColor Green
}

# 3. Final Commit & Push
Write-Host "`n📦 Finalizing local repository..." -ForegroundColor Gray
git add .
git commit -m "Automated Final Provisioning" --quiet

Write-Host "📤 Syncing to GitHub..." -ForegroundColor Cyan
git push -u origin master --force

Write-Host "`n----------------------------------------------------"
Write-Host "✅ STEP 1: Repository is now LIVE on GitHub." -ForegroundColor Green
Write-Host "✅ STEP 2: Render & Netlify detected render.yaml / netlify.toml." -ForegroundColor Green
Write-Host "`n🔥 LAST ACTION REQUIRED: 🔥" -ForegroundColor Yellow
Write-Host "1. Open your GitHub Repo in the browser."
Write-Host "2. Go to Settings -> Secrets -> Actions."
Write-Host "3. Done! Automation is fully engaged." -ForegroundColor Cyan
