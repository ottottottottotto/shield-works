# Shield Works One-Click Deployment Automation

Write-Host "🚀 Initializing Shield Works Automation Sequence..." -ForegroundColor Cyan

# 1. Verification
if (!(Test-Path .git)) {
    Write-Host "⚠️ Git not initialized. Initializing..." -ForegroundColor Yellow
    git init
}

# 2. Stage Changes
Write-Host "📦 Staging all local assets..." -ForegroundColor Gray
git add .

# 3. Commit
$msg = Read-Host "💬 Enter deployment identifier (commit message) [default: platform-update]"
if ([string]::IsNullOrWhiteSpace($msg)) { $msg = "platform-update" }

git commit -m "$msg"

# 4. Push to remote
$branch = git branch --show-current
Write-Host "📤 Syncing branch [$branch] to secure repository..." -ForegroundColor Cyan

try {
    git push origin $branch
    Write-Host "✅ Deployment signal sent to GitHub & Render!" -ForegroundColor Green
}
catch {
    Write-Host "❌ Deployment failed. Ensure 'origin' is set correctly (see walkthrough)." -ForegroundColor Red
}

Write-Host "`n🌐 Dashboard: https://shield-works.onrender.com" -ForegroundColor Blue
Write-Host "🛠️ CI/CD Pipeline: https://github.com/YOUR_USERNAME/shield-works/actions" -ForegroundColor Blue
