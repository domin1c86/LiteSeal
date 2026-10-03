# Fresh, marked synthetic database; credentials only live in this process.
$ErrorActionPreference='Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$audioSuffix=[guid]::NewGuid().ToString('N')
$audioRole='liteseal_test_'+$audioSuffix
$audioDatabase='liteseal_test_audio_'+$audioSuffix
$audioPassword=[guid]::NewGuid().ToString('N')+[guid]::NewGuid().ToString('N')
$previousAudioUrl=$env:LITESEAL_TEST_DATABASE_URL
$audioCode=2
try {
    "CREATE ROLE $audioRole LOGIN PASSWORD '$audioPassword'; CREATE DATABASE $audioDatabase OWNER $audioRole; COMMENT ON DATABASE $audioDatabase IS 'liteseal-dedicated-test-v1';" | docker exec -i liteseal-postgres-1 psql -U liteseal -d postgres -v ON_ERROR_STOP=1 | Out-Null
    if($LASTEXITCODE-ne 0){throw 'Isolated audio fixture creation failed; no credentials logged.'}
    $env:LITESEAL_TEST_DATABASE_URL="postgres://$($audioRole):$($audioPassword)@127.0.0.1:5432/$audioDatabase"
    node scripts/test-audio-relay.mjs
    $audioCode=$LASTEXITCODE
} finally {
    $env:LITESEAL_TEST_DATABASE_URL=$previousAudioUrl
    "DROP DATABASE IF EXISTS $audioDatabase WITH (FORCE); DROP ROLE IF EXISTS $audioRole;" | docker exec -i liteseal-postgres-1 psql -U liteseal -d postgres -v ON_ERROR_STOP=1 | Out-Null
    $audioPassword=$null
    if($LASTEXITCODE-ne 0){throw 'Isolated audio fixture cleanup failed; inspect dedicated DB names only.'}
    Write-Output 'Isolated audio database and temporary login role removed.'
}
exit $audioCode
