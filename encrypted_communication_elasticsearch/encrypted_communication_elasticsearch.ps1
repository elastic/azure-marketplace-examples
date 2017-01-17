<#
.Synopsis
    Deploys an Elasticsearch cluster with Transport Layer Security to Elasticsearch
.Description
    Uses Application Gateway for external access and SSL offload
.Example
    & .\encrypted_communication_elasticsearch.ps1 -AdminUserName "russ" `
    -AdminPassword $(ConvertTo-SecureString -String "Password1234" -AsPlainText -Force) `
    -CertPath "C:\cert.pfx" -CertPassword $(ConvertTo-SecureString -String "Password" -AsPlainText -Force) `
    -SecurityAdminPassword $(ConvertTo-SecureString -String "Password123" -AsPlainText -Force) `
    -SecurityReadPassword $(ConvertTo-SecureString -String "Password123" -AsPlainText -Force) `
    -SecurityKibanaPassword $(ConvertTo-SecureString -String "Password123" -AsPlainText -Force)
.Example
    & .\encrypted_communication_elasticsearch.ps1 -ClientId "clientid" `
    -ClientSecret $(ConvertTo-SecureString -String "clientsecret" -AsPlainText -Force) `
    -TenantId "tenantid" -SubscriptionId "subscriptionid" `
    -CertPath "C:\cert.pfx" -CertPassword $(ConvertTo-SecureString -String "Password" -AsPlainText -Force) `
    -AdminUserName "russ" -AdminPassword $(ConvertTo-SecureString -String "Password1234" -AsPlainText -Force) `
    -SecurityAdminPassword $(ConvertTo-SecureString -String "Password123" -AsPlainText -Force) `
    -SecurityReadPassword $(ConvertTo-SecureString -String "Password123" -AsPlainText -Force) `
    -SecurityKibanaPassword $(ConvertTo-SecureString -String "Password123" -AsPlainText -Force)
.Parameter ClientId
    the client id to log in with a Service Principal
.Parameter ClientSecret
    the client secret to log in with a Service Principal
.Parameter TenantId
    the tenant id to log in with a Service Principal
.Parameter SubscriptionId
    the subscription id to deploy the resources to. If the current session is not logged into the Azure account, user will
    be prompted to log in and select a SubscriptionId
.Parameter CertPath
    the path to the certificate to use to encrypt communication with Application Gateway
.Parameter CertPassword
    the password for the certificate. Optional as may not have a password
.Parameter AdminUserName
    the admin username in order to log into VMs deployed in the Elasticsearch cluster
.Parameter AdminPassword
    the admin password in order to log into VMs deployed in the Elasticsearch cluster 
.Parameter SecurityAdminPassword
    the password to log into the Elasticsearch cluster through X-Pack Security with user 'es_admin' (2.x) or 'elastic' (5.x)
.Parameter SecurityReadPassword
    the password to log into the Elasticsearch cluster through X-Pack Security with user 'es_read'
.Parameter SecurityKibanaPassword
    the password to log into the Elasticsearch cluster through X-Pack Security with user 'es_kibana'
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string] $ClientId,

    [Parameter(Mandatory=$false)]
    [securestring] $ClientSecret,

    [Parameter(Mandatory=$false)]
    [string] $TenantId,

    [Parameter(Mandatory=$false)]
    [string] $SubscriptionId,

    [Parameter(Mandatory=$true)]
    [string] $CertPath,

    [Parameter(Mandatory=$false)]
    [securestring] $CertPassword,

    [Parameter(Mandatory=$true)]
    [string] $KeyPath,

    [Parameter(Mandatory=$true)]
    [string] $AdminUserName,

    [Parameter(Mandatory=$true)]
    [securestring] $AdminPassword,

    [Parameter(Mandatory=$true)]
    [securestring] $SecurityAdminPassword,

    [Parameter(Mandatory=$true)]
    [securestring] $SecurityReadPassword,
  
    [Parameter(Mandatory=$true)]
    [securestring] $SecurityKibanaPassword
)
$ErrorActionPreference = "Stop"

function Write-Log($Message, $ForegroundColor) {
    if ($ForegroundColor -eq $null) {
        $ForegroundColor = "White"
    }

    Write-Host "[$(Get-Date -format 'u')] $message" -ForegroundColor $ForegroundColor
}

function Show-Custom($title, $optionValues, $optionDescriptions) {
    Write-Host $title
    Write-Host
    for($i = 0; $i -lt $optionValues.Length; $i++) {
        Write-Host "$($i+1))" $optionDescriptions[$i]
    }
    Write-Host

    while($true) {
        Write-Host "Choose an option: "
        $option = Read-Host
        $option = $option -as [int]

        if($option -ge 1 -and $option -le $optionValues.Length) {
            return $optionValues[$option-1]
        }
    }
}

function Show-Subscription() {
    # Choose subscription. If there's only one we will choose automatically
    $subs = Get-AzureRmSubscription
    $subscriptionId = ""

    if($subs.Length -eq 0) {
        Write-Error "No subscriptions bound to this account."
        return
    }

    if($subs.Length -eq 1) {
        $subscriptionId = $subs[0].SubscriptionId
    }
    else {
        $subscriptionChoices = @()
        $subscriptionValues = @()

        foreach($subscription in $subs) {
            $subscriptionChoices += "$($subscription.SubscriptionName) ($($subscription.SubscriptionId))";
            $subscriptionValues += ($subscription.SubscriptionId);
        }

        $subscriptionId = Show-Custom "Choose a subscription" $subscriptionValues $subscriptionChoices
    }

    return $subscriptionId
}

try {
    if ($ClientId -and $ClientSecret -and $TenantId -and $SubscriptionId) {
        $credential = new-object -typename System.Management.Automation.PSCredential `
                                -argumentlist $ClientId, $ClientSecret

        Add-AzureRmAccount -Credential $credential -Tenant $TenantId -ServicePrincipal -ErrorAction Stop     
    }

    Select-AzureRmSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop
}
catch {
    Write-Host "Please Login"
    Login-AzureRmAccount
    $SubscriptionId = Show-Subscription
    Select-AzureRmSubscription -SubscriptionId $SubscriptionId
}

$templateVersion = "5.1.2"
$templateUrl = "https://raw.githubusercontent.com/elastic/azure-marketplace/$templateVersion/src"
$mainTemplate = "$templateUrl/mainTemplate.json"
$location = "Australia Southeast"
$resourceGroup = "app-gateway-cluster"
$name = "elasticsearch"
$gatewayCert = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($CertPath))

$templateParameters = @{
    "artifactsBaseUrl"= $templateUrl
    "esClusterName" = $name
    "loadBalancerType" = "gateway"
    "appGatewayCertBlob" = $gatewayCert
    "appGatewayCertPassword" = $CertPassword
    "adminUsername" = $AdminUserName
    "authenticationType" = "password"
    "adminPassword" = $AdminPassword
    "securityAdminPassword" = $SecurityAdminPassword
    "securityReadPassword" = $SecurityReadPassword
    "securityKibanaPassword" = $SecurityKibanaPassword
}

Write-Log "Deploying Elasticsearch cluster"
New-AzureRmResourceGroup -Name $resourceGroup -Location $location
New-AzureRmResourceGroupDeployment -Name $name -ResourceGroupName $resourceGroup -TemplateUri $mainTemplate -TemplateParameterObject $templateParameters
Write-Log "Elasticsearch cluster deployed" -ForegroundColor "green"