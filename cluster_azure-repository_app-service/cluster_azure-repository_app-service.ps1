<#
.Synopsis
    Deploys an Azure Storage Account, Elasticsearch cluster and Azure App Service. 
.Description
    The Storage account is configured with the azure-repository plugin to be used for snapshot/restore for the Elasticsearch cluster.
    The Azure App Service is connected to the Virtual Network deployed as part of the cluster so that it can connect to the cluster.
.Example
    & .\cluster_azure-repository_app-service.ps1 -AdminUserName "russ" `
    -AdminPassword $(ConvertTo-SecureString -String "Password1234" -AsPlainText -Force) `
    -SecurityAdminPassword $(ConvertTo-SecureString -String "Password123" -AsPlainText -Force) `
    -SecurityReadPassword $(ConvertTo-SecureString -String "Password123" -AsPlainText -Force) `
    -SecurityKibanaPassword $(ConvertTo-SecureString -String "Password123" -AsPlainText -Force)
.Example
    & .\cluster_azure-repository_app-service.ps1 -ClientId "clientid" `
    -ClientSecret $(ConvertTo-SecureString -String "clientsecret" -AsPlainText -Force) `
    -TenantId "tenantid" -SubscriptionId "subscriptionid" `
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

function New-StorageAccount($storageAccountResourceGroup, $storageAccountName, $location) {
    $account = Get-AzureRmStorageAccount -ResourceGroupName $storageAccountResourceGroup -Name $storageAccountName -ErrorAction Ignore

    if ($account -ne $null) {
        Write-Log "Storage account $storageAccountName in resource group $storageAccountResourceGroup already exists. Using this." -ForegroundColor "green"
        return
    }

    Write-Log "Creating Storage account $storageAccountName in resource group $storageAccountResourceGroup"
    New-AzureRmResourceGroup -Name $storageAccountResourceGroup -Location $location
    New-AzureRmStorageAccount -ResourceGroupName $storageAccountResourceGroup -AccountName $storageAccountName -Type "Standard_LRS" -Location $location
    Write-Log "Finished creating Storage account" -ForegroundColor "green"
}

function New-ElasticsearchCluster($resourceGroupName, $clusterName, $location, $elasticTemplateUri, $elasticParameters) {
    $resourceGroup = Get-AzureRmResourceGroup -Name $resourceGroupName -Location $location -ErrorAction Ignore

    if ($resourceGroup -ne $null) {
        Write-Log "Resource group $resourceGroupName already exists. Using this." -ForegroundColor "green"
        return
    }

    Write-Log "Deploying Elasticsearch cluster $clusterName from $elasticTemplateUri"
    New-AzureRmResourceGroup -Name $resourceGroupName -Location $location
    New-AzureRmResourceGroupDeployment -Name $clusterName -ResourceGroupName $resourceGroupName -TemplateUri $elasticTemplateUri -TemplateParameterObject $elasticParameters
    Write-Log "Finished Deploying Elasticsearch cluster" -ForegroundColor "green"
}

function New-Website($resourceGroupName, $webAppName, $location, $webAppParameters) {
    $resourceGroup = Get-AzureRmResourceGroup -Name $resourceGroupName -Location $location -ErrorAction Ignore

    if ($resourceGroup -ne $null) {
        Write-Log "Resource group $resourceGroupName already exists. Using this." -ForegroundColor "green"
        return
    }

    $deployFromGithubTemplate = "https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/201-web-app-github-deploy/azuredeploy.json"
    New-AzureRmResourceGroup -Name $resourceGroupName -Location $location
    New-AzureRmResourceGroupDeployment -Name $webAppName -ResourceGroupName $resourceGroupName `
        -TemplateUri $deployFromGithubTemplate -TemplateParameterObject $webAppParameters
    Write-Log "Finished Deploying Nusearch website" -ForegroundColor "green"
}

function Add-VNetGateway($resourceGroupName, $vnetName, $vnetIpName, $location, $vnetIpConfigName, $vnetGatewayName, $certificateData, $vnetPointToSiteAddressSpace) {
    
    $gateway = Get-AzureRmVirtualNetworkGateway -Name $vnetGatewayName -ResourceGroupName $resourceGroupName -ErrorAction Ignore

    if ($gateway -ne $null) {
        Write-Log "Virtual Network Gateway $vnetGatewayName already exists. Using this." -ForegroundColor "green"
        return
    }
    
    $vnet = Get-AzureRmVirtualNetwork -Name $vnetName -ResourceGroupName $resourceGroupName
    $subnet = Get-AzureRmVirtualNetworkSubnetConfig -Name "GatewaySubnet" -VirtualNetwork $vnet

    Write-Log "Creating a public IP address for this Virtual Network"
    $pip = New-AzureRmPublicIpAddress -Name $vnetIpName -ResourceGroupName $resourceGroupName -Location $location -AllocationMethod Dynamic
    $ipconf = New-AzureRmVirtualNetworkGatewayIpConfig -Name $vnetIpConfigName -Subnet $subnet -PublicIpAddress $pip
    Write-Log "Finished creating a public IP address for this Virtual Network" -ForegroundColor "green"

    Write-Log "Adding a root certificate to this Virtual Network"
    $root = New-AzureRmVpnClientRootCertificate -Name "AppServiceCertificate.cer" -PublicCertData $certificateData
    Write-Log "Finished Adding a root certificate to this Virtual Network" -ForegroundColor "green"

    Write-Log "Creating Virtual Network Gateway. This may take up to an hour."
    $gateway = New-AzureRmVirtualNetworkGateway -Name $vnetGatewayName -ResourceGroupName $resourceGroupName `
        -Location $location -IpConfigurations $ipconf -GatewayType Vpn -VpnType RouteBased -EnableBgp $false `
        -GatewaySku Basic -VpnClientAddressPool $vnetPointToSiteAddressSpace -VpnClientRootCertificates $root
    Write-Log "Finished creating Virtual Network Gateway" -ForegroundColor "green"
}

function Add-AppServiceToExistingVnet($subscriptionId, $webAppResourceGroup, $webAppName, $vnetName, $vnetResourceGroup) {
    Write-Log "Getting App information"
    $webApp = Get-AzureRmResource -ResourceName $webAppName -ResourceType "Microsoft.Web/sites" `
        -ApiVersion 2015-08-01 -ResourceGroupName $webAppResourceGroup
    $location = $webApp.Location

    $webAppConfig = Get-AzureRmResource -ResourceName "$($webAppName)/web" -ResourceType "Microsoft.Web/sites/config" `
        -ApiVersion 2015-08-01 -ResourceGroupName $webAppResourceGroup
    $vnet = Get-AzureRmVirtualNetwork -Name $vnetName -ResourceGroupName $vnetResourceGroup

    # Virtual Network settings
    $vnetName = $vnet.Name
    $vnetGatewayName="$($vnetName)-gateway"
    $vnetIpName="$($vnetName)-gateway-ip"
    $vnetIpConfigName="$($vnetName)-gateway-ip-conf"
    $vnetGatewayAddressSpace="10.0.0.128/28"
    $vnetPointToSiteAddressSpace="172.16.0.0/16"

    Write-Log "Creating Virtual Network Connection for website $webAppName to Virtual Network $($vnet.Name)"
    $virtualNetworkParameters = @{
        "vnetResourceId" = "/subscriptions/$($subscriptionId)/resourceGroups/$($vnet.ResourceGroupName)/providers/Microsoft.Network/virtualNetworks/$($vnetName)"
    }
    $virtualNetworkConnection = New-AzureRmResource -Location $location -Properties $virtualNetworkParameters -ResourceName "$($webAppName)/$($vnet.Name)" -ResourceType "Microsoft.Web/sites/virtualNetworkConnections" -ApiVersion 2015-08-01 -ResourceGroupName $webAppResourceGroup -Force
    Write-Log "Virtual Network Connection created" -ForegroundColor "green"

    $gatewaySubnet = Get-AzureRmVirtualNetworkSubnetConfig -Name "GatewaySubnet" -VirtualNetwork $vnet -ErrorAction Ignore
    if ($gatewaySubnet -ne $null) {
        Write-Log "GatewaySubnet already exists for Virtual Network $($vnet.Name). Using this." -ForegroundColor "green"
    }
    else {
        Write-Log "Creating GatewaySubnet in Virtual Network $($vnet.Name)"
        Add-AzureRmVirtualNetworkSubnetConfig -Name "GatewaySubnet" -AddressPrefix $vnetGatewayAddressSpace -VirtualNetwork $vnet
        Set-AzureRmVirtualNetwork -VirtualNetwork $vnet
        Write-Log "GatewaySubnet created in Virtual Network $($vnet.Name)" -ForegroundColor "green"
    }

    # Create the VNet Gateway
    Add-VNetGateway $vnet.ResourceGroupName $vnetName $vnetIpName $location $vnetIpConfigName $vnetGatewayName $virtualNetworkConnection.Properties.CertBlob $vnetPointToSiteAddressSpace
    $gateway = Get-AzureRmVirtualNetworkGateway -ResourceGroupName $vnet.ResourceGroupName -Name $vnetGatewayName

    # Now finish joining by getting the VPN package and giving it to the App
    Write-Log "Retrieving VPN Package and supplying to Web App"
    $packageUri = Get-AzureRmVpnClientPackage -ResourceGroupName $vnet.ResourceGroupName -VirtualNetworkGatewayName $gateway.Name -ProcessorArchitecture Amd64

    # Put the VPN client configuration package onto the App
    $virtualNetworkGatewayParameters = @{
        "vnetName" = $vnet.Name; 
        "vpnPackageUri" = $packageUri.ToString().Trim('"')
    }

    Write-Log "Adding website $webAppName to Virtual Network $($vnet.Name)"
    New-AzureRmResource -Location $location -Properties $virtualNetworkGatewayParameters -ResourceName "$($webAppName)/$($vnet.Name)/primary" -ResourceType "Microsoft.Web/sites/virtualNetworkConnections/gateways" -ApiVersion 2015-08-01 -ResourceGroupName $webAppResourceGroup -Force      
    Write-Log "Finished adding website $webAppName to Virtual Network $($vnet.Name)" -ForegroundColor "green"
}

function Add-AppSettings($resourceGroupName, $webAppName, $appSettings) {
    Write-Log "Updating App Settings for website"
    $webApp = Get-AzureRMWebAppSlot -ResourceGroupName $resourceGroupName -Name $webAppName -Slot production
    $existingAppSettings = $webApp.SiteConfig.AppSettings

    $hash = @{}
    foreach ($kvp in $existingAppSettings) {
        $hash[$kvp.Name] = $kvp.Value
    }
    foreach ($kvp in $appSettings.GetEnumerator()) {
        $hash[$kvp.Name] = $kvp.Value
    }

    Set-AzureRMWebAppSlot -ResourceGroupName $resourceGroupName -Name $webAppName -AppSettings $hash -Slot production
    Write-Log "App Settings for website updated" -ForegroundColor "green"
}

##################
# Start of Process
##################

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

$location = "Australia Southeast"

#################################################################################################
# Create the storage account, or use existing one if resource group with same name already exists
#################################################################################################

$storageAccountResourceGroup = "nusearch-storage"
$storageAccountName = "nusearchdata"

New-StorageAccount $storageAccountResourceGroup $storageAccountName $location
$storageAccountKeys = Get-AzureRmStorageAccountKey -ResourceGroupName $storageAccountResourceGroup -Name $storageAccountName

#########################################################################################
# Create the cluster, or use existing one if resource group with same name already exists
#########################################################################################

$templateVersion = "5.1.2"
$clusterResourceGroup = "nusearch-cluster"
$clusterName = "nusearch-cluster"
$templateUrl = "https://raw.githubusercontent.com/elastic/azure-marketplace/$templateVersion/src"
$mainTemplate = "$templateUrl/mainTemplate.json"

# parameters match those of the version of the template that we are targeting
$templateParameters = @{
    "artifactsBaseUrl"= $templateUrl
    "esClusterName" = $clusterName
    "adminUsername" = $AdminUserName
    "vNetLoadBalancerIp" = "10.0.0.4"
    "vNetName" = "es-net"
    "authenticationType" = "password"
    "adminPassword" = $AdminPassword
    "securityAdminPassword" = $SecurityAdminPassword
    "securityReadPassword" = $SecurityReadPassword
    "securityKibanaPassword" = $SecurityKibanaPassword
    "azureCloudPlugin" = "Yes"
    "azureCloudStorageAccountName" = $storageAccountName
    "azureCloudStorageAccountKey" = $storageAccountKeys[0].Value   
}

New-ElasticsearchCluster $clusterResourceGroup $clusterName $location $mainTemplate $templateParameters

#########################################################################################
# Create the website, or use existing one if resource group with same name already exists
#########################################################################################

$webAppResourceGroup = "nusearch-web"
$webAppName = "nusearch-app"
$webAppParameters = @{
    "siteName" = $webAppName
    "hostingPlanName" = "nusearch"
    "sku" = "S1"
    "workerSize" = "1"
    "repoURL" = "https://github.com/elastic/elasticsearch-net-example.git"
    "branch" = "5.x-deploy"
}

New-Website $webAppResourceGroup $webAppName $location $webAppParameters

########################################
# Add the website to the Virtual Network
########################################

Add-AppServiceToExistingVnet $subscriptionId $webAppResourceGroup $webAppName $templateParameters.vNetName $clusterResourceGroup

################################################################################
# Update the app settings for the website to point to the internal load balancer
################################################################################

$appSettings = @{
    "ElasticClient:Host" = "$($templateParameters.vNetLoadBalancerIp)"
    "ElasticClient:Username" = "es_read"
    "ElasticClient:Password" = $SecurityReadPassword
}

Add-AppSettings $webAppResourceGroup $webAppName $appSettings

<#
TODO: automate these as part of the example

Configure azure repository for snapshots
----------------------------------------

PUT _snapshot/nusearchdata
{
    "type": "azure",
    "settings": {
        "container": "backups"
    }
}

POST _snapshot/nusearchdata/_verify

GET _snapshot/nusearchdata/_all

POST /_snapshot/nusearchdata/snapshot_1/_restore?wait_for_completion=true


Need to Sync Network in Azure Portal!
-------------------------------------

nusearch-web -> App Service Plan -> Networking -> VNet Integration -> click network name -> click Sync Network

#>
