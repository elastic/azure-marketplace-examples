<#
.Synopsis
    Deploys two Elasticsearch clusters into a separate Virtual Network
.Example
    & .\two_clusters_one_vnet.ps1 -AdminUserName "russ" `
    -AdminPassword $(ConvertTo-SecureString -String "Password1234" -AsPlainText -Force) `
    -SecurityAdminPassword $(ConvertTo-SecureString -String "Password123" -AsPlainText -Force) `
    -SecurityReadPassword $(ConvertTo-SecureString -String "Password123" -AsPlainText -Force) `
    -SecurityKibanaPassword $(ConvertTo-SecureString -String "Password123" -AsPlainText -Force)
.Example
    & .\two_clusters_one_vnet.ps1 -ClientId "clientid" `
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

function ConvertTo-UInt32 ([IPAddress]$IpAddress) {
    $bytes = $IpAddress.GetAddressBytes()
    if ([BitConverter]::IsLittleEndian) {
        [Array]::Reverse($bytes)
    }
    return [BitConverter]::ToUInt32($bytes, 0)
}

function ConvertTo-IpAddress([UInt32]$UInt32) {
    $bytes = [BitConverter]::GetBytes($UInt32)
    if ([BitConverter]::IsLittleEndian) {
        [Array]::Reverse($bytes)
    }
    return [IPAddress]::new($bytes)
}

function Get-AvailablePrivateIpAddresses($VNet, $SubnetName, $Count) {
    $subnet = Get-AzureRmVirtualNetworkSubnetConfig -VirtualNetwork $VNet -Name $SubnetName
    $addressPrefixParts = $subnet.AddressPrefix.Split("/")
    $ipAddress = [IPAddress]::Parse($addressPrefixParts[0])
    $cidr = [Convert]::ToByte($addressPrefixParts[1])
    $maskUInt = [Convert]::ToUInt32("1" * $cidr + "0" * (32 - $cidr), 2)
    [UInt32] $networkUInt = $maskUInt -band (ConvertTo-UInt32 $ipAddress.Address)
    [UInt32] $broadcastUInt = 4294967295 -bxor $maskUInt -bor $networkUInt
    $subnetCount = $broadcastUInt - ($networkUInt + 1)

    if ($Count -and $subnetCount -lt $Count) {
        Write-Error -Message "Requested $Count available addresses but subnet contains maximum $subnetCount addresses"
        return
    }

    $availableAddresses = New-Object "System.Collections.Generic.HashSet[IpAddress]"
    for($i = $networkUInt; $i -le $broadcastUInt; $i++) { 
      [IpAddress] $testAddress = ConvertTo-IpAddress ($i)
      if ($availableAddresses.Contains($testAddress)) {
        continue;
      }

      $result = Test-AzureRmPrivateIPAddressAvailability -VirtualNetwork $vnet `
          -IPAddress $($testAddress.IPAddressToString)
      if ($result.Available) {
        $availableAddresses.Add($testAddress) > $null
      }

      foreach($a in $result.AvailableIPAddresses) {
        $availableAddress = [IpAddress]::Parse($a)
        if ($availableAddress.Address -ge $networkAddress.Address -and `
            $availableAddress.Address -le $broadcastAddress.Address) {
            $availableAddresses.Add($availableAddress) > $null
        }     
      }

      if ($Count -and $availableAddresses.Count -ge $Count) {
        break;
      }
    }

    if ($availableAddresses.Count -lt $Count) {
        Write-Error "Insufficent available addresses in subnet. Requested $Count, available $($availableAddresses.Count)"
        return
    }

    return $availableAddresses
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

$location = "Australia Southeast"
$vnetResourceGroup = "vnet"
$vnetName = "es-net"
$addressPrefix = "10.0.0.0/24"

Write-Log "Deploying virtual network"
New-AzureRmResourceGroup -Name $vnetResourceGroup -Location $location
New-AzureRmVirtualNetwork -ResourceGroupName $vnetResourceGroup -Name $vnetName `
    -AddressPrefix $addressPrefix -Location $location
Write-Log "Virtual network deployed" -ForegroundColor "green"

$vnet = Get-AzureRmVirtualNetwork -Name $vnetName -ResourceGroupName $vnetResourceGroup
$subnetName = "es-subnet"

Write-Log "Adding subnet to virtual network"
Add-AzureRmVirtualNetworkSubnetConfig -Name $subnetName -AddressPrefix "10.0.0.0/25" -VirtualNetwork $vnet
Set-AzureRmVirtualNetwork -VirtualNetwork $vnet
Write-Log "subnet added" -ForegroundColor "green"

$templateVersion = "5.1.2"
$templateUrl = "https://raw.githubusercontent.com/elastic/azure-marketplace/$templateVersion/src"
$mainTemplate = "$templateUrl/mainTemplate.json"
$resourceGroup = "first-cluster"
$name = $resourceGroup
$availableAddresses = Get-AvailablePrivateIpAddresses -VNet $vnet -SubnetName $subnetName -Count 8

$templateParameters = @{
    "artifactsBaseUrl"= $templateUrl
    "esClusterName" = "first-cluster"
    "adminUsername" = $AdminUserName
    "authenticationType" = "password"
    "adminPassword" = $AdminPassword
    "securityAdminPassword" = $SecurityAdminPassword
    "securityReadPassword" = $SecurityReadPassword
    "securityKibanaPassword" = $SecurityKibanaPassword
    "vmHostNamePrefix" = "f-"
    "vNetNewOrExisting" = "existing"
    "vNetName" = $vnetName
    "vNetExistingResourceGroup" = $vnetResourceGroup
    "vNetLoadBalancerIp" = "$(($availableAddresses | Select-Object -First 1).IPAddressToString)"
    "vNetClusterSubnetName" = $subnetName
}

Write-Log "Deploying first cluster"
New-AzureRmResourceGroup -Name $resourceGroup -Location $location
New-AzureRmResourceGroupDeployment -Name $name -ResourceGroupName $resourceGroup `
    -TemplateUri $mainTemplate -TemplateParameterObject $templateParameters
Write-Log "Deployed first cluster" -ForegroundColor "green"

$resourceGroup = "second-cluster"
$name = $resourceGroup
$availableAddresses = Get-AvailablePrivateIpAddresses -VNet $vnet -SubnetName $subnetName -Count 8

$templateParameters = @{
    "artifactsBaseUrl"= $templateUrl
    "esClusterName" = "second-cluster"
    "adminUsername" = $AdminUserName
    "authenticationType" = "password"
    "adminPassword" = $AdminPassword
    "securityAdminPassword" = $SecurityAdminPassword
    "securityReadPassword" = $SecurityReadPassword
    "securityKibanaPassword" = $SecurityKibanaPassword
    "vmHostNamePrefix" = "s-"
    "vNetNewOrExisting" = "existing"
    "vNetName" = $vnetName
    "vNetExistingResourceGroup" = $vnetResourceGroup
    "vNetLoadBalancerIp" = "$(($availableAddresses | Select-Object -First 1).IPAddressToString)"
    "vNetClusterSubnetName" = $subnetName
}

Write-Log "Deploying second cluster"
New-AzureRmResourceGroup -Name $resourceGroup -Location $location
New-AzureRmResourceGroupDeployment -Name $name -ResourceGroupName $resourceGroup `
    -TemplateUri $mainTemplate -TemplateParameterObject $templateParameters
Write-Log "Deployed second cluster" -ForegroundColor "green"