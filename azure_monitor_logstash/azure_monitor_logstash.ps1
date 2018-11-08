<#
.Synopsis
    Deploys Elasticsearch, Kibana and Logstash, with Azure Monitor Logstash module configured. 
.Description
    Deploys Elasticsearch, Kibana and Logstash, with Azure Monitor Logstash module configured. 
    Additional steps must currently be taken on the Logstash VM to complete Azure Monitor configuration
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
.Parameter SecurityBootstrapPassword
    the bootstrap password to initially log into the Elasticsearch cluster through X-Pack Security
.Parameter SecurityAdminPassword
    the password to log into the Elasticsearch cluster through X-Pack Security with built-in user 'elastic'
.Parameter SecurityReadPassword
    the password to log into the Elasticsearch cluster through X-Pack Security with user 'es_read'
.Parameter SecurityKibanaPassword
    the password to log into the Elasticsearch cluster through X-Pack Security with built-in user 'kibana'
.Parameter SecurityLogstashPassword
    the password to log into the Elasticsearch cluster through X-Pack Security with built-in user 'logstash_system'
.Parameter SecurityBeatsPassword
    the password to log into the Elasticsearch cluster through X-Pack Security with built-in user 'beats_system'
.Parameter EventHubResourceGroup
    the resource group for event hubs
.Parameter EventHubNamespaceName
    the namespace for event hubs
.Parameter StorageResourceGroup
    the resource group for the Storage account    
.Parameter StorageAccountName
    the name of the storage account. Must be universally unique
.Parameter ResourceGroup
    the resource group for Elasticsearch, Logstash and Kibana
.Parameter Name
    the name of the Elasticsearch cluster
.Parameter Location
    Azure location for all deployed resources
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

    [Parameter(Mandatory=$false, HelpMessage="Admin user to log into VMs")]
    [string] $AdminUserName = "russ",

    [Parameter(Mandatory=$true, HelpMessage="Password for the Admin user to log into VMs")]
    [securestring] $AdminPassword,

    [Parameter(Mandatory=$true, HelpMessage="Password to bootstrap the cluster with")]
    [securestring] $SecurityBootstrapPassword,

    [Parameter(Mandatory=$true, HelpMessage="Password for the built-in 'elastic' user")]
    [securestring] $SecurityAdminPassword,

    [Parameter(Mandatory=$true, HelpMessage="Password for a read-only 'es_read' user")]
    [securestring] $SecurityReadPassword,
  
    [Parameter(Mandatory=$true, HelpMessage="Password for the built-in 'kibana' user")]
    [securestring] $SecurityKibanaPassword,

    [Parameter(Mandatory=$true, HelpMessage="Password for the built-in 'logstash_system' user")]
    [securestring] $SecurityLogstashPassword,

    [Parameter(Mandatory=$true, HelpMessage="Password for the built-in 'beats_system' user")]
    [securestring] $SecurityBeatsPassword,

    [Parameter(Mandatory=$false)]
    [string] $EventHubResourceGroup = "logstash-monitor-eventhubs",

    [Parameter(Mandatory=$false)]
    [string] $EventHubNamespaceName = "logstash-monitor-eventhubs",

    [Parameter(Mandatory=$false)]
    [string] $StorageResourceGroup = "logstash-monitor-storage",

    [Parameter(Mandatory=$false)]
    [string] $StorageAccountName = "logstashstorage$([System.Guid]::NewGuid().ToString().Replace('-', '').Substring(0, 9))",

    [Parameter(Mandatory=$false)]
    [string] $ResourceGroup = "logstash-monitor",

    [Parameter(Mandatory=$false)]
    [string] $Name = "logstash-monitor",

    [Parameter(Mandatory=$false)]
    [string] $Location = "Australia Southeast"
)

$ErrorActionPreference = "Stop"

function Write-Log($Message, $ForegroundColor) {
    if ($null -eq $ForegroundColor) {
        $ForegroundColor = "White"
    }

    Write-Host "[$(Get-Date -format 'u')] $Message" -ForegroundColor $ForegroundColor
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
    $subs = Get-AzureRmSubscription
    $subscriptionId = ""

    if($subs.Length -eq 0) {
        Write-Error "No subscriptions bound to this account."
        return
    }

    if($subs.Length -eq 1) {
        $subscriptionId = $subs[0].Id
    }
    else {
        $subscriptionChoices = @()
        $subscriptionValues = @()

        foreach($subscription in $subs) {
            $subscriptionChoices += "$($subscription.Name) ($($subscription.Id))";
            $subscriptionValues += ($subscription.Id);
        }

        $subscriptionId = Show-Custom "Choose a subscription" $subscriptionValues $subscriptionChoices
    }

    return $subscriptionId
}

function ConvertTo-PlainText {
	param(
		[System.Security.SecureString]
        [Parameter(ValueFromPipeline = $true)]
        $secureString
	)

	$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
	try {
		return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
	}
	finally {
		[Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
	}
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

# create event hub namespace
Write-Log "Create event hub namespace $EventHubNamespaceName in resource group $EventHubResourceGroup"

New-AzureRmResourceGroup -Name $EventHubResourceGroup -Location $Location
$eventHubNamespace = New-AzureRmEventHubNamespace -ResourceGroupName $EventHubResourceGroup -NamespaceName $EventHubNamespaceName -Location $Location
Write-Log "Created event hub namespace $EventHubNamespaceName"
$eventHubEndpoint = $eventHubNamespace.ServiceBusEndpoint.Replace("https://", "sb://")

Write-Log "Get the SAS key for event hub namespace $EventHubNamespaceName"
# get shared access key for the event hub namespace. Doesn't look like there is a PowerShell cmdlet to do this anymore :(
$sharedAccessKey = (Invoke-AzureRmResourceAction -ResourceGroupName $EventHubResourceGroup -ResourceType Microsoft.EventHub/namespaces/AuthorizationRules `
                        -ResourceName $EventHubNamespaceName/RootManageSharedAccessKey -Action listKeys -ApiVersion 2015-08-01 -Force).primaryKey

##############################
# create the Azure Log Profile
##############################

Write-Log "Check for existing log profile"
$logProfile = Get-AzureRmLogProfile -ErrorAction Ignore
if ($null -ne $logProfile) {
    Write-Log "Existing log profile $($logProfile.Name)"
    Write-Log "Delete existing log profile $($logProfile.Name)"
    Remove-AzureRmLogProfile -Name $logProfile.Name
    Write-Log "Deleted existing log profile $($logProfile.Name)"
}

$logProfileName = "default"
$locations = (Get-AzureRmLocation).Location
$locations += "global"
$serviceBusRuleId = "/subscriptions/$subscriptionId/resourceGroups/$EventHubResourceGroup" + `
                    "/providers/Microsoft.EventHub/namespaces/$EventHubNamespaceName" + ` 
                    "/authorizationrules/RootManageSharedAccessKey"

Write-Log "Create log profile $logProfileName"
Add-AzureRmLogProfile -Name $logProfileName -Location $locations -ServiceBusRuleId $serviceBusRuleId
Write-Log "Created log profile $logProfileName"

##############################################################
# set up storage account for persisting logstash read position
##############################################################

Write-Log "Create storage account $StorageAccountName in resource group $StorageResourceGroup"
New-AzureRmResourceGroup -Name $StorageResourceGroup -Location $Location
$storageAccount = New-AzureRmStorageAccount -ResourceGroupName $StorageResourceGroup -AccountName $StorageAccountName -Type "Standard_LRS" -Location $Location
Write-Log "Created storage account $StorageAccountName"

$storageAccountKeys = Get-AzureRmStorageAccountKey -ResourceGroupName $storageResourceGroup -Name $storageAccountName
$uri = New-Object -TypeName System.Uri $storageAccount.Context.BlobEndPoint

#####################################
# build the storage connection string 
#####################################

$storageConnectionString = "DefaultEndpointsProtocol=$($uri.Scheme);AccountName=$storageAccountName;" + `
                           "AccountKey=$($storageAccountKeys[0].Value);EndpointSuffix=$($storageAccount.Context.EndPointSuffix);"


# assumes we're using Azure DNS resolution, which can resolve by hostname
$kibanaIp = "kibana"
$logstashConsumerGroup = "logstash"
$elasticUserPassword = ConvertTo-PlainText $SecurityAdminPassword

#########################################################
# Build the yaml to append to the template's logstash.yml
#########################################################

$logstashYaml = @"
modules:
  - name: azure
    var.elasticsearch.hosts: `"`${ELASTICSEARCH_URL}`"
    var.elasticsearch.username: elastic
    var.elasticsearch.password: `"$elasticUserPassword`"
    var.kibana.ssl.enabled: false
    var.kibana.host: `"$($kibanaIp):5601`"
    var.kibana.username: elastic
    var.kibana.password: `"$elasticUserPassword`"
    var.input.azure_event_hubs.consumer_group: "$logstashConsumerGroup"
    var.input.azure_event_hubs.storage_connection: "$storageConnectionString"
    var.input.azure_event_hubs.threads: 9
    var.input.azure_event_hubs.event_hub_connections:
"@

############################################################
# Get all the event hubs set up by the log profile. This can
# take some time to propagate so loop until they're visible
############################################################

Write-Log "Get the event hubs in event hub namespace $EventHubNamespaceName"
$eventHubs = Get-AzureRmEventHub -ResourceGroupName $EventHubResourceGroup -Namespace $EventHubNamespaceName
while ($null -eq $eventHubs) {
    $sleepySeconds = 5
    Write-Log "No event hubs in event namespace $EventHubNamespaceName. Trying again in $sleepySeconds seconds..."
    Start-Sleep -Seconds $sleepySeconds
    $eventHubs = Get-AzureRmEventHub -ResourceGroupName $EventHubResourceGroup -Namespace $EventHubNamespaceName  
}

$entityPaths = $eventHubs | % { $_.Name }

$entityPaths | % {
    Write-Log "Add consumer group $logstashConsumerGroup to event hub $_"
    New-AzureRmEventHubConsumerGroup -ResourceGroupName $EventHubResourceGroup -Namespace $EventHubNamespaceName -Name $logstashConsumerGroup -EventHub $_
    Write-Log "Add event hub $_ to logstash.yml"
    $logstashYaml += "`n      - `"Endpoint=$eventHubEndpoint;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=$sharedAccessKey;EntityPath=$_`""
}

###########################################
# Deploy Elasticsearch, Logstash and Kibana
###########################################

# last template version tag released to Marketplace
$templateVersion = "6.4.2"
$templateUrl = "https://raw.githubusercontent.com/elastic/azure-marketplace/$templateVersion/src"
$elasticTemplate = "$templateUrl/mainTemplate.json"

$clusterParameters = @{
    "artifactsBaseUrl"= $templateUrl
    "esVersion" = "6.4.2"
    "esClusterName" = $name
    "vmDataDiskCount" = 2
    "vmDataNodeCount" = 3
    "vmSizeDataNodes" = "Standard_D1_v2"
    "vmSizeMasterNodes" = "Standard_D1_v2"
    "dataNodesAreMasterEligible" = "Yes"

    "kibana" = "Yes"
    "vmSizeKibana" = "Standard_D1_v2"

    "logstash" = "Yes"
    "vmSizeLogstash" = "Standard_D1_v2"
    "logstashKeystorePassword" = "Password123"
    "logstashAdditionalYaml" = $logstashYaml

    "loadBalancerType" = "internal"

    "xpackPlugins" = "Yes"
    "adminUsername" = $AdminUserName
    "authenticationType" = "password"
    "adminPassword" = $AdminPassword
    "securityBootstrapPassword" = $SecurityBootstrapPassword
    "securityAdminPassword" = $SecurityAdminPassword
    "securityReadPassword" = $SecurityReadPassword
    "securityKibanaPassword" = $SecurityKibanaPassword
    "securityLogstashPassword" = $SecurityLogstashPassword
    "securityBeatsPassword" = $SecurityBeatsPassword
}


Write-Log "Deploying Elasticsearch, Logstash, Kibana"
New-AzureRmResourceGroup -Name $resourceGroup -Location $location
$deployment = New-AzureRmResourceGroupDeployment -Name $name -ResourceGroupName $resourceGroup -TemplateUri $elasticTemplate -TemplateParameterObject $clusterParameters
Write-Log "Deployed Elasticsearch, Logstash, Kibana"

#launch Kibana after deployment finishes
Start-Process $deployment.Outputs.kibana.Value

<#

##########################################################
Steps on Logstash VM to finish Azure Monitor configuration
##########################################################

1. SSH into Logstash through Kibana VM

    ssh <adminname>@<kibana ip>

    ssh logstash

2. Stop Logstash service with systemctl

    sudo systemctl stop logstash.service

3. Remove path.config setting from /etc/logstash/logstash.yml. Can't be used in conjunction with Azure modules

    sudo nano /etc/logstash/logstash.yml

4. Need to run one time setup for Logstash module to export Dashboards to Kibana.
Get the keystore password from /etc/sysconfig/logstash and export to environment variables

    sudo cat /etc/sysconfig/logstash

    export LOGSTASH_KEYSTORE_PASS="<password from /etc/sysconfig/logstash>"

5. Run Logstash setup with logstash user, passing environment variables

    sudo -Eu logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash --setup

6. Once [Azure Monitor] Dashboards appear under the Dashboard tab in Kibana, stop Logstash with CTRL+C

7. Start Logstash service with systemctl

    sudo systemctl start logstash.service

#>