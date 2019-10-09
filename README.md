# SentinelBasicQueries
Basic queries to start understanding each Log table and its columns

## Microsoft Services:

### 1. Office 365
#### Exchange logs
    OfficeActivity | where OfficeWorkload == "Exchange" | sort by TimeGenerated
#### SharePoint and OneDrive logs 
    OfficeActivity | where OfficeWorkload == "SharePoint" or OfficeWorkload == "OneDrive" | sort by TimeGenerated
    
### 2. Azure AD audit logs and sign-ins (Azure Active Directory)
    SigninLogs | take 1000 | sort by TimeGenerated
    AuditLogs | summarize count() by bin(TimeGenerated, 1h) | sort by TimeGenerated

### 3. Azure Activity
    AzureActivity | take 1000
    AzureActivity | summarize count() by bin(TimeGenerated, 1h) | sort by TimeGenerated

### 4. Azure AD Identity Protection
    SecurityAlert | where ProductName == "Azure Active Directory Identity Protection" ​| summarize arg_max(TimeGenerated, *) by SystemAlertId | sort by TimeGenerated
    SecurityAlert | where ProductName == "Azure Active Directory Identity Protection" ​| summarize arg_max(TimeGenerated, *) by SystemAlertId | summarize count() by AlertSeverity | sort by TimeGenerated
	
### 5. Azure Security Center
#### all logs
    SecurityAlert | where ProductName == "Azure Security Center" | sort by TimeGenerated
#### summarized by severity
    SecurityAlert | where ProductName == "Azure Security Center") | summarize count() by AlertSeverity​

### 6. Azure Information Protection
#### summarize by operation:
    InformationProtectionLogs_CL | summarize count() by Operation_s, TimeGenerated | sort by TimeGenerated
#### summarize by user, computer and operation
    InformationProtectionLogs_CL | summarize count() by UserId_s, Computer, Operation_s, TimeGenerated | sort by TimeGenerated	
#### all logs:
    SecurityAlert | where ProductName == "Azure Information Protection"​ | sort by TimeGenerated

### 7. Azure Advanced Threat Protection
#### see all logs:
    SecurityAlert | where ProductName == "Azure Advanced Threat Protection" ​| summarize arg_max(TimeGenerated, *) by SystemAlertId | sort by TimeGenerated
#### summarize by operation:
    SecurityAlert | where ProductName == "Azure Advanced Threat Protection" ​| summarize arg_max(TimeGenerated, *) by SystemAlertId | summarize count() by TimeGenerated | sort by TimeGenerated

### 8. Cloud App Security
#### all logs
    SecurityAlert | where ProductName == "Microsoft Cloud App Security"​ ​| summarize arg_max(TimeGenerated, *) by SystemAlertId | summarize count() by AlertSeverity | sort by TimeGenerated
#### Summarize by severity
    SecurityAlert | where ProductName == "Microsoft Cloud App Security"​ ​| summarize arg_max(TimeGenerated, *) by SystemAlertId | summarize count() by AlertSeverity | sort by TimeGenerated
#### all logs
    SecurityAlert | where ProductName == "Microsoft Cloud App Security"​ ​| summarize arg_max(TimeGenerated, *) by SystemAlertId | summarize count() by AlertSeverity | sort by TimeGenerated

### 9. Security events (Windows)
    SecurityEvent | sort by TimeGenerated

### 10. Windows firewall
#### all logs
    WindowsFirewall | sort by TimeGenerated
#### summarize by firewall actions
    WindowsFirewall | summarize count() by FirewallAction | sort by TimeGenerated

### 11. App GW WAF
#### all logs
    AzureDiagnostics | where ResourceType == "APPLICATIONGATEWAYS" | sort by TimeGenerated
#### Blocked actions
    AzureDiagnostics | where ResourceType == "APPLICATIONGATEWAYS" | where OperationName == "ApplicationGatewayFirewall" | where action_s == "Blocked" | sort by TimeGenerated

## External solution via API:

### 1. Barracuda
#### All logs
    CommonSecurityLog | where DeviceVendor == "Barracuda" | sort by TimeGenerated
#### Summarize by protocol and destination IP
    CommonSecurityLog | where DeviceVendor == "Barracuda" | summarize count() by ApplicationProtocol, DestinationIP​ | sort by TimeGenerated
#### Barracuda audit logs events
    barracuda_CL | where Vendor_s == "Barracuda" and Product_s == "WAF" | where LogType_s == "AUDIT" | sort by TimeGenerated

### 2. Symantec ICDx
#### Summarize by connection source ip
    SymantecICDx_CL | summarize count() by connection_src_ip_s | sort by TimeGenerated
#### Summarize by threat id
    SymantecICDx_CL | summarize count() by threat_id_d | sort by TimeGenerated

## External solutions via agent

## Firewalls, proxies, and endpoints: 
### 3. F5
#### all logs
    CommonSecurityLog | where DeviceVendor == "F5" | sort by TimeGenerated
#### summarize by time
    CommonSecurityLog | where DeviceVendor == "F5" | sort by TimeGenerated
	
### 4. Check Point
#### all logs
    CommonSecurityLog | where DeviceVendor == "Check Point" | sort by TimeGenerated
#### Drop device actions
    CommonSecurityLog | where DeviceVendor == "Check Point" | where DeviceAction == "Drop" | sort by TimeGenerated

### 5. Cisco ASA
#### all logs
    CommonSecurityLog | where DeviceVendor == "Cisco" | where DeviceProduct == "ASA" | sort by TimeGenerated
#### Deny device actions
    CommonSecurityLog | where DeviceVendor == "Cisco" | where DeviceProduct == "ASA" | where SimplifiedDeviceAction == "Deny" | sort by TimeGenerated

### 6. Fortinet
#### all logs
    CommonSecurityLog | where DeviceVendor == "Fortinet" | where DeviceProduct == "Fortigate" | sort by TimeGenerated
#### Summarize by destination IP and port 
    CommonSecurityLog | where DeviceVendor == "Fortinet" | where DeviceProduct == "Fortigate" | summarize count() by DestinationIP, DestinationPort | sort by TimeGenerated
	
### 7. Palo Alto
#### all logs
    CommonSecurityLog | where DeviceVendor == "Palo Alto Networks" | where DeviceProduct == "PAN-OS" | sort by TimeGenerated
#### THREAT activity
    CommonSecurityLog | where DeviceVendor == "Palo Alto Networks" | where DeviceProduct == "PAN-OS" | where Activity == "THREAT" | sort by TimeGenerated
			
### 8. Other CEF appliances
    CommonSecurityLog | where DeviceVendor !in ("Cisco","Check Point","Palo Alto Networks","Fortinet","F5","Barracuda") | sort by TimeGenerated

## Other Syslog appliances
		...
    
## DLP solutions
	
### 1. Threat intelligence providers
#### Summarize by threat type
    ThreatIntelligenceIndicator | where ExpirationDateTime > now() | join ( SigninLogs ) on $left.NetworkIP == $right.IPAddress | summarize count() by ThreatType
#### Summarize by 1 hour bins
    CommonSecurityLog | where DestinationIP in (( ThreatIntelligenceIndicator | where ExpirationDateTime > now() | where ThreatType == "DDoS" | project NetworkIP )) | summarize count() by bin(TimeGenerated, 1d)​​
	
### 2. DNS machines - agent installed directly on the DNS machine
#### All event logs
    DnsEvents | sort by TimeGenerated
#### All inventory logs
    DnsInventory | sort by TimeGenerated
	
### 3. Other clouds (AWS Cloud Trail)
    AWSCloudTrail | summarize count() by AWSRegion, TimeGenerated | sort by TimeGenerated
