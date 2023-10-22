function Get-GSAClientPolicyRules {
    <#
    .SYNOPSIS
        this cmdlet lists Global Secrure Access client local policies.
    .DESCRIPTION
        Reads configuration from regisrty in json format, export it as pscustomobject 
    .EXAMPLE
        Get-GSAClientDetails
    #>
    [CmdletBinding()]
    Param (
    )
    #try read Global Secure Access config from registry 
    $GSACRegKey = 'HKLM:\SOFTWARE\Microsoft\Global Secure Access Client'
    if (!(Test-Path $GSACRegKey)) {
        Write-Output "Global Secure Access Client regkey $GSACRegKey not found on this machine"
        break
    }
    $KeyValue = Get-ItemProperty $GSACRegKey
    
    $ForwardingProfile = $KeyValue.ForwardingProfile | ConvertFrom-Json
    $channels = $ForwardingProfile.policy.channels
    $rules = $ForwardingProfile.policy.rules
    $rulesoutput = New-Object -TypeName System.Collections.ArrayList
    #$rule = $rules[23]
    foreach ($rule in $rules) {
        if ($rule.matchingCriteria.address.ips) {
            #$ip = $rule.matchingCriteria.address.ips[0]
            $channelName = ($channels | Where-Object { $_.id -eq $rule.channelId }).name
            foreach ($ip in $rule.matchingCriteria.address.ips) {
                $HexStart = [Convert]::ToString($ip.start, 16)
                $ipStart = [Convert]::ToUint64($HexStart, 16) -as [ipaddress]
                $HexEnd = [Convert]::ToString($ip.start, 16)
                $ipEnd = [Convert]::ToUint64($HexEnd, 16) -as [ipaddress]
                $ruleEntry = [PSCustomObject]@{
                    id        = $rule.id
                    channel   = $channelName
                    order     = $rule.order
                    action    = $rule.action
                    hardening = $rule.hardening
                    ipStart   = $ipStart
                    ipEnd     = $ipEnd
                    fqdn      = ''
                    protocol  = $rule.matchingCriteria.protocol
                    portStart = $rule.matchingCriteria.ports.start
                    portEnd   = $rule.matchingCriteria.ports.end
                }
                $rulesoutput.Add($ruleEntry) | Out-Null
            }
        }
        if ($rule.matchingCriteria.address.fqdns) {
            $fqdn = $rule.matchingCriteria.address.fqdns[0]
            foreach ($fqdn in $rule.matchingCriteria.address.fqdns) {
                $fqdnformated = $fqdn.replace('\', '')
                $ruleEntry = [PSCustomObject]@{
                    id        = $rule.id
                    channel   = $channelName
                    order     = $rule.order
                    action    = $rule.action
                    hardening = $rule.hardening
                    ipStart   = ''
                    ipEnd     = ''
                    fqdn      = $fqdnformated
                    protocol  = $rule.matchingCriteria.protocol
                    portStart = $rule.matchingCriteria.ports.start
                    portEnd   = $rule.matchingCriteria.ports.end
                }
                $rulesoutput.Add($ruleEntry) | Out-Null
            }
        }
    }
    $rulesoutput
}