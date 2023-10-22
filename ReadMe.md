# Get-GSAClientPolicyRules

A PowerShell cmdlet to list all local policyrules on a machine received by Global Secure Access Client.

Global Secure Access is in preview, only 2 of 3 channels are implemented in current preview:

- M365 Profile
- Private Profile

Internet profile is not in public preview

# Example

```powershell
PS> Get-GSAClientPolicyRules | ?{$_.channel -eq 'Private'}

id        : 8bfe1dfc-bcec-47a8-a240-473eb07f8a31
channel   : Private
order     : 107.0
action    : Tunnel
hardening : Bypass
ipStart   : 192.168.178.22
ipEnd     : 192.168.178.22
fqdn      :
protocol  : Tcp
portStart : 3389
portEnd   : 3389

```
