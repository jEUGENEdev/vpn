#Requires -RunAsAdministrator
# Offline recovery for OLD installations, even after their EXE was removed.
# Deletes only the fixed WFP keys created by LineVPN 0.2; never resets Windows Firewall.
$ErrorActionPreference = 'Stop'
$service = Get-Service -Name LineVPN -ErrorAction SilentlyContinue
if ($service) {
    Set-Service -Name LineVPN -StartupType Disabled
    if ($service.Status -ne 'Stopped') {
        $service.Stop()
        $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(15))
    }
}
if (-not ('LineVPNRecovery.Wfp' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
namespace LineVPNRecovery {
 public static class Wfp {
  [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode)]
  static extern uint FwpmEngineOpen0(string server, uint auth, IntPtr identity, IntPtr session, out IntPtr handle);
  [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr handle);
  [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr handle, ref Guid key);
  [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerDeleteByKey0(IntPtr handle, ref Guid key);
  [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderDeleteByKey0(IntPtr handle, ref Guid key);
  static Guid Key(string name) {
   using (var sha = SHA256.Create()) {
    var digest = sha.ComputeHash(Encoding.UTF8.GetBytes(name));
    var bytes = new byte[16]; Array.Copy(digest, bytes, 16); return new Guid(bytes);
   }
  }
  static void Check(List<string> errors, uint code, uint missing) {
   if (code != 0 && code != missing && code != 1168) errors.Add("WFP 0x" + code.ToString("X8"));
  }
  public static void Recover() {
   IntPtr engine;
   uint result = FwpmEngineOpen0(null, 10, IntPtr.Zero, IntPtr.Zero, out engine);
   if (result != 0) throw new Exception("Open WFP: 0x" + result.ToString("X8"));
   var errors = new List<string>();
   try {
    // wf.LayerID.String() uses these symbolic names in the original client.
    foreach (var layer in new [] { "ALE_AUTH_CONNECT_V4", "ALE_AUTH_CONNECT_V6" }) {
     foreach (var rule in new [] { "deny", "agent", "loopback", "tunnel", "dhcp4" }) {
      var key = Key(rule + layer);
      Check(errors, FwpmFilterDeleteByKey0(engine, ref key), 0x80320003);
     }
    }
    var sublayer = Key("linevpn-sublayer");
    Check(errors, FwpmSubLayerDeleteByKey0(engine, ref sublayer), 0x80320007);
    var provider = Key("linevpn-provider");
    Check(errors, FwpmProviderDeleteByKey0(engine, ref provider), 0x80320005);
   } finally { FwpmEngineClose0(engine); }
   if (errors.Count != 0) throw new Exception(String.Join("; ", errors));
  }
 }
}
'@
}
try { [LineVPNRecovery.Wfp]::Recover() }
finally { & ipconfig.exe /flushdns | Out-Null }
Write-Output 'LineVPN filters removed. DNS cache cleared. VPN service stays disabled.'
