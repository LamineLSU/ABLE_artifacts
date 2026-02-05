rule Malware_Evasion_Bypass
{
    meta:
        description = "Detects evasion bypass patterns in malware to prevent early exit in sandboxed environments."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? 33 FF }  // Push ebx, Call ExitProcess, Xor edi, edi
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? }  // Test eax, JE to exit path, mov eax
        $pattern2 = { BA 21 05 00 00 50 FF 15 ?? ?? ?? ?? }  // Mov edx, Push eax, Call CloseHandle

    condition:
        any of them
}