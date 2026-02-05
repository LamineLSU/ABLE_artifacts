rule SandboxEvasion
{
    meta:
        description = "Detects sandbox evasion techniques through early termination and handle checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "CyberDefenseTeam"
        date = "2023-10-05"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }  // Initial test and jump sequence
        $pattern1 = { 5A E8 ?? ?? ?? ?? 85 C0 }  // Pop edx, call, and test sequence
        $pattern2 = { B9 42 8C EA 00 E8 ?? ?? ?? ?? }  // Mov ecx, call with displacement

    condition:
        all of them
}