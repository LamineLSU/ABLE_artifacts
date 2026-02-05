rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 74 ?? }  // Call + test + je (evasion check)
        $pattern1 = { FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? }  // CloseHandle + push + ExitProcess (cleanup logic)
        $pattern2 = { 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 03 C3 BA ?? ?? ?? ?? 03 C1 }  // Arithmetic + register manipulation (obfuscation)

    condition:
        any of them
}