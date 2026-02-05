rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 F8 01 74 ?? }  // Call + cmp eax,01 + je
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 A8 01 75 ?? }  // TLS pointer + bitwise check
        $pattern2 = { FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? }  // GetCurrentProcess + push + TerminateProcess

    condition:
        any of them
}