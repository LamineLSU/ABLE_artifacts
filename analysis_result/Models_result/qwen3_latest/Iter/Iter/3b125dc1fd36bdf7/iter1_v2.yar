rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 C0 A0 41 00 E8 47 00 00 00 }  // GetStartupInfoA + conditional check
        $pattern1 = { FF 15 44 A2 41 00 51 51 E8 5A 29 01 00 }  // GetModuleHandleA + hook detection
        $pattern2 = { E8 6A 00 00 00 FF 15 28 A2 41 00 }  // Conditional exit decision before ExitProcess

    condition:
        any of them
}