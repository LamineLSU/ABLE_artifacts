rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 20 }      // cmp eax,01h + je (evasion check)
        $pattern1 = { FF 15 3C F1 42 00 }   // GetCurrentProcess API call (conditional logic)
        $pattern2 = { FF 15 A0 F1 42 00 }   // ExitProcess API call (final exit decision)

    condition:
        any of them
}