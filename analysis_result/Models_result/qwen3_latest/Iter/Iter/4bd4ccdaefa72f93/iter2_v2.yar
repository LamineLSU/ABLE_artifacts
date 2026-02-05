rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 4E FF 15 ?? ?? ?? ?? }  // JE + ExitProcess call (0x116E -> 0x1170)
        $pattern1 = { FF 15 F1 0E 00 00 }         // Call to first evasion check
        $pattern2 = { FF 15 E9 0E 00 00 }         // Call to second evasion check

    condition:
        any of them
}