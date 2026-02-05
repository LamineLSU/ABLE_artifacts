rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 F8 01 74 20 } // CALL + CMP+JE sequence
        $pattern1 = { C1 E8 08 A8 01 75 10 } // SHR + TEST+JNE sequence
        $pattern2 = { FF 15 ?? ?? ?? ?? } // ExitProcess call (direct target)

    condition:
        any of them
}