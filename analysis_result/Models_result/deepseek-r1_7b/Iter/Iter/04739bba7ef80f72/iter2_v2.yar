rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting early conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 0E E8 43 1C 00 00 }
        $pattern1 = { E8 E0 A2 FF FF 74 0E }
        $pattern2 = { E8 EE 82 FF FF 74 0E }

    condition:
        any of them
}