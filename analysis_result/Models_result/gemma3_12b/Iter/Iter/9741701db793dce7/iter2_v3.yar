rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 43 1C 00 85 C0 74 0E }
        $pattern1 = { E8 EE 82 FF FF 85 C0 74 0E }
        $pattern2 = { E8 B7 F7 FF FF 85 C0 74 0E }

    condition:
        any of them
}