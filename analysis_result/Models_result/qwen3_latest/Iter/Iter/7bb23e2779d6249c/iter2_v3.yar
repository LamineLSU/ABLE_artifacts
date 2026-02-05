rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 05 00 00 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { FF 15 ?? A0 33 00 FF 15 ?? A1 33 00 }
        $pattern2 = { E8 ?? 00 00 00 FF 15 ?? E1 F1 00 }

    condition:
        any of them
}