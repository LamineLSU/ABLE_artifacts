rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 F8 01 74 12 }
        $pattern1 = { FF 75 08 8B 45 FC 83 F8 00 74 08 }
        $pattern2 = { 8B FF 55 8B EC 83 F8 00 75 06 }

    condition:
        any of them
}