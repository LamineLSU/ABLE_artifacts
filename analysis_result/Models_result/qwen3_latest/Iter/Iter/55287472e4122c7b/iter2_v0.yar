rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 83 F8 11 74 05 }
        $pattern1 = { FF 15 ?? ?? ?? ?? 83 C4 0C }
        $pattern2 = { 83 7D FC 00 74 2F }

    condition:
        any of them
}