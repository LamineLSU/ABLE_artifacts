rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific test and exit calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { 6A 3C 00 00 00 3C }
        $pattern2 = { FF 15 84 74 45 00 CA DD 00 45 74 84 }
}

condition:
    any of them