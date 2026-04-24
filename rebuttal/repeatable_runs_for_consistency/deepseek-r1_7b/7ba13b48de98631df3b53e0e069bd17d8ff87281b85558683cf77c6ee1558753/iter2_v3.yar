rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific exit sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 0F 84 ?? ?? ?? 8B 4D FC }
        $pattern1 = { E8 57 26 00 5D EB }
        $pattern2 = { E8 4B 17 00 74 07 50 }

    condition:
        any of them
}