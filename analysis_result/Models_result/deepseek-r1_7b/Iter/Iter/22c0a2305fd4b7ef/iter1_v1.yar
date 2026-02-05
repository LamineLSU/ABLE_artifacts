rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - refined"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? FE ?? FE ?? FE ?? }
        $pattern1 = { 8B 4D F8 5F 45 FC 00 00 00 00 00 00 }
        $pattern2 = { 8B E5 07 4C 6C 9A CA 00 00 00 00 00 00 }
    condition:
        any of them
}