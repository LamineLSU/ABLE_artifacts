rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 08 BF F5 54 F7 50 }
        $pattern1 = { 08 BF F5 54 F7 50 8E 8C 8F FF FF }
        $pattern2 = { 08 BF F5 54 F7 50 8F F1 5A CB 04 10 }
    condition:
        any of them
}