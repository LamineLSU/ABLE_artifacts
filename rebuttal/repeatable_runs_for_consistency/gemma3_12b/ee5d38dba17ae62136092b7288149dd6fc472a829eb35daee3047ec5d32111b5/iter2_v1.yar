rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 35 56 56 6A 00 }
        $pattern1 = { 8B 45 08 8B 45 08 8B 48 14 }
        $pattern2 = { 83 C4 14 52 52 8B 16 }

    condition:
        any of them
}