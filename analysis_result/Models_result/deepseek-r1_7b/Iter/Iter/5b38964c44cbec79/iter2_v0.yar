rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific bypass points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 00 9B 61 90 }
        $pattern1 = { 8D 43 01 00 9B 61 F7 }
        $pattern2 = { 00 9B 61 E5 00 9B 61 EC }

    condition:
        (match $pattern0) || (match $pattern1) || (match $pattern2)
}