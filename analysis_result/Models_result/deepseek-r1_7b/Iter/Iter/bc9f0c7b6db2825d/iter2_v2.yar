rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE 5A 8B 4D FC }
        $pattern1 = { E9 B5 FC FF FF 53 }
        $pattern2 = { 8E 4B 6F 7C 8B DD }

    condition:
        any of them
}