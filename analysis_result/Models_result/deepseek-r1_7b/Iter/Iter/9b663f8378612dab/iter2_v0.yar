rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific trace patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 }
        $pattern1 = { 3D 00 10 00 00 00 0F 82 }
        $pattern2 = { 8B 4D FC 5F 5E 33 CD 5B }

    condition:
        any of them
}