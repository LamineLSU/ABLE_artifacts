rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting conditional exit checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A E8 45 FC }
        $pattern1 = { 83 F8 01 74 12 8B F8 }
        $pattern2 = { 3D 00 10 00 0F 82 }

    condition:
        any of them
}