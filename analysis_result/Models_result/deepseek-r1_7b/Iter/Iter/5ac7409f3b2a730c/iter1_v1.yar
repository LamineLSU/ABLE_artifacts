rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting decision points before exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 00 00 3C 0F 84 74 12 8B 45 FC }
        $pattern1 = { 6A 5B 5A 8B CE 0F 84 00 00 3C 74 12 89 CC }

    condition:
        any of them
}