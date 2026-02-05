rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC 83 EC 48 56 }
        $pattern1 = { 83 F8 01 74 12 8B 40 68 }
        $pattern2 = { 85 C0 0F 84 8B 45 FC }

    condition:
        any of them
}