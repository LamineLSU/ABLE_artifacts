rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { 03 C3 74 12 8B 45 FC }
        $pattern2 = { 03 C9 74 12 8B 4D F8 }

    condition:
        any of them
}