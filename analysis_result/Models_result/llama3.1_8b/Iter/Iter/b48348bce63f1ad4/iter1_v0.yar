rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B C4 ?? ?? ?? ?? E9 ?? ?? ?? ?? }
        $pattern1 = { 83 F8 ?? 74 ?? 8B 45 FC }
        $pattern2 = { 0F A8 ?? 3D ?? ?? ?? ?? 0F 82 }

    condition:
        any of them
}