rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B ?? ?? ?? ?? ?? 74 ?? ?? }
        $pattern1 = { 3D ?? ?? ?? ?? ?? 0F 82 }
        $pattern2 = { DC ?? ?? ?? 8B 4D F8 }

    condition:
        any of them
}