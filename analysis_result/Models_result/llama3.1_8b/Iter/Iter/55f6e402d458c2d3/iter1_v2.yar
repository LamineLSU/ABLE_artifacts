rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B ?? FC ?? C7 DC ?? }
        $pattern1 = { 3D ?? ?? ?? ?? 0F 82 }
        $pattern2 = { 0F 01 F8 00 00 ?? }

    condition:
        any of them
}