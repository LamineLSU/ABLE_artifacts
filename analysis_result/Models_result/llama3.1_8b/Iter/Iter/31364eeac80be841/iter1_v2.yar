rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B E5 E8 ?? ?? ?? ?? 83 F8 01 74 ?? }
        $pattern1 = { 8B FF 55 8B E5 E8 ?? ?? ?? ?? C1 E8 08 A8 01 }
        $pattern2 = { 8B FF 55 8B E5 E8 ?? ?? ?? ?? 3D ?? ?? ?? 0F 82 }

    condition:
        any of them
}