rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { 3D ?? ?? ?? ?? 0F 82 ?? ?? ?? ?? }
        $pattern2 = { FF 15 ?? ?? ?? ?? F9 8A }

    condition:
        any of them
}