rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 80 3D ?? ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? }
        $pattern1 = { 3B F0 0F 87 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 8B 4D FC 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}