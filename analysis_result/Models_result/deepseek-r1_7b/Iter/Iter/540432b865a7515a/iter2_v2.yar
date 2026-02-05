rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 74 12 ?? 00 00 01 10 }
        $pattern1 = { 6A 5B 00 00 00 5B 5A ?? E8 CE ?? ?? ?? }
        $pattern2 = { ?? ?? 3D 00 10 00 00 00 0F 82 ?? ?? }

    condition:
        any of them
}