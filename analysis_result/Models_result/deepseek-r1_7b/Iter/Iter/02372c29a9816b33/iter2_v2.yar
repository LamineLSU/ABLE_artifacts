rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting call sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { FF ?? 8A 00 00 00 ?? ??.??.??? F9 75 ?? 5D }
        $pattern2 = { E8 ?? ?? ?? ?? 8B 3C ?? ?? ?? ?? 5D }

    condition:
        any of them
}