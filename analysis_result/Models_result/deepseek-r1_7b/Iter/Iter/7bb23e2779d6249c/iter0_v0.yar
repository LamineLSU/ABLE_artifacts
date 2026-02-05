rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting memory addresses and stack offsets"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 05 00 ?? ?? 0F 84 ??
                     E825 ?? ?F 74 0A 6A ?? ?F ?C ?? ?D ?? }
        $pattern1 = { 8B FF 55 ?? ?F 0F 84 ?F ?C 00 03 C9 ?F ?4 ?F
                     5E ?? 74 0A 68 ?? ?? ?? ?? 83 C3 ?F ?D ?F }
        $pattern2 = { 6A ?? 5B ?? E8 ?? ?? ?? 8B 41 ?F 0F 84 ?F ?C
                     0F 84 ?F ?C 00 03 FC ?F ?D ?F ?C ?F ?D }

    condition:
        any of them
}