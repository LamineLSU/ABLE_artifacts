rule Bypass_Sample_Evasion
{
    meta:
        description = "Evasion bypass detection rules targeting ExitProcess"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { FF 75 08 8B EC 55 8B EC FF 75 08 8B FC ?? FF 75 08 8B EC FF 75 08 8B FC ?? FF 75 08 8B EC FF 75 08 ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}