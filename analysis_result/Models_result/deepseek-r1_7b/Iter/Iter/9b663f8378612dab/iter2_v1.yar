rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule (three possible paths)"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C0 5A ?? ?? ?? ?? ?? ?? ?? ?? }
        $pattern1 = { ?? ?? ?? ?? ?? 74 3F 8B EC 6A ?? 5A ?? }
        $pattern2 = { FF 75 08 FF 75 08 E8 FF ?? ?? ?? ?? ?? ?? }
    condition:
        any of them
}