rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        count = 0
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"

    strings:
        $pattern0 = { 55 8B EC FF ?? ?? ?? ?? E8 C1 FF FF }
        $pattern1 = { E8 C1 FF FF FF 75 08 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}