rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 FF ?? ?? 8B 45 ?? E8 ?? ?? }
        $pattern1 = { 6A ?? 5A ?? ?? ?? ?? ?? ?? ?? E8 C8 FF FF 00 40 E7 C3 }
        $pattern2 = { ?? ?? ?? ?? 8B EC FF 15 AC B0 41 00 00 41 B0 AC }

    condition:
        any of them
}