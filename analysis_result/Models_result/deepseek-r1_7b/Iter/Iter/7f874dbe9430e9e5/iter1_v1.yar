rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action=skip,bp1=$pattern1+0,action=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 8B FF EB F4 8B EC FF 75 08 E8 C8 FF FF FF }
        $pattern1 = { FF 75 08 E8 C8 FF FF FF 83 C4 ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }
    condition:
        any of them
}