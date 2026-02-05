rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }
        $pattern1 = { 8B 43 13 00 00 00 75 C0 0F 84 ?? ?? ?? ?? F3 A2 00 00 01 0D 7A 03 00 00 02 00 00 64 5E 00 8B 5C ?? ?? ?? ?? }
        $pattern2 = { E8 A1 FF FF FF FF 15 18 C0 41 00 74 0A 89 43 00 00 75 C0 74 0A 59 00 8B 03 8B 42 FF 0F }

    condition:
        any of them
}