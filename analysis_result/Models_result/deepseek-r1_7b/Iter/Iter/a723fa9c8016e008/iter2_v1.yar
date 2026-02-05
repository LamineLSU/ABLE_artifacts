rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? 6A ?? 5A 8B CE E8 ?? }
        $pattern1 = { E8 ?? 75 08 83 C4 85 C0 0F 84 ?? ?? FF 07 2C 00 00 8B 40 68 A1 9B 7E FF F7 0A }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? 83 C4 ?? ?? 85 C0 0F 84 ?? 8D 05 8B 41 95 9C FF F7 0A }

    condition:
        any of them
}