rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - generic stack/return address manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? 74 1A 6A ?? 5A 8B CE E8 85 C0 }
        $pattern1 = { E8 ?? ?? ?? ?? FF 15 3C E1 F1 00 50 FF 75 08 FF 15 40 E1 F1 00 }
        $pattern2 = { 6A ?? 5A 8B CE E8 85 C0 ?? 5B FF 75 08 FF 15 AC B0 41 00 }

    condition:
        any of them
}