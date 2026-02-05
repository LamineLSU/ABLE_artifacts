rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 EA 6A ?? EB FF 75 08 DD EB 08 0F 84 ?? ?? ?? ?? AE EE CE FF E8 C8 FF FF FF FF CD FF FF 15 AC B0 41 00 CA DD 00 41 B0 AC }
        $pattern1 = { 6A ?? EB 5A ?? ?? ?? ?? EC FF 75 08 DD EB 08 8B 45 EB E8 C8 FF FF FF FF CD FF FF 15 AC B0 41 00 CA DD 00 41 B0 AC }
        $pattern2 = { 8B EC EB FF 75 08 DD EB 08 6A ?? 53 EB E8 C8 FF FF FF FF CD FF FF 15 AC B0 41 00 CA DD 00 41 B0 AC }

    condition:
        any of them (i.e., if any of the patterns match, it indicates a bypass)
}