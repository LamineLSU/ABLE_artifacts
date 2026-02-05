rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Your Name"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 6A ?? 5A 8B CE E8 25 05 00 00 CA 00 80 66 7F E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { FF 15 AC B0 41 00 CA DD 00 41 B0 FF 75 08 59 FF 15 AC B0 41 00 }

    condition:
        any of them
}