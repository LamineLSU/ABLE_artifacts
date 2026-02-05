rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting specific calls",
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5A ?? 51 ?? FF 4E 8B ?? ?? ?? 6A ?? ?? ?? FF 15 C8 A2 41 ?? }
        $pattern1 = { 00 ?? 8D 45 3F 9E ?? 75 C0 ?? FF 45 E8 ?? CA DD 00 41 A2 38 }
        $pattern2 = { 6A ?? FF 45 E8 ?? F9 75 C0 ?? FF 45 E8 ?? CA DD 00 41 A2 38 }

    condition:
        any of them
}