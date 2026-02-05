rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection (Test EAX JZ with offset)"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 ?? ?? ?? 0F 84 F8 C0 }
        $pattern1 = { E8 ?? ?? ?? ?? 03 C3 F8 C0 00 00 00 00 00 00 }
        $pattern2 = { 6A 5B 5A ?? 8B CE E8 25 ?? 00 00 00 00 00 01 00 00 }

    condition:
        any of them
}