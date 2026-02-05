rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting multiple memory addresses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? 0A ?? 3C 6A ?? 5B ?? 7E ?? 5E }
        $pattern1 = { 8B 95 7C 21 00 8D ?? FE 00 ?? BA 1E 3E ?? 41 ?? 2D }
        $pattern2 = { E8 C7 F0 ?? FF 6A 53 ?? EB 0F ?? EC 1C 07 ?? AF }

    condition:
        any of them
}