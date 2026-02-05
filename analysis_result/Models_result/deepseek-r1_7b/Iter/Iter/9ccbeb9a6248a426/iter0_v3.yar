rule EvasionBypass {
    meta:
        description = "Evasion bypass patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? 05 ?? 8B CE E8 74 FA FF FF }
        $pattern1 = { 6A 5B ?? 5A 8B CE E8 25 05 00 00 FF 15 AC B0 41 00 ?? }
        $pattern2 = { E8 C8 FF FF FF ?? FF 15 8C E1 E5 00 ?? }
    condition:
        any of them
}