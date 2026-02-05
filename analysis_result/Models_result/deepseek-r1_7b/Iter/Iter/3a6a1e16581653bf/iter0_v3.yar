rule EvasionBypass
{
    meta:
        description = "Evasion bypass patterns targeting attacker's checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? 5A 8B CE E8 25 05 00 00 ?? 74 07 EB ?? }   // Skips conditional test before call
        $pattern1 = { 6A 5B ?? 5A 8B CE E8 25 05 00 00 ?? 74 07 EB ?? }   // Skips stack manipulation check
        $pattern2 = { FF 15 3C E1 C0 00 ?? 8B EC E8 0E 12 00 00 ?? FF 15 AC B0 41 00 }   // Skips function execution
}

    condition:
        any of them
}