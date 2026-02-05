rule EvasionBypass {
    meta:
        description = "Evasion bypass patterns targeting different code paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? 85 C0 } // Pattern matching a bypass in one exit path
        $pattern1 = { 6A ?? 5A 8B EC E9 ?? ?? ?? FF 75 ?? } // Another bypass pattern for a different exit
        $pattern2 = { 4F ?? C0 ?? ?? ?? ?? ?? ?? ?? } // Third unique bypass path

    condition:
        any of them
}