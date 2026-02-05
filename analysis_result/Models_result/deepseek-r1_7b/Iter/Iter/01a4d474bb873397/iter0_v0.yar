rule EvasionBypass_001 {
    meta:
        description = "Evasion bypass patterns targeting specific points in the code"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 25 05 00 00 5A 8B CE }  # 8 bytes
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }  # 12 bytes
        $pattern2 = { E9 B5 FC FF FF 50 8D 53 53 68 40 53 53 D9 11 00 C3 }  # 15 bytes

    condition:
        any of them
}