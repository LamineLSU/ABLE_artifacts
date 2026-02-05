rule Bypass_Evasion_Patterns {
    meta:
        description = "Evasion bypass patterns targeting specific execution points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF FF FF FF FF FF FF FF FF 74 16 74 08 B3 5A F1 47 00 }
        $pattern1 = { 6A ?? 5A 8B CE E8 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 29 ?? 3E FF D6 3E }
        $pattern2 = { FF D6 3E 5A 8B CE E8 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 29 ?? 3E FF D6 3E }
    condition:
        any_of($pattern0, $pattern1, $pattern2)
}