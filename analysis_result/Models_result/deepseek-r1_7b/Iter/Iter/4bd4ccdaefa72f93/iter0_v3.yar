rule Bypass_Evasion {
    meta:
        description = "Evasion bypass patterns for sandbox exit detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 48 8D 54 24 40 48 8B CF FF 15 CB 0E 00 00 ?? ?? ?? ?? }
        $pattern1 = { 4C 8D 8D 90 01 00 00 00 48 8B CE 74 4E ?? ?? ?? ?? ?? ?? }
        $pattern2 = { ?? ?? ?? ?? 85 C0 0F 84 FF 15 AA 0E 00 00 }
    condition:
        any_of(these)
}