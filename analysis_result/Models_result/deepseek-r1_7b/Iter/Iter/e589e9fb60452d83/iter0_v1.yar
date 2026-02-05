rule Bypass_Evasion {
    meta:
        description = "Evasion bypass patterns identified from trace analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 64 A1 30 00 00 00 ?? ?? ?? ?? ?? 40 5E 7C 00 }  // Example pattern from exitProcess in TRACE //1
        $pattern1 = { 8B EC 55 8B 40 68 E8 36 34 01 00 59 74 20 5A 75 10 }  // Example pattern from exitProcess in TRACE //2
        $pattern2 = { 8D 45 A8 5E 33 DB 8B EC 5F 6A 40 57 8D 4D FC }  // Example pattern from exitProcess in TRACE //3

    condition:
        any of them
}