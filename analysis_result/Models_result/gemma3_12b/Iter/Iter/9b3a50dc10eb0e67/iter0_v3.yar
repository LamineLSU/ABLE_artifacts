rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 D1 FF FF FF 59 FF 74 24 04 } // Bypass call 00403B85h (Trace 1/2)
        $pattern1 = { 8B FF 55 8B EC FF 15 A8 01 B8 00 50 FF 15 5C 01 B8 00 } // Bypass call [00B801A8h] (Trace 3)
        $pattern2 = { 8B FF 55 8B EC 83 F8 01 74 20 6A ?? 5A } // Bypass cmp eax, 01h and je 00B6C2F0h (Trace 3)

    condition:
        any of them
}