rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass patterns targeting call and conditional jump sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 55 14 EC DD EB 14 56 6A 35 00 00 00 35 8B 45 10 EA DD EB 10 5E 5D EB } // 12 bytes

        $pattern1 = { 8B 55 0C ED DD EB 0C FF D0 CA ED 6A 36 00 00 00 36 5E 5D EB } // 12 bytes

        $pattern2 = { 8B 45 10 EC DD EB 10 E8 04 CA 00 41 F1 43 6A 37 00 00 00 37 5E 5D EB } // 12 bytes

    condition:
        any of them
}