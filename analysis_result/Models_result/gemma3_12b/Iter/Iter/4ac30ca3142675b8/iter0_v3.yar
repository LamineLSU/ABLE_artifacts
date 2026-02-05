rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 55 0C 8B 06 83 C4 14 52 8B 16 50 51 FF D2 5E 5D C3 }  // Bypass CALL eax at 0041E24F (15 bytes)
        $pattern1 = { 7B 74 F0 B6 61 57 C0 13 23 C9 83 C2 55 55 8B EC 8B 45 08 8B 48 14 56 56 6A 35 6A 00 }  // Bypass JNP at 0041E1DB (19 bytes)
        $pattern2 = { 56 6A 36 6A 00 51 8D B0 A0 0C 00 00 56 50 E8 74 0A 00 00 }  // Bypass CALL 0041EB47h at 0041E1FE (17 bytes)

    condition:
        any of them
}