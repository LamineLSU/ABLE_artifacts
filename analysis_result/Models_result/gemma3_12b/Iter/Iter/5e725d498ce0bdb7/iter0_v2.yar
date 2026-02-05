rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 52 5E 5D C3 }  // Skipping the final call eax
        $pattern1 = { 56 6A 35 6A 00 51 8D B0 98 0C 00 00 56 50 E8 74 0A 00 00 } // Skipping call to 0041EC07h
        $pattern2 = { 41 E2 A3 A9 C5 1E B6 55 8B EC 8B 45 08 8B 48 14 56 6A 35 6A 00 51 8D B0 A0 0C 00 00 } // Skipping test eax, 55B61EC5h

    condition:
        any of them
}