rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 40 68 8B 45 FC C1 E8 08 A8 01 75 10 }  // FS Register Check
        $pattern1 = { 55 8B EC 53 55 8B 6C 24 08 FF 15 5C 00 6E 00 }  // Indirect Call
        $pattern2 = { 8B FF 55 8B EC 51 51 A1 D8 EB 78 00 33 C5 } //Register comparison

    condition:
        any of them
}