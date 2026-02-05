rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 77 ?? 01 ?? E9 ?? FF FF FF 5E 89 F7 B9 00 0C 00 00 }
        $pattern1 = { 24 0F C1 E0 10 66 8B 07 83 C7 02 EB E2 48 BA EE 34 E0 }
        $pattern2 = { 47 8A 07 08 C0 74 DC 89 F9 57 48 F2 AE 55 FF 96 30 E0 }

    condition:
        any of them
}