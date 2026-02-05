rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specifically targets program termination trigger sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF ED ED 55 EB 8B EC EB E8 F7 25 00 00 CA }
        $pattern1 = { C1 E8 08 EA 08 A8 01 EA 3C 75 10 00 41 B9 30 }
        $pattern2 = { 8B 45 FC EB 0E 82 FF FD EA 00 00 00 30 }

    condition:
        any of them
}