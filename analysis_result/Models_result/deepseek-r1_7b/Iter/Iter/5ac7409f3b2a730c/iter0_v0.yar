rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF 84 33 DB 5A 8B CE E8 0C 0F 84 FF FF FF FF FF FF FF FF FF FF }
        $pattern1 = { 6A 5B FF EC 21 05 04 FF 75 08 59 FF 75 08 FF FF FF FF FF FF FF FF FF FF FF FF FF FF }
        $pattern2 = { 03 C3 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF }

    condition:
        any of them
}