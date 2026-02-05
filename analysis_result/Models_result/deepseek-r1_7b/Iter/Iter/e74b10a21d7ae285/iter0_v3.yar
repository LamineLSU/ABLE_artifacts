rule Bypass_Sample {
    meta:
        description = "Evasion bypass pattern"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 5A 4F 3F 09 00 B6 00 00 01 17 8D 43 01 FE FF FF FF 84 85 0F EF FF }
        $pattern1 = { 8B EC F8 C7 81 BE 00 00 5A 8B CE 3C 50 00 00 01 04 53 8D 43 01 E5 00 00 01 07 }
        $pattern2 = { FF 15 88 A0 B9 0F 0C 42 8B E5 5D FF 15 88 A0 B9 0F 0C 42 8B E5 }

    condition:
        any of them
}