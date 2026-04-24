rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 FF 7F 26 00 00 FF C2 }  // After call and jump
        $pattern1 = { 6A 5A 8B CE 00 D3 FF 04 10 0D 84 10 20 10 00 00 06 84 01 1D 70 00 00 00 10 40 10 0C 04 10 }  // After call and jump with offset
        $pattern2 = { 50 E0 8B CE 00 D3 FF 04 10 0D 84 10 20 10 00 00 06 84 01 1D 70 00 00 00 10 40 10 0C 04 10 }  // After call and jump with offset
    condition:
        any of them
}