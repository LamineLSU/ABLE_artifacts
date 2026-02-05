rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? 8B CE E8 25 05 00 00 E8 CE ?? }     // Example pattern
        $pattern1 = { 6A 5B 5A 8B CE E8 74 FA FF FF 03 C3 ?? 8B 85 F0 FE FF FF E8 4B 17 00 00 }  // Another example pattern
        $pattern2 = { FF 15 2C A1 C7 00 85 C0 0F 84 ?? 8B CE E8 4B 17 00 00 03 C9 E8 57 26 00 00 }   // Third example pattern

    condition:
        any of them
}