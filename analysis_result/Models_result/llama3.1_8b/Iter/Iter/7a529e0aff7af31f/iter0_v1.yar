rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? } (11 bytes)
        $pattern2 = { 8B FF 55 8B EC FF 75 08 } (9 bytes)
        $pattern3 = { FF 75 08 FF 15 AC B0 41 00 } (11 bytes)

    condition:
        any of them
}