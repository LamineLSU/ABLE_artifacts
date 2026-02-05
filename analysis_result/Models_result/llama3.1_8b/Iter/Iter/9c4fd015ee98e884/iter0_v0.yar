rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF FF FF 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { FF 15 AC B0 41 ?? 59 FF 75 08 E8 ?? ?? ?? ?? }
        $pattern2 = { 8B FF 55 8B EC FF 75 ?? E8 ?? ?? ?? ?? }

    condition:
        any of them
}