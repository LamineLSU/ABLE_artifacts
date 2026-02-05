rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection rules"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 FF 5A 4F FE FF 61 73 FF FF ?? ?? ?? ?? FF 8B ED BE EF }
        $pattern1 = { 8C 90 F7 00 02 00 05 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? FF FF FF FF }
        $pattern2 = { 6A 03 FF 8B FC FF FF ?? ?? ?? ?? 45 7E ?? }

    condition:
        any of them
}