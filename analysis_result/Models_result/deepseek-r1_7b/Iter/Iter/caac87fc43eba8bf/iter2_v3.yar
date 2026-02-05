rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule targeting three specific code paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 7F C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }
        $pattern2 = { 6E ?? 9C FF 8B CB ?? }

    condition:
        any of them
}