rule Bypass_Sample_Evolved {
    meta:
        description = "Evasion bypass rule - checked function return values"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 ?? ?? ?? ?? 8B EC ?? }
        $pattern1 = { E8 C8 ?? ?? ?? ?? ?? ?? ?? ?? }
        $pattern2 = { 6A ?D ?E 45 ?? ?? ?? ?? FC ?? }

    condition:
        any of them
}