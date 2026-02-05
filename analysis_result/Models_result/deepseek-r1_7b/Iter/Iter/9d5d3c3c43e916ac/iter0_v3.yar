rule EvasionBypass {
    meta:
        description = "Bot detecting bypassed instructions to avoid execution analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 FF 75 08 FF 75 08 8B EC E8 ?? }
        $pattern1 = { 6A 5A 8B CE E8 ?? ?? ?? ?? 85 C0 0F 84 }
        $pattern2 = { FF 75 08 FF 75 08 8B EC E8 CF DD 9C 8E }

    condition:
        any of them
}