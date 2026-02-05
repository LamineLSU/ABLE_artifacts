rule Bypass_Evasion {
    meta:
        description = "Anti-debugging bypass rules targeting stack manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 56 5A 8B 45 08 56 ?? ?? }
        $pattern1 = { FF D2 5E 5D C3 8B 45 0C ?? ?? }
        $pattern2 = { E8 74 0A 00 56 50 8B EC ?? ?? }

    condition:
        any of them
}