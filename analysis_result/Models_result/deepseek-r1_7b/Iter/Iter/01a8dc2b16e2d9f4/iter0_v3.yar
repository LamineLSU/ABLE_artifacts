rule Bypass_Sample {
    meta:
        description = "Evasion bypass for exitProcess"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE 85 C0 FF 84 33 CD 5A 8B EC 8D 43 01 00 } // Skip EAX test and jump
        $pattern1 = { 6A 40 53 8B E5 FF 84 33 CB 5A 8B CE 8D 43 01 00 } // Skip push/pop EBP setup
        $pattern2 = { EB 74 17 00 8B E5 FF 84 33 C9 5A 8B EC 8D 43 01 00 } // Modify final jump destination

    condition:
        any of them
}