rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 0E }  // Skip EAX test
        $pattern1 = { 6A 00 8B 45 }   // Skip push instruction before EAX test
        $pattern2 = { FF 15 14 28 43 00 }  // Skip jump after EAX test

    condition:
        any of them
}