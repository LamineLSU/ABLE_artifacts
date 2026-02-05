rule Bypass_Sample {
    meta: {
        description = "Evasion bypass patterns targeting fixed address checks",
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
    },
    
    strings: {
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }, // Bypass first check by skipping EAX call and mov
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }, // Bypass second check by skipping E8C8 check and jmp near
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } // Bypass third check by skipping push ebp and call
    }
}