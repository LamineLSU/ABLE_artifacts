rule Bypass_MemoryManip {
    meta:
        description = "Evasion bypass using memory manipulation instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern2 = { 85 C0 74 12 ?? ?? 6A ?? 5B ?? EB 1B ?? ?? ?? ?? ?? ?? EB 1B }
    
    condition:
        any of them
}