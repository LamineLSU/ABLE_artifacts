rule Bypass_Sample {
    meta:
        description = "Evasion bypass detection based on trace analysis"
        cape_options = "$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { FF C0 8B 45 ?? ?? ?? ?? FF } // Adjusted based on context
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}