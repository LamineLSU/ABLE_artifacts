rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule targeting specific addresses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 8B 45 ?? } // Example pattern
        $pattern1 = { FF7508 push ebp jmp ??C4 ??. ?? ?? } // Another example pattern
        $pattern2 = { FF7508 ?? ?? ?? ?? push ?? jmp ?? } // Third unique pattern

    condition:
        any of them
}