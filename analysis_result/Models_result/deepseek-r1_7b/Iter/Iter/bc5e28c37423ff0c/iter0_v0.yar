rule Bypass_Sample {
    meta:
        description = "Evasion bypass using stack manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC 56 56 ?? 5E 5D C3 } // Push ebp, push eax, then call
        $pattern1 = { 8B 4F 55 55 5A CA 8B 45 ?? FE } // Push values and OR operation
        $pattern2 = { 8B 06 8B 55 0C 5E 5D C3 } // Move value from register, sub esp

    condition:
        any_of($pattern0, $pattern1, $pattern2)
}