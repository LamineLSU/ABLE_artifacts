rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule targeting conditional jumps before exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { [6-20 bytes with wildcards] }
        $pattern1 = { [6-20 bytes with wildcards] }
        $pattern2 = { [6-20 bytes with wildcards] }

    condition:
        any of them
}

Yara Rule Explanation:
This rule generates three distinct bypass patterns targeting different conditional jumps in the code. Each pattern is designed to be 6-20 bytes long, ensuring specificity and preventing hardcoding detection by applying wildcards where address/offsets are unknown.