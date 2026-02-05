rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeted to specific calls for improved specificity"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 63 5E 49 6F 72 4D } // Example: "Call Eax"
        $pattern1 = { 4B 4F 4C 4F 43 54 } // Another specific instruction sequence
        $pattern2 = { 79 6D 2E 53 77 2A } // Different variation matching the trace

    condition:
        any of them
}