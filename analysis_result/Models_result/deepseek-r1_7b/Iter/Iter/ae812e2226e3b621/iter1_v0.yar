rule Bypass_Sample_Evolved {
    meta:
        description = "Evasion bypass using TEST EAX and JE, plus push followed by ExitProcess call"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip"
        confidence: 65
        reasoning: "These patterns target known sequences leading to exit calls in the sample code."
    
    strings:
        $pattern0 = { 85 C0 74 25 EA 74 12 ?? }
        $pattern1 = { 6A 5B FF E1 5C EC 7F 24 }\n        $pattern2 = { 00 94 61 8A 5B 5C EC 7F 24 }
    
    condition:
        any of ($pattern0 | $pattern1 | $pattern2)
}