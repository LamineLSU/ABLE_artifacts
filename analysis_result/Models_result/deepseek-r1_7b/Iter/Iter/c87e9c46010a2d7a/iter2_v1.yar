rule Bypass_Sample_Evaded {
    meta:
        description = "Bypass detected using known test and jump sequences from sample analysis"
        cape_options = "bp0=Pattern1+0,action0=skip,bp1=Pattern2+0,action1=skip,bp2=Pattern3+0,action2=skip"
        confidence = 60
        reasoning = "Using specific test and jump patterns identified in the sample's execution trace to avoid false positives."
    strings:
        $pattern0 = { 85 C0 74 12 ?? ?? ?? ?? }
        $pattern1 = { 8A ?? ?? ?? 9B ?? ?? ?? }
        $pattern2 = { 3D 00 00 00 6A 00 00 00 }
    condition:
        any of the patterns match"
}