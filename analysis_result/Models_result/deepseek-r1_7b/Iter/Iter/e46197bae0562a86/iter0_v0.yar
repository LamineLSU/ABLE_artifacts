rule Bypass_Evasion_Patterns {
    meta: {
        description: "Evasion bypass patterns targeting speculative execution",
        cape_options: "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
    },
    strings: {
        $pattern0: "{ 85 C0 74 ?? 0F 84 ?? ?? ?? ?? 8B 45 ?? }",
        $pattern1: "{ E8 ?? 74 ?? F0 FC 53 ?? 8B 45 ?? }",
        $pattern2: "{ E8 ?? 0F 84 ?? ?? ?? ?? 8B 45 ?? }"
    }
}