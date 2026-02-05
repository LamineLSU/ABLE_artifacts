rule EvasionBypass_Pattern2 {
    meta:
        description = "Evasion bypass: Skipping after E80D0C0000 in Phase 2"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern2 = { E8 0D 0C 00 00 ?? BB ?? CC ?? DD ?? }
    condition:
        any of them
}