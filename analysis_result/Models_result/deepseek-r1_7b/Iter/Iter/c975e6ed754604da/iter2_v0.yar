rule Bypass_Sample {
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 E8C8FFFFF FF7508 59 8BCE ?? ??? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ???? ??? }
        $pattern2 = { FF7508 59 8BCE FF15ACB04100 85 C0 }
}

# Patterns are designed to be specific enough to match only the target locations while being general enough to capture common bypass attempts.