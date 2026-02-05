rule Bypass_Sample {
    meta:
        description = "Evasion bypass detection based on trace analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 0040E7F0:55, 0040E7F1:??, 0040E7F3:FF7508 }
        $pattern1 = { ??, 0040E7F0:55, 0040E7F1:8BEC, 0040E7F3:FF7508 }
        $pattern2 = { 0040E7F0:??, 0040E7F1:8BEC, 0040E7F3:FF7508 }
}