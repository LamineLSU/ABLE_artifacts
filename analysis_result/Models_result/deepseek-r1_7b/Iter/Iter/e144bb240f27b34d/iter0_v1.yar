rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns targeting call instructions"
        cape_options = "bp0=0040E7EE,action0=skip;bp1=0040E7F3,action1=skip;bp2=0040E7F6,action2=skip"
    strings:
        $pattern0 = { 8B FF 55 8B EC 8C 8F F7 50 10 }
        $pattern1 = { 8B FF 55 8B EC 8C 8F F7 50 10 00 }
        $pattern2 = { 8B FF 55 8B EC 8C 8F F7 50 10 01 }
    condition:
        any of them
}