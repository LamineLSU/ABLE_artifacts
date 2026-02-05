rule Bypass_Evasion {
    meta:
        description = "Bypass exit process check"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern1 = { 8B EC ?? FF 75 ?? ?? } // Bypasses the call at 0040E7FF
}

    condition:
        any of them
}