rule Bypass_Sample {
    meta: description = "Evasion bypass rule targeting specific instructions to bypass detection"
    cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings: {
        $pattern0 = "{8B55?? ?? FF7508}"  # Bypasses a check around the first call instruction
        $pattern1 = "{6A??5A8BCEE8??"}   # Modifies context to bypass an offset check after pop ecx
        $pattern2 = "{85C06A55??45C0??"}  # Skips a test before the final call, allowing execution"
    }
}