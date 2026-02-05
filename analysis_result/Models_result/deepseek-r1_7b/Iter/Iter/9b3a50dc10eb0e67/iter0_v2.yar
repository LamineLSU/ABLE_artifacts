rule Bypass_Sample {
    meta:
        description = "Evasion bypass around call and conditional jump instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 20 FF 74 24 04 E8 D1 FF FF 59 }
        $pattern1 = { 20 FF 74 24 04 59 FF 74 24 04 E8 D1 FF FF }
        $pattern2 = { 20 FF 74 24 04 59 FF 74 24 04 E8 D1 FF FF FF 74 24 04 59 }

    condition:
        any of the patterns match the trace data exactly
}