rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule targeting specific memory checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE E8 ?? ?? ?? ?? }  # Example pattern around first call
        $pattern1 = { FF75 ???? E8C8 ???? ??? }  # Example pattern around second call in Trace #3
        $pattern2 = { 6A 53 ???? FF15ACB04100h }  # Example pattern around third call

    condition:
        any of them
}