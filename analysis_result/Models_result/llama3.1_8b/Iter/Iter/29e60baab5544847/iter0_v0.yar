rule Bypass_Trace_5
{
    meta:
        description = "Evasion bypass rule for TRACE #5"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8BFF 55 8BEC E807260000 }
        $pattern1 = { 64A130000000 8B4068 C1E808 A801 }
        $pattern2 = { FF7508 FF153CE12A00 FF1540E12A00 }

    condition:
        any of them
}