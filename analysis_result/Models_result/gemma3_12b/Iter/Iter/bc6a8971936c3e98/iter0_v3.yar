rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3A FF 15 BC 36 61 00 } // Trace //1, Call to [006136BCh]
        $pattern1 = { 14 FF 15 BC 36 61 00 } // Trace //2, Call to [006136BCh]
        $pattern2 = { 4D FF 15 BC 36 61 00 } // Trace //5, Call to [006136BCh]

    condition:
        any of them
}