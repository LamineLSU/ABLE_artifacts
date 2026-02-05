rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific exit calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 40 00 00 00 40 } // Target a specific register push
        $pattern1 = { FF 15 08 50 44 00 CA DD 00 44 50 85 } // Directly target an exit process call
        $pattern2 = { 6A 00 00 00 00 00 } // Another specific register push

    condition:
        (any of the patterns match)
}