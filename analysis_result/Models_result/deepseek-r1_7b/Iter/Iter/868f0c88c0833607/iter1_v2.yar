rule Bypass_Sample_Evolved
{
    meta:
        description = "Bypass check function using known sequences from trace"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5B AD E8 25 05 00 00 }
        $pattern1 = { EC E8 74 FA FF FF }
        $pattern2 = { EA E8 25 05 00 00 }

    condition:
        any of them
}