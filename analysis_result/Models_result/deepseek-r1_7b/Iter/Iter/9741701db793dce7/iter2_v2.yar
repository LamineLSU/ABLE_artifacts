rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting initial calls"
        cape_options = "bp0=$pattern0+0,action0=skip;bp1=$pattern1+0,action1=skip;bp2=$pattern2+0,action2=skip;count=0"

    strings:
        $pattern0 = { E8 43 1C 00 03 EC ?? }
        $pattern1 = { E8 EE 82 FF FF 00 05 ?? }
        $pattern2 = { E8 89 E0 FF FF 00 07 ?? }

    condition:
        (any of them)
}