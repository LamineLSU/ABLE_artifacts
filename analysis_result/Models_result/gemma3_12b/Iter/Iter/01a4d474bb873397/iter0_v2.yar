rule Bypass_ExitCall
{
    meta:
        description = "Evasion bypass rule - Prevent Exit Call"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 33 DB BA 21 05 00 00 53 6A 40 53 68 40 11 E8 00 FF 15 2C A1 E8 00 }
        $pattern1 = { 53 6A 40 53 68 40 11 E8 00 FF 15 2C A1 E8 00 }
        $pattern2 = { 6A 40 53 68 40 11 E8 00 FF 15 2C A1 E8 00 }

    condition:
        any of them
}