rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // Skip VM check call in TRACE //1
        $pattern1 = { FF 75 08 FF 15 ?? ?? ?? ?? }  // Skip sandbox check call in TRACE //3
        $pattern2 = { C1 E8 08 A8 01 75 10 }  // Skip debugger check in TRACE //5

    condition:
        any of them
}