rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // Push ebx + call [addr] (TRACE //1)
        $pattern1 = { FF 75 08 E8 ?? ?? ?? ?? }  // Push ebp+08 + call [addr] (TRACE //3)
        $pattern2 = { E8 0B 00 00 00 FF 15 ?? ?? ?? ?? }  // Call [addr] + next call [addr] (TRACE //5)

    condition:
        any of them
}