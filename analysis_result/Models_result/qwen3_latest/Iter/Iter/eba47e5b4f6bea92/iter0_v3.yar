rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // Call to sandbox check (TRACE //1)
        $pattern1 = { FF 75 08 E8 ?? ?? ?? ?? }  // Call to sandbox check (TRACE //3)
        $pattern2 = { E8 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }  // Call to sandbox check (TRACE //5)

    condition:
        any of them
}