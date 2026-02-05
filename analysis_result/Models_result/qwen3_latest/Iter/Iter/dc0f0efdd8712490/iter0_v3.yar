rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? 33 FF } // TRACE //1: Call to evasion check
        $pattern1 = { FF 75 08 E8 ?? ?? ?? ?? }     // TRACE //3: Call to evasion check
        $pattern2 = { FF 75 08 E8 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? } // TRACE //5: Call to evasion check

    condition:
        any of them
}