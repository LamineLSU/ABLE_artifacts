rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 7D 29 E7 3C 4D 1B F2 }  // jnl + out + dec ebp + sbb esi,edx
        $pattern1 = { 83 C4 14 52 52 FF D0 }   // add esp + push edx x2 + call eax
        $pattern2 = { 52 50 E8 ?? ?? ?? ?? } // push edx + push eax + call (offset wildcards)

    condition:
        any of them
}