rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting 74DF4100h"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 06 74 ?? } // TEST followed by JZ with unknown offset
        $pattern1 = { 6A ?? 8B CE E8 ?? } // PUSH, POP, and call with address displacement
        $pattern2 = { 79 FF 5A 8B CE E8 ?? } // ARITHMETIC operation leading to call

    condition:
        any of them
}