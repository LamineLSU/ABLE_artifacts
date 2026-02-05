rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Call 004010F0h"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern2 = { E8 72 DC FF FF 83 06 8B 45 0C 8B 42 10 3B 42 04 }
    
    condition:
        any of them
}