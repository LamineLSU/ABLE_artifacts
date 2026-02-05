rule Bypass_Evasion

{
    meta:
        description = "Evasion bypass rule targeting E7C3h"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 ?? ... }
        $pattern1 = { E8 ???? 83 C4 ?? ??? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? }

    condition:
        any of them
}