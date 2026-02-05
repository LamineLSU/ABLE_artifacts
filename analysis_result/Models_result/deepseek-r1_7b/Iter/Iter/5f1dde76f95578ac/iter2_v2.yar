rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass targeting E7C3h"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { FF 75 08 DD EB 08 ?? ?? ?? ?? ?? 45 ?? EA }
        $pattern2 = { 75 0F 8A ?? ?? ?? ?? E8 C8 FF FF FF FF CA DD 00 40 E7 C3 }

    condition:
        any of them
}